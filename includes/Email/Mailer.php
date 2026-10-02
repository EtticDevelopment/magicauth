<?php
/**
 * Mailer: render and send the magic-link/code email.
 *
 * Multipart via phpmailer_init AltBody (not a Content-Type header). Plaintext
 * always renders from its own template — never strip_tags($html).
 *
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Email;

defined( 'ABSPATH' ) || exit;

use MagicAuth\Auth\Crockford;
use MagicAuth\Passkeys\Aaguids;
use MagicAuth\Passkeys\Clock;
use MagicAuth\Passkeys\CredentialStore;
use MagicAuth\Passkeys\Module;
use WP_User;

final class Mailer {

	/** Send the magic-link email. */
	public static function send_magic_link( int $user_id, string $link_url, string $code, string $expires_at ): bool {
		$user = get_userdata( $user_id );
		if ( ! $user instanceof WP_User || empty( $user->user_email ) ) {
			return false;
		}

		$locale = function_exists( 'get_user_locale' ) ? get_user_locale( $user_id ) : '';
		$switched = false;

		if ( $locale && function_exists( 'switch_to_locale' ) ) {
			$switched = switch_to_locale( $locale );
		}

		try {
			return self::dispatch( $user, $link_url, $code, $expires_at, false );
		} finally {
			if ( $switched && function_exists( 'restore_previous_locale' ) ) {
				restore_previous_locale();
			}
		}
	}

	/**
	 * One-shot "your account is restricted" notice. Throttle gate is the
	 * caller's responsibility — this method always renders + sends.
	 */
	public static function send_disabled_notice( int $user_id ): bool {
		$user = get_userdata( $user_id );
		if ( ! $user instanceof WP_User || empty( $user->user_email ) ) {
			return false;
		}

		$locale = function_exists( 'get_user_locale' ) ? get_user_locale( $user_id ) : '';
		$switched = false;
		if ( $locale && function_exists( 'switch_to_locale' ) ) {
			$switched = switch_to_locale( $locale );
		}

		try {
			return self::dispatch_disabled_notice( $user );
		} finally {
			if ( $switched && function_exists( 'restore_previous_locale' ) ) {
				restore_previous_locale();
			}
		}
	}

	/** Settings → "Send test email" diagnostic. Forces a fixed brand color and placeholder selector/code. */
	public static function send_test( int $user_id ): bool {
		$user = get_userdata( $user_id );
		if ( ! $user instanceof WP_User || empty( $user->user_email ) ) {
			return false;
		}

		$test_link = home_url( '/?magicauth=verify&s=' . str_repeat( '0', 16 ) . '&v=' . str_repeat( '0', 64 ) );
		$test_code = 'TEST00';
		$expires   = gmdate( 'Y-m-d H:i:s', time() + ( 10 * MINUTE_IN_SECONDS ) );

		return self::dispatch( $user, $test_link, $test_code, $expires, true );
	}

	/**
	 * "A passkey was added" security notice (SPEC 10.2), after every
	 * successful registration. Carries the server-derived label, never the
	 * passkey name or any other user-supplied text, and no link.
	 *
	 * @param int $user_id           Owner.
	 * @param int $credential_row_id Row id of the new credential.
	 */
	public static function send_passkey_added( int $user_id, int $credential_row_id ): bool {
		$user = get_userdata( $user_id );
		if ( ! $user instanceof WP_User || empty( $user->user_email ) ) {
			return false;
		}

		$switched = self::switch_locale( $user_id );
		try {
			$row = self::visible_row( $user, $credential_row_id );
			if ( null === $row ) {
				magicauth_debug_log( 'passkey-added: credential not found (user_id=' . $user_id . ')' );
				return false;
			}

			$args = self::build_passkey_added_args( $user, $row );
			return self::dispatch_security_email(
				'magicauth_passkey_added',
				'passkey_added',
				$user,
				$args,
				'email-passkey-added.php',
				'email-passkey-added-plain.php',
				sprintf(
					/* translators: %s: company name */
					__( 'A passkey was added to your %s account', 'magicauth' ),
					$args['company_name']
				)
			);
		} finally {
			self::restore_locale( $switched );
		}
	}

	/**
	 * Step-up confirmation code (SPEC 10.3), sent only from
	 * magicauth_passkey_reauth_email for the signed-in user. Not a login
	 * email: the code only refreshes an existing session. No link, and the
	 * code is not in the subject.
	 *
	 * @param int    $user_id Signed-in user.
	 * @param string $code    6-character Crockford code.
	 */
	public static function send_confirm_code( int $user_id, string $code ): bool {
		$user = get_userdata( $user_id );
		if ( ! $user instanceof WP_User || empty( $user->user_email ) ) {
			return false;
		}

		$switched = self::switch_locale( $user_id );
		try {
			$args                   = self::build_security_args( $user );
			$args['code_display']   = Crockford::format_for_display( $code );
			$args['expiry_minutes'] = 10;

			return self::dispatch_security_email(
				'magicauth_confirm_code',
				'confirm_code',
				$user,
				$args,
				'email-confirm-code.php',
				'email-confirm-code-plain.php',
				sprintf(
					/* translators: %s: company name */
					__( 'Your confirmation code for %s', 'magicauth' ),
					$args['company_name']
				)
			);
		} finally {
			self::restore_locale( $switched );
		}
	}

	/**
	 * "Passkeys removed" security notice (SPEC 10.4): after a user's delete
	 * from a session that is not fresh, every admin delete and revoke-all, and
	 * an email-change revocation (to the old and the new address, one mail
	 * each so neither address sees the other). No name, no link.
	 *
	 * @param int               $user_id Owner.
	 * @param int               $count   Passkeys removed (> 0).
	 * @param string            $actor   self | admin | system.
	 * @param string            $reason  removed | email_changed.
	 * @param array<int,string> $to      Recipients; the account's address when empty.
	 */
	public static function send_passkeys_removed( int $user_id, int $count, string $actor, string $reason, array $to ): bool {
		$user = get_userdata( $user_id );
		if ( ! $user instanceof WP_User || $count < 1 ) {
			return false;
		}
		$recipients = self::recipients( [] !== $to ? $to : [ (string) $user->user_email ] );
		if ( [] === $recipients ) {
			return false;
		}

		$switched = self::switch_locale( $user_id );
		try {
			$args = self::build_security_args( $user ) + [
				'count'            => $count,
				'actor'            => in_array( $actor, [ 'self', 'admin', 'system' ], true ) ? $actor : 'system',
				'reason'           => 'email_changed' === $reason ? 'email_changed' : 'removed',
				'removed_at_local' => self::local_time( Clock::now() ),
				'timezone_label'   => wp_timezone_string(),
				'manage_location'  => Module::manage_location( $user ),
			];
			$subject = sprintf(
				/* translators: 1: number of passkeys, 2: company name */
				_n( '%1$d passkey was removed from your %2$s account', '%1$d passkeys were removed from your %2$s account', $count, 'magicauth' ),
				$count,
				$args['company_name']
			);

			$sent = true;
			foreach ( $recipients as $address ) {
				$sent = self::dispatch_security_email( 'magicauth_passkeys_removed', 'passkeys_removed', $user, $args, 'email-passkeys-removed.php', 'email-passkeys-removed-plain.php', $subject, $address ) && $sent;
			}
			return $sent;
		} finally {
			self::restore_locale( $switched );
		}
	}

	/**
	 * "Passkey blocked" security notice (SPEC 10.5): sent once, by the request
	 * whose UPDATE set counter_anomaly_at (7.6). Label from the stored row only.
	 *
	 * @param int $user_id           Owner.
	 * @param int $credential_row_id Row id of the blocked credential.
	 */
	public static function send_passkey_blocked( int $user_id, int $credential_row_id ): bool {
		$user = get_userdata( $user_id );
		if ( ! $user instanceof WP_User || empty( $user->user_email ) ) {
			return false;
		}

		$switched = self::switch_locale( $user_id );
		try {
			$row = self::visible_row( $user, $credential_row_id );
			if ( null === $row ) {
				magicauth_debug_log( 'passkey-blocked: credential not found (user_id=' . $user_id . ')' );
				return false;
			}
			$suffix  = strtoupper( substr( (string) ( $row->credential_hash ?? '' ), -4 ) );
			$blocked = strtotime( (string) ( $row->counter_anomaly_at ?? '' ) . ' UTC' );
			$args    = self::build_security_args( $user ) + [
				/* translators: %s: last 4 characters of the passkey's identifier, for example 9F3A. */
				'passkey_label'    => sprintf( __( 'Passkey ending in %s', 'magicauth' ), $suffix ),
				'passkey_suffix'   => $suffix,
				'blocked_at_local' => self::local_time( false !== $blocked ? $blocked : Clock::now() ),
				'timezone_label'   => wp_timezone_string(),
				'manage_location'  => Module::manage_location( $user ),
			];

			return self::dispatch_security_email(
				'magicauth_passkey_blocked',
				'passkey_blocked',
				$user,
				$args,
				'email-passkey-blocked.php',
				'email-passkey-blocked-plain.php',
				sprintf(
					/* translators: %s: company name */
					__( 'A passkey on your %s account was blocked', 'magicauth' ),
					$args['company_name']
				)
			);
		} finally {
			self::restore_locale( $switched );
		}
	}

	private static function dispatch( WP_User $user, string $link, string $code, string $expires, bool $is_test ): bool {
		$args = self::build_args( $user, $link, $code, $expires, $is_test );

		/** @var array<string,mixed> $args */
		$args = apply_filters( 'magicauth_email_template_args', $args, $user );

		$html = self::render( 'email-magic-link.php', $args );
		$html = (string) apply_filters( 'magicauth_email_html', $html, $args );

		$plaintext = self::render( 'email-magic-link-plain.php', $args );
		$plaintext = (string) apply_filters( 'magicauth_email_plaintext', $plaintext, $args );

		$subject = (string) apply_filters(
			'magicauth_email_subject',
			sprintf(
				/* translators: 1: formatted sign-in code (XXX-XXX), 2: company name */
				__( '%1$s is your %2$s-code', 'magicauth' ),
				$args['code_display'],
				$args['company_name']
			),
			$user,
			$args
		);

		$from = (array) apply_filters(
			'magicauth_email_from',
			[ magicauth_get_company_name(), magicauth_get_from_email() ],
			$user
		);

		$headers = (array) apply_filters(
			'magicauth_email_headers',
			[
				'Content-Type: text/html; charset=UTF-8',
				sprintf( 'From: %s <%s>', self::header_safe( (string) ( $from[0] ?? '' ) ), self::header_safe( (string) ( $from[1] ?? '' ) ) ),
			],
			$user
		);

		$short_circuit = apply_filters( 'magicauth_email_send', null, $user, $args );
		if ( null !== $short_circuit ) {
			return (bool) $short_circuit;
		}

		// AltBody injection. Removed after this send so we don't pollute other plugins' mail.
		$alt_body_handler = static function ( $phpmailer ) use ( &$plaintext ) {
			if ( is_object( $phpmailer ) && property_exists( $phpmailer, 'AltBody' ) ) {
				$phpmailer->AltBody = $plaintext;
			}
		};
		add_action( 'phpmailer_init', $alt_body_handler );

		$sent = wp_mail( $user->user_email, $subject, $html, $headers );

		if ( function_exists( 'remove_action' ) ) {
			remove_action( 'phpmailer_init', $alt_body_handler );
		}

		if ( ! $sent ) {
			magicauth_debug_log( 'wp_mail returned false (user_id=' . (int) $user->ID . ')' );
		}

		return (bool) $sent;
	}

	/** Mirrors dispatch() but uses disabled-notice templates. NO sign-in URL, NO code, NO action button. */
	private static function dispatch_disabled_notice( WP_User $user ): bool {
		$args = self::build_disabled_notice_args( $user );

		/** @var array<string,mixed> $args */
		$args = apply_filters( 'magicauth_disabled_notice_template_args', $args, $user );

		$html = self::render( 'email-disabled-notice.php', $args );
		$html = (string) apply_filters( 'magicauth_disabled_notice_html', $html, $args );

		$plaintext = self::render( 'email-disabled-notice-plain.php', $args );
		$plaintext = (string) apply_filters( 'magicauth_disabled_notice_plaintext', $plaintext, $args );

		$subject = (string) apply_filters(
			'magicauth_disabled_notice_subject',
			sprintf(
				/* translators: %s: company name */
				__( 'About your sign-in request for %s', 'magicauth' ),
				$args['company_name']
			),
			$user,
			$args
		);

		$from = (array) apply_filters(
			'magicauth_email_from',
			[ magicauth_get_company_name(), magicauth_get_from_email() ],
			$user
		);

		$headers = (array) apply_filters(
			'magicauth_email_headers',
			[
				'Content-Type: text/html; charset=UTF-8',
				sprintf( 'From: %s <%s>', self::header_safe( (string) ( $from[0] ?? '' ) ), self::header_safe( (string) ( $from[1] ?? '' ) ) ),
			],
			$user
		);

		$short_circuit = apply_filters( 'magicauth_disabled_notice_send', null, $user, $args );
		if ( null !== $short_circuit ) {
			return (bool) $short_circuit;
		}

		$alt_body_handler = static function ( $phpmailer ) use ( &$plaintext ) {
			if ( is_object( $phpmailer ) && property_exists( $phpmailer, 'AltBody' ) ) {
				$phpmailer->AltBody = $plaintext;
			}
		};
		add_action( 'phpmailer_init', $alt_body_handler );

		$sent = wp_mail( $user->user_email, $subject, $html, $headers );

		if ( function_exists( 'remove_action' ) ) {
			remove_action( 'phpmailer_init', $alt_body_handler );
		}

		if ( ! $sent ) {
			magicauth_debug_log( 'wp_mail returned false (disabled-notice; user_id=' . (int) $user->ID . ')' );
		}

		return (bool) $sent;
	}

	/**
	 * Args for disabled-notice templates. Exposes allow_password_login so the
	 * body can include the optional "you may still be able to sign in with your password" line.
	 *
	 * @return array<string,mixed>
	 */
	private static function build_disabled_notice_args( WP_User $user ): array {
		$brand     = (string) magicauth_get_setting( 'brand_color', '#2271b1' );
		$site_name = function_exists( 'get_bloginfo' ) ? (string) get_bloginfo( 'name' ) : '';
		$company   = magicauth_get_company_name();

		return [
			'user'                 => $user,
			'brand_color'          => $brand,
			'brand_text'           => magicauth_yiq_text_color( $brand ),
			'company_name'         => '' !== $company ? $company : $site_name,
			'site_name'            => $site_name,
			'allow_password_login' => (bool) magicauth_get_setting( 'allow_password_login', true ),
		];
	}

	/** @return array<string,mixed> */
	private static function build_args( WP_User $user, string $link, string $code, string $expires, bool $is_test ): array {
		$brand = $is_test ? '#2271b1' : (string) magicauth_get_setting( 'brand_color', '#2271b1' );

		$ttl_minutes = max( 1, min( 30, (int) magicauth_get_setting( 'ttl_minutes', 10 ) ) );

		$site_name = function_exists( 'get_bloginfo' ) ? (string) get_bloginfo( 'name' ) : '';
		$company   = magicauth_get_company_name();

		return [
			'user'           => $user,
			'link'           => $link,
			'code'           => $code,
			'code_display'   => Crockford::format_for_display( $code ),
			'expires_at'     => $expires,
			'expiry_minutes' => $ttl_minutes,
			'brand_color'    => $brand,
			'brand_text'     => magicauth_yiq_text_color( $brand ),
			'company_name'   => '' !== $company ? $company : $site_name,
			'site_name'      => $site_name,
			'is_test'        => $is_test,
		];
	}

	/** Theme override → parent theme → plugin. */
	public static function locate_template( string $filename ): string {
		$relative = trim( (string) apply_filters( 'magicauth_template_path', 'magicauth/' ), '/' );

		$candidates = [];
		if ( function_exists( 'get_stylesheet_directory' ) ) {
			$candidates[] = get_stylesheet_directory() . '/' . $relative . '/' . $filename;
		}
		if ( function_exists( 'get_template_directory' ) ) {
			$candidates[] = get_template_directory() . '/' . $relative . '/' . $filename;
		}
		$candidates[] = MAGICAUTH_DIR . 'templates/' . $filename;

		$resolved = '';
		foreach ( $candidates as $path ) {
			if ( is_readable( $path ) ) {
				$resolved = $path;
				break;
			}
		}

		return (string) apply_filters( 'magicauth_locate_template', $resolved, $filename, $candidates );
	}

	/**
	 * Render a template into a string.
	 *
	 * @param array<string,mixed> $args Extracted as locals.
	 */
	public static function render( string $filename, array $args ): string {
		$template = self::locate_template( $filename );
		if ( '' === $template ) {
			return '';
		}

		ob_start();
		( static function ( string $magicauth_template, array $magicauth_args ): void {
			extract( $magicauth_args, EXTR_SKIP ); // phpcs:ignore WordPress.PHP.DontExtract.extract_extract
			include $magicauth_template;
		} )( $template, $args );

		return (string) ob_get_clean();
	}

	/**
	 * Shared send path of the passkey emails (10.1): filters {prefix}_html,
	 * _plaintext, _subject, _send and _template_args; the shared from and
	 * headers filters get $type as a trailing argument. Same AltBody pattern
	 * as dispatch().
	 *
	 * @param string              $prefix         Filter prefix, e.g. magicauth_passkey_added.
	 * @param string              $type           Email type for the shared filters.
	 * @param WP_User             $user           Recipient.
	 * @param array<string,mixed> $args           Template args.
	 * @param string              $html_template  HTML template file name.
	 * @param string              $plain_template Plaintext template file name.
	 * @param string              $subject        Translated subject.
	 * @param string              $to             Recipient; the account's address when ''.
	 */
	private static function dispatch_security_email( string $prefix, string $type, WP_User $user, array $args, string $html_template, string $plain_template, string $subject, string $to = '' ): bool {
		/** @var array<string,mixed> $args */
		$args = apply_filters( $prefix . '_template_args', $args, $user );

		$html      = (string) apply_filters( $prefix . '_html', self::render( $html_template, $args ), $args );
		$plaintext = (string) apply_filters( $prefix . '_plaintext', self::render( $plain_template, $args ), $args );
		$subject   = (string) apply_filters( $prefix . '_subject', $subject, $user, $args );

		$from = (array) apply_filters(
			'magicauth_email_from',
			[ magicauth_get_company_name(), magicauth_get_from_email() ],
			$user,
			$type
		);

		$headers = (array) apply_filters(
			'magicauth_email_headers',
			[
				'Content-Type: text/html; charset=UTF-8',
				sprintf( 'From: %s <%s>', self::header_safe( (string) ( $from[0] ?? '' ) ), self::header_safe( (string) ( $from[1] ?? '' ) ) ),
			],
			$user,
			$type
		);

		$short_circuit = apply_filters( $prefix . '_send', null, $user, $args );
		if ( null !== $short_circuit ) {
			return (bool) $short_circuit;
		}

		$alt_body_handler = static function ( $phpmailer ) use ( &$plaintext ) {
			if ( is_object( $phpmailer ) && property_exists( $phpmailer, 'AltBody' ) ) {
				$phpmailer->AltBody = $plaintext;
			}
		};
		add_action( 'phpmailer_init', $alt_body_handler );

		$sent = wp_mail( '' !== $to ? $to : $user->user_email, $subject, $html, $headers );

		remove_action( 'phpmailer_init', $alt_body_handler );

		if ( ! $sent ) {
			magicauth_debug_log( 'wp_mail returned false (' . $type . '; user_id=' . (int) $user->ID . ')' );
		}
		return (bool) $sent;
	}

	/**
	 * Brand and company args shared by the passkey emails.
	 *
	 * @return array<string,mixed>
	 */
	private static function build_security_args( WP_User $user ): array {
		$brand     = (string) magicauth_get_setting( 'brand_color', '#2271b1' );
		$site_name = (string) get_bloginfo( 'name' );
		$company   = magicauth_get_company_name();

		return [
			'user'         => $user,
			'brand_color'  => $brand,
			'brand_text'   => magicauth_yiq_text_color( $brand ),
			'company_name' => '' !== $company ? $company : $site_name,
			'site_name'    => $site_name,
		];
	}

	/**
	 * Args of the passkey-added email (10.2). No passkey_name: every value is
	 * derived by the server from the stored row.
	 *
	 * @param WP_User $user Owner.
	 * @param object  $row  Credential row.
	 * @return array<string,mixed>
	 */
	private static function build_passkey_added_args( WP_User $user, object $row ): array {
		$args     = self::build_security_args( $user );
		$provider = Aaguids::name( (string) ( $row->aaguid ?? '' ) );
		$added    = strtotime( (string) ( $row->created_at ?? '' ) . ' UTC' );
		$added    = false !== $added ? $added : Clock::now();

		if ( ! empty( $row->backup_state ) ) {
			$sync_label = __( 'Synced across your devices', 'magicauth' );
		} elseif ( ! empty( $row->backup_eligible ) ) {
			$sync_label = __( 'Can be synced, not synced yet', 'magicauth' );
		} else {
			$sync_label = __( 'This device only', 'magicauth' );
		}

		$date_format = (string) get_option( 'date_format', 'F j, Y' );
		$time_format = (string) get_option( 'time_format', 'g:i a' );
		$local       = wp_date( ( '' !== $date_format ? $date_format : 'F j, Y' ) . ' ' . ( '' !== $time_format ? $time_format : 'g:i a' ), $added );

		return $args + [
			/* translators: %s: last 4 characters of the passkey's identifier, for example 9F3A. */
			'passkey_label'   => sprintf( __( 'Passkey ending in %s', 'magicauth' ), strtoupper( substr( (string) ( $row->credential_hash ?? '' ), -4 ) ) ),
			'passkey_suffix'  => strtoupper( substr( (string) ( $row->credential_hash ?? '' ), -4 ) ),
			'provider'        => null !== $provider ? $provider : __( 'Unknown provider', 'magicauth' ),
			/* translators: %s: passkey provider name, as the device reports it. */
			'provider_text'   => null !== $provider ? sprintf( __( '%s (reported by the device)', 'magicauth' ), $provider ) : __( 'Unknown provider', 'magicauth' ),
			'sync_label'      => $sync_label,
			'manage_location' => Module::manage_location( $user ),
			'added_at_local'  => is_string( $local ) ? $local : '',
			'timezone_label'  => wp_timezone_string(),
		];
	}

	/**
	 * The owner's credential row by id, through the per-user read (7.6 rule
	 * X: a former ID holder's row is not the owner's), or null.
	 */
	private static function visible_row( WP_User $user, int $row_id ): ?object {
		foreach ( (array) CredentialStore::for_user( $user ) as $candidate ) {
			if ( (int) $candidate->id === $row_id ) {
				return $candidate;
			}
		}
		return null;
	}

	/**
	 * Valid, distinct (case-insensitive) addresses.
	 *
	 * @param array<int,mixed> $addresses
	 * @return array<int,string>
	 */
	private static function recipients( array $addresses ): array {
		$out = [];
		foreach ( $addresses as $address ) {
			$address = is_string( $address ) ? trim( $address ) : '';
			if ( '' !== $address && is_email( $address ) && ! isset( $out[ strtolower( $address ) ] ) ) {
				$out[ strtolower( $address ) ] = $address;
			}
		}
		return array_values( $out );
	}

	/** Site date and time format in the site time zone (10.2). */
	private static function local_time( int $timestamp ): string {
		$date_format = (string) get_option( 'date_format', 'F j, Y' );
		$time_format = (string) get_option( 'time_format', 'g:i a' );
		$local       = wp_date( ( '' !== $date_format ? $date_format : 'F j, Y' ) . ' ' . ( '' !== $time_format ? $time_format : 'g:i a' ), $timestamp );
		return is_string( $local ) ? $local : '';
	}

	/**
	 * Switches to the recipient's locale; true when switched.
	 *
	 * @param int $user_id Recipient.
	 */
	private static function switch_locale( int $user_id ): bool {
		$locale = get_user_locale( $user_id );
		return '' !== $locale && switch_to_locale( $locale );
	}

	/**
	 * Restores the locale switch_locale() changed.
	 *
	 * @param bool $switched From switch_locale().
	 */
	private static function restore_locale( bool $switched ): void {
		if ( $switched ) {
			restore_previous_locale();
		}
	}

	/** Strip newlines/colons so a malicious display name can't inject headers. */
	private static function header_safe( string $value ): string {
		return trim( str_replace( [ "\r", "\n", ':' ], '', $value ) );
	}
}
