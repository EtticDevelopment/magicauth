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

	/** Strip newlines/colons so a malicious display name can't inject headers. */
	private static function header_safe( string $value ): string {
		return trim( str_replace( [ "\r", "\n", ':' ], '', $value ) );
	}
}
