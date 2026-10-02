<?php
/**
 * Procedural helpers for MagicAuth.
 *
 * @package MagicAuth
 */

declare( strict_types=1 );

defined( 'ABSPATH' ) || exit;

if ( ! function_exists( 'magicauth_get_settings' ) ) {
	/** Settings merged onto Installer::default_settings(), the one defaults array. */
	function magicauth_get_settings(): array {
		$defaults = \MagicAuth\Installer::default_settings();

		$saved = function_exists( 'get_option' ) ? get_option( 'magicauth_settings', [] ) : [];
		if ( ! is_array( $saved ) ) {
			$saved = [];
		}

		return array_replace_recursive( $defaults, $saved );
	}
}

if ( ! function_exists( 'magicauth_get_setting' ) ) {
	/**
	 * Read a single top-level setting key.
	 *
	 * @param mixed $fallback Returned when the key is absent.
	 * @return mixed
	 */
	function magicauth_get_setting( string $key, $fallback = null ) {
		$settings = magicauth_get_settings();
		return array_key_exists( $key, $settings ) ? $settings[ $key ] : $fallback;
	}
}

if ( ! function_exists( 'magicauth_get_company_name' ) ) {
	/** Branded display name; falls back to site name when blank. */
	function magicauth_get_company_name(): string {
		$saved = (string) magicauth_get_setting( 'company_name', '' );
		if ( '' !== trim( $saved ) ) {
			return $saved;
		}
		return function_exists( 'get_bloginfo' ) ? (string) get_bloginfo( 'name' ) : '';
	}
}

if ( ! function_exists( 'magicauth_site_email_domain' ) ) {
	/**
	 * The site's own domain, for use as the sender's email domain. Derived from
	 * the site URL (not REMOTE host / SERVER_NAME, which are request-spoofable),
	 * lowercased, with a leading "www." stripped. Keeping the From address on the
	 * site's own domain is what lets it pass SPF/DKIM/DMARC.
	 */
	function magicauth_site_email_domain(): string {
		$host = '';
		if ( function_exists( 'home_url' ) && function_exists( 'wp_parse_url' ) ) {
			$host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		}
		$host = strtolower( trim( $host ) );
		if ( 0 === strpos( $host, 'www.' ) ) {
			$host = substr( $host, 4 );
		}
		return '' !== $host ? $host : 'localhost';
	}
}

if ( ! function_exists( 'magicauth_sanitize_email_local' ) ) {
	/**
	 * Sanitize the local part (before the @) of the sender address. Allows the
	 * common, header-safe subset (letters, digits, . _ - +); strips everything
	 * else, collapses leading/trailing dots, caps at the RFC 64-char limit.
	 * Returns '' when nothing usable survives, so callers can fall back.
	 */
	function magicauth_sanitize_email_local( string $value ): string {
		$value = strtolower( trim( $value ) );
		$value = preg_replace( '/[^a-z0-9._+\-]/', '', $value );
		$value = trim( (string) $value, '.' );
		if ( function_exists( 'mb_substr' ) ) {
			return mb_substr( $value, 0, 64 );
		}
		return substr( $value, 0, 64 );
	}
}

if ( ! function_exists( 'magicauth_get_from_email' ) ) {
	/** Sender address: configurable local part @ the site's own domain. */
	function magicauth_get_from_email(): string {
		$local = magicauth_sanitize_email_local( (string) magicauth_get_setting( 'from_email_local', 'login' ) );
		if ( '' === $local ) {
			$local = 'login';
		}
		return $local . '@' . magicauth_site_email_domain();
	}
}

if ( ! function_exists( 'magicauth_get_agency_credit' ) ) {
	/** Agency-credit payload, or null when name/URL/icon aren't all set. */
	function magicauth_get_agency_credit(): ?array {
		$name   = trim( (string) magicauth_get_setting( 'agency_credit_name', '' ) );
		$url    = trim( (string) magicauth_get_setting( 'agency_credit_url', '' ) );
		$icon_id = (int) magicauth_get_setting( 'agency_credit_icon_id', 0 );
		$label  = trim( (string) magicauth_get_setting( 'agency_credit_label', '' ) );

		if ( '' === $name || '' === $url || $icon_id <= 0 ) {
			return null;
		}

		if ( ! function_exists( 'wp_get_attachment_image_src' ) ) {
			return null;
		}

		$src = wp_get_attachment_image_src( $icon_id, 'thumbnail' );
		if ( ! is_array( $src ) || empty( $src[0] ) ) {
			return null;
		}

		return [
			'name'     => $name,
			'url'      => $url,
			'icon_url' => (string) $src[0],
			'icon_alt' => $name,
			'label'    => $label,
		];
	}
}

if ( ! function_exists( 'magicauth_jitter' ) ) {
	/** Sleep 50–150ms to flatten timing oracles. Called once per response path. */
	function magicauth_jitter(): void {
		if ( defined( 'MAGICAUTH_TESTING' ) && MAGICAUTH_TESTING ) {
			global $magicauth_test_state;
			if ( isset( $magicauth_test_state ) && is_array( $magicauth_test_state ) ) {
				$magicauth_test_state['jitter_calls'] = ( $magicauth_test_state['jitter_calls'] ?? 0 ) + 1;
			}
		}
		usleep( random_int( 50000, 150000 ) );
	}
}

if ( ! function_exists( 'magicauth_client_ip' ) ) {
	/** REMOTE_ADDR only — never X-Forwarded-For. Override via magicauth_client_ip filter if behind validated proxy. */
	function magicauth_client_ip(): string {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- set by the web server, not the client; only HMAC'd, never output.
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '0.0.0.0';

		if ( function_exists( 'apply_filters' ) ) {
			$filtered = apply_filters( 'magicauth_client_ip', $ip );
			if ( is_string( $filtered ) ) {
				$validated = filter_var( $filtered, FILTER_VALIDATE_IP );
				if ( false !== $validated ) {
					$ip = (string) $validated;
				}
			}
		}

		return $ip;
	}
}

if ( ! function_exists( 'magicauth_hash_ip' ) ) {
	/** HMAC-SHA256 the IP, truncated to 16 hex (64 bits) — for rate-limit accounting, not recovery. */
	function magicauth_hash_ip( string $ip ): string {
		$salt = function_exists( 'wp_salt' ) ? wp_salt( 'auth' ) : '';
		return substr( hash_hmac( 'sha256', $ip, $salt ), 0, 16 );
	}
}

if ( ! function_exists( 'magicauth_ip_bucket' ) ) {
	/**
	 * Network bucket of an address for the passkey IP throttles (SPEC 6.9),
	 * HMAC'd with magicauth_hash_ip() like any IP key: IPv4 as is (/32), IPv6
	 * cut to its /64, so a client that owns a /64 gets one bucket, not 2^64.
	 * IPv4-mapped IPv6 counts as its IPv4 address (a /64 cut would put every
	 * such client in one bucket). Anything else comes back unchanged.
	 */
	function magicauth_ip_bucket( string $ip ): string {
		if ( false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			return $ip;
		}
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			return $ip;
		}
		$packed = inet_pton( $ip );
		if ( ! is_string( $packed ) || 16 !== strlen( $packed ) ) {
			return $ip;
		}
		if ( str_repeat( "\0", 10 ) . "\xff\xff" === substr( $packed, 0, 12 ) ) {
			$v4 = inet_ntop( substr( $packed, 12 ) );
			return is_string( $v4 ) ? $v4 : $ip;
		}
		$bucket = inet_ntop( substr( $packed, 0, 8 ) . str_repeat( "\0", 8 ) );
		return is_string( $bucket ) ? $bucket : $ip;
	}
}

if ( ! function_exists( 'magicauth_hash_email' ) ) {
	/** HMAC-SHA256 the lowercased/trimmed email; full 64 hex. */
	function magicauth_hash_email( string $email ): string {
		$salt       = function_exists( 'wp_salt' ) ? wp_salt( 'auth' ) : '';
		$normalized = strtolower( trim( $email ) );
		return hash_hmac( 'sha256', $normalized, $salt );
	}
}

if ( ! function_exists( 'magicauth_yiq_text_color' ) ) {
	/** Black or white text for a hex bg via YIQ luminance. */
	function magicauth_yiq_text_color( string $hex ): string {
		$hex = ltrim( $hex, '#' );
		if ( 3 === strlen( $hex ) ) {
			$hex = $hex[0] . $hex[0] . $hex[1] . $hex[1] . $hex[2] . $hex[2];
		}
		if ( 6 !== strlen( $hex ) || ! ctype_xdigit( $hex ) ) {
			return '#ffffff';
		}
		$r   = hexdec( substr( $hex, 0, 2 ) );
		$g   = hexdec( substr( $hex, 2, 2 ) );
		$b   = hexdec( substr( $hex, 4, 2 ) );
		$yiq = ( ( $r * 299 ) + ( $g * 587 ) + ( $b * 114 ) ) / 1000;
		return $yiq >= 128 ? '#000000' : '#ffffff';
	}
}

if ( ! function_exists( 'magicauth_locale_short_code' ) ) {
	/** Uppercase language-subtag badge for a locale (nl_NL → NL, en_US → EN, pt_BR → PT). */
	function magicauth_locale_short_code( string $locale ): string {
		$locale = trim( $locale );
		if ( '' === $locale ) {
			return '';
		}
		$lang = strtok( $locale, '_-' );
		if ( ! is_string( $lang ) ) {
			$lang = $locale;
		}
		return strtoupper( $lang );
	}
}

if ( ! function_exists( 'magicauth_locale_label' ) ) {
	/**
	 * Human-readable language name for a locale, written in $display_locale's
	 * language. Region-qualified via the intl extension when present (so
	 * pt_BR and pt_PT stay distinct); falls back to the raw locale code.
	 */
	function magicauth_locale_label( string $locale, string $display_locale = '' ): string {
		if ( class_exists( '\Locale' ) ) {
			$display = '' !== $display_locale ? $display_locale : $locale;
			$name    = \Locale::getDisplayName( $locale, $display );
			if ( is_string( $name ) && '' !== $name ) {
				return $name;
			}
		}
		return $locale;
	}
}

if ( ! function_exists( 'magicauth_current_user_can_control_user' ) ) {
	/** Cap gate: edit_user + same-or-higher role. Filterable for custom hierarchies. */
	function magicauth_current_user_can_control_user( int $target_user_id ): bool {
		if ( $target_user_id <= 0 ) {
			return false;
		}

		$can = false;

		if ( function_exists( 'current_user_can' ) && current_user_can( 'edit_user', $target_user_id ) ) {
			$actor  = function_exists( 'wp_get_current_user' ) ? wp_get_current_user() : null;
			$target = function_exists( 'get_userdata' ) ? get_userdata( $target_user_id ) : null;

			if ( $actor && $target && $actor->ID === $target->ID ) {
				$can = true;
			} elseif ( $actor && $target && function_exists( 'wp_roles' ) ) {
				$can = magicauth_actor_outranks_target( $actor, $target );
			}
		}

		if ( function_exists( 'apply_filters' ) ) {
			$can = (bool) apply_filters( 'magicauth_current_user_can_control_user', $can, $target_user_id );
		}

		return $can;
	}
}

if ( ! function_exists( 'magicauth_actor_outranks_target' ) ) {
	/**
	 * Actor caps are a superset of target's. Reads ->allcaps so direct
	 * add_cap() grants count, not just role-derived caps.
	 */
	function magicauth_actor_outranks_target( \WP_User $actor, \WP_User $target ): bool {
		$actor_caps  = array_filter( (array) $actor->allcaps );
		$target_caps = array_filter( (array) $target->allcaps );

		if ( empty( $target_caps ) ) {
			return ! empty( $actor_caps );
		}

		return empty( array_diff_key( $target_caps, $actor_caps ) );
	}
}

if ( ! function_exists( 'magicauth_current_user_can_revoke_passkeys' ) ) {
	/**
	 * Gate for removing another user's passkeys (SPEC 6.12, D-22): the admin
	 * capability (filter magicauth_passkey_admin_capability, default
	 * manage_options), edit_user on the target, administrators and super
	 * admins only by peers. Not magicauth_current_user_can_control_user():
	 * group leaders hold edit_users (B13), and removal is gated on the admin
	 * capability, not on rank. Removal only; nothing creates.
	 * Filter magicauth_current_user_can_revoke_passkeys( $can, $target ).
	 *
	 * @param int $target User whose passkeys would be removed.
	 */
	function magicauth_current_user_can_revoke_passkeys( int $target ): bool {
		$can = false;
		if ( $target > 0 ) {
			$cap = apply_filters( 'magicauth_passkey_admin_capability', 'manage_options' );
			$can = is_string( $cap ) && '' !== $cap
				&& current_user_can( $cap )
				&& current_user_can( 'edit_user', $target )
				&& ( ! user_can( $target, 'manage_options' ) || current_user_can( 'manage_options' ) )
				&& ( ! is_super_admin( $target ) || is_super_admin() );
		}
		return (bool) apply_filters( 'magicauth_current_user_can_revoke_passkeys', $can, $target );
	}
}

if ( ! function_exists( 'magicauth_passkeys_enabled' ) ) {
	/**
	 * Theme contract (SPEC 8.9): whether passkey sign-in runs on this request
	 * (setting on and the site able to run it). Decided once at init.
	 */
	function magicauth_passkeys_enabled(): bool {
		return \MagicAuth\Passkeys\Module::enabled();
	}
}

if ( ! function_exists( 'magicauth_passkey_signin_button' ) ) {
	/**
	 * Theme contract (SPEC 8.9): prints the default passkey sign-in block for a
	 * theme template that renders its own login form. Sign-in only; prints
	 * nothing with the module off or for a signed-in visitor.
	 *
	 * @param array<string,mixed> $args redirect_to: the destination after sign-in.
	 */
	function magicauth_passkey_signin_button( array $args = [] ): void {
		if ( ! magicauth_passkeys_enabled() || is_user_logged_in() ) {
			return;
		}
		echo \MagicAuth\Passkeys\Assets::signin_markup( $args ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- every value escaped in signin_markup().
	}
}

if ( ! function_exists( 'magicauth_debug_log' ) ) {
	/** error_log gated by WP_DEBUG_LOG; filterable. */
	function magicauth_debug_log( string $message ): void {
		$on = defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG;
		if ( function_exists( 'apply_filters' ) ) {
			$on = (bool) apply_filters( 'magicauth_debug_log', $on );
		}
		if ( $on ) {
			error_log( '[magicauth] ' . $message ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		}
	}
}

if ( ! function_exists( 'magicauth_dispatch_after_response' ) ) {
	/**
	 * Run a callable after the HTTP response is flushed — keeps wp_mail SMTP latency
	 * off the response path (closes timing oracle T-1/T-2 without wp-cron).
	 * fastcgi_finish_request (PHP-FPM) closes the client first; otherwise shutdown
	 * phase runs it. MAGICAUTH_TESTING runs sync. Throwables logged, never thrown.
	 */
	function magicauth_dispatch_after_response( callable $task ): void {
		if ( defined( 'MAGICAUTH_TESTING' ) && MAGICAUTH_TESTING ) {
			global $magicauth_test_state;
			if ( isset( $magicauth_test_state ) && is_array( $magicauth_test_state ) ) {
				$magicauth_test_state['after_response_calls'] = ( $magicauth_test_state['after_response_calls'] ?? 0 ) + 1;
			}
			$task();
			return;
		}

		register_shutdown_function(
			static function () use ( $task ): void {
				if ( function_exists( 'fastcgi_finish_request' ) ) {
					fastcgi_finish_request();
				}
				try {
					$task();
				} catch ( \Throwable $e ) {
					magicauth_debug_log( 'after-response task failed: ' . $e->getMessage() );
				}
			}
		);
	}
}
