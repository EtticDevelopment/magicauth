<?php
/**
 * Procedural helpers for MagicAuth.
 *
 * @package MagicAuth
 */

declare( strict_types=1 );

defined( 'ABSPATH' ) || exit;

if ( ! function_exists( 'magicauth_get_settings' ) ) {
	/**
	 * Settings merged onto defaults. Memoized per-request via $GLOBALS so the
	 * 7 calls on the login render path don't each rebuild the defaults array
	 * and run array_replace_recursive. Invalidated by the option-update hooks
	 * registered at the bottom of this file (and by the test stubs).
	 */
	function magicauth_get_settings(): array {
		if ( isset( $GLOBALS['magicauth_settings_cache'] ) && is_array( $GLOBALS['magicauth_settings_cache'] ) ) {
			return $GLOBALS['magicauth_settings_cache'];
		}

		$defaults = [
			'ttl_minutes'           => 10,
			'max_link_uses'         => 2,
			'throttle'              => [
				'per_email_cooldown_sec'           => 60,
				'per_ip_window_hours'              => 1,
				'per_ip_max'                       => 10,
				'per_ip_code_window_hours'         => 1,
				'per_ip_code_max'                  => 20,
				'per_ip_password_window_min'       => 15,
				'per_ip_password_max'              => 5,
				'per_ip_password_reset_window_min' => 60,
				'per_ip_password_reset_max'        => 5,
			],
			'replace_default'       => false,
			'company_name'          => '',
			'logo_attachment_id'    => 0,
			'brand_color'           => '#2271b1',
			'link_color'            => '',
			'page_color'            => '#eeeeee',
			'background_attachment_id' => 0,
			'card_radius'           => 6,
			'card_width'            => 480,
			'font_stack'            => 'system',
			'color_mode'            => 'light',
			'agency_credit_name'    => '',
			'agency_credit_url'     => '',
			'agency_credit_icon_id' => 0,
			'agency_credit_label'   => '',
			'redirect_to_default'   => 'auto',
			'allow_password_login'  => true,
			'db_version'            => MAGICAUTH_DB_VERSION,
		];

		$saved = function_exists( 'get_option' ) ? get_option( 'magicauth_settings', [] ) : [];
		if ( ! is_array( $saved ) ) {
			$saved = [];
		}

		$GLOBALS['magicauth_settings_cache'] = array_replace_recursive( $defaults, $saved );
		return $GLOBALS['magicauth_settings_cache'];
	}
}

if ( ! function_exists( 'magicauth_invalidate_settings_cache' ) ) {
	/** Drop the per-request settings memo. Tests reset state; admin saves fire this. */
	function magicauth_invalidate_settings_cache(): void {
		unset( $GLOBALS['magicauth_settings_cache'] );
	}
}

if ( function_exists( 'add_action' ) ) {
	foreach ( [ 'update_option_magicauth_settings', 'add_option_magicauth_settings', 'delete_option_magicauth_settings' ] as $magicauth_cache_hook ) {
		add_action( $magicauth_cache_hook, 'magicauth_invalidate_settings_cache' );
	}
	unset( $magicauth_cache_hook );
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
		usleep( random_int( 50000, 150000 ) );
	}
}

if ( ! function_exists( 'magicauth_client_ip' ) ) {
	/** REMOTE_ADDR only — never X-Forwarded-For. Override via magicauth_client_ip filter if behind validated proxy. */
	function magicauth_client_ip(): string {
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

if ( ! function_exists( 'magicauth_hash_email' ) ) {
	/** HMAC-SHA256 the lowercased/trimmed email; full 64 hex. */
	function magicauth_hash_email( string $email ): string {
		$salt       = function_exists( 'wp_salt' ) ? wp_salt( 'auth' ) : '';
		$normalized = strtolower( trim( $email ) );
		return hash_hmac( 'sha256', $normalized, $salt );
	}
}

if ( ! function_exists( 'magicauth_hex_to_rgb' ) ) {
	/**
	 * Parse a 3- or 6-digit hex color (leading `#` optional) into [r, g, b]
	 * ints (0–255). Returns null on malformed input.
	 *
	 * @return array{0:int,1:int,2:int}|null
	 */
	function magicauth_hex_to_rgb( string $hex ): ?array {
		$hex = ltrim( $hex, '#' );
		if ( 3 === strlen( $hex ) ) {
			$hex = $hex[0] . $hex[0] . $hex[1] . $hex[1] . $hex[2] . $hex[2];
		}
		if ( 6 !== strlen( $hex ) || ! ctype_xdigit( $hex ) ) {
			return null;
		}
		return [
			(int) hexdec( substr( $hex, 0, 2 ) ),
			(int) hexdec( substr( $hex, 2, 2 ) ),
			(int) hexdec( substr( $hex, 4, 2 ) ),
		];
	}
}

if ( ! function_exists( 'magicauth_yiq_text_color' ) ) {
	/** Black or white text for a hex bg via YIQ luminance. */
	function magicauth_yiq_text_color( string $hex ): string {
		$rgb = magicauth_hex_to_rgb( $hex );
		if ( null === $rgb ) {
			return '#ffffff';
		}
		$yiq = ( ( $rgb[0] * 299 ) + ( $rgb[1] * 587 ) + ( $rgb[2] * 114 ) ) / 1000;
		return $yiq >= 128 ? '#000000' : '#ffffff';
	}
}

if ( ! function_exists( 'magicauth_contrast_ratio' ) ) {
	/**
	 * WCAG 2.1 relative-luminance contrast ratio between two hex colors.
	 *
	 * Range: 1.0 (identical) to 21.0 (pure black on pure white). Uses ITU-R
	 * BT.709 coefficients and the sRGB gamma curve per the WCAG 2.1 spec.
	 * Accepts 3- or 6-digit hex with optional leading `#`. Returns 1.0 (the
	 * worst valid ratio) on malformed input — callers should pre-validate.
	 */
	function magicauth_contrast_ratio( string $hex_a, string $hex_b ): float {
		$lum = static function ( string $hex ): ?float {
			$rgb = magicauth_hex_to_rgb( $hex );
			if ( null === $rgb ) {
				return null;
			}
			$channels = [ $rgb[0] / 255.0, $rgb[1] / 255.0, $rgb[2] / 255.0 ];
			foreach ( $channels as &$c ) {
				$c = ( $c <= 0.03928 )
					? $c / 12.92
					: pow( ( $c + 0.055 ) / 1.055, 2.4 );
			}
			unset( $c );
			return ( 0.2126 * $channels[0] ) + ( 0.7152 * $channels[1] ) + ( 0.0722 * $channels[2] );
		};

		$l1 = $lum( $hex_a );
		$l2 = $lum( $hex_b );
		if ( null === $l1 || null === $l2 ) {
			return 1.0;
		}
		if ( $l2 > $l1 ) {
			[ $l1, $l2 ] = [ $l2, $l1 ];
		}
		return ( $l1 + 0.05 ) / ( $l2 + 0.05 );
	}
}

if ( ! function_exists( 'magicauth_contrast_evaluate' ) ) {
	/**
	 * Three-tier WCAG verdict on a contrast ratio.
	 *
	 * - 'fail' below 2.5:1 (unreadable territory; reject at sanitize).
	 * - 'warn' from 2.5:1 to context floor (AA 4.5:1 normal, 3:1 large/UI).
	 * - 'pass' at or above context floor.
	 *
	 * @param float  $ratio   Output of magicauth_contrast_ratio().
	 * @param string $context 'normal'|'large'|'ui' — defaults to 'normal' (strictest).
	 */
	function magicauth_contrast_evaluate( float $ratio, string $context = 'normal' ): string {
		$floor = 'normal' === $context ? 4.5 : 3.0;
		if ( $ratio < 2.5 ) {
			return 'fail';
		}
		if ( $ratio < $floor ) {
			return 'warn';
		}
		return 'pass';
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
