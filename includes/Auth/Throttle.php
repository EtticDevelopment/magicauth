<?php
/**
 * Throttle: per-IP/email counters via transients. Security floor is the
 * DB per-row attempt counter in TokenManager; eviction races here are at
 * worst "one extra attempt window," not a bypass.
 *
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Auth;

defined( 'ABSPATH' ) || exit;

/** Transient-backed throttle counters. */
final class Throttle {

	private const PREFIX = 'magicauth_throttle_';

	public const ACTION_LINK_EMAIL        = 'link_email';
	public const ACTION_LINK_EMAIL_CD     = 'link_email_cd';
	public const ACTION_LINK_IP           = 'link_ip';
	public const ACTION_CODE_IP           = 'code_ip';
	public const ACTION_PASSWORD_IP       = 'password_ip';
	public const ACTION_PASSWORD_RESET_IP = 'password_reset_ip';
	public const ACTION_DISABLED_NOTICE   = 'disabled_notice';

	/**
	 * Registry option. Object-cache backends (Redis, Memcached) hold transient
	 * values opaquely — no way to enumerate magicauth_throttle_* keys via WP.
	 * This is our inverse index.
	 */
	public const REGISTRY_OPTION = 'magicauth_throttle_registry';

	/** Soft cap; FIFO-evict oldest. Bounds recovery-button reach under unique-HMAC flood. */
	public const REGISTRY_MAX = 5000;

	/**
	 * In-process registry cache. Lazy-hydrated; mutations flush once at shutdown
	 * so N counters cost one DB write, not N.
	 *
	 * @var array<string,int>|null
	 */
	private static ?array $registry_cache = null;

	/** @var bool */
	private static bool $registry_dirty = false;

	/**
	 * Allow / deny a link-request POST for an email.
	 *
	 * Replaced in v1.3.6: hard-cap-per-window was a DoS primitive (any IP could
	 * lock out any victim email). Cooldown lets the legit user back in fast.
	 * cooldown=0 disables.
	 */
	public static function allow_link_request_email( string $email_hmac ): bool {
		return self::allow_link_request_email_cooldown( $email_hmac );
	}

	/** One transient per email_hmac; value is absolute expiry ts so controller can compute remaining for the toast. */
	public static function allow_link_request_email_cooldown( string $email_hmac ): bool {
		$cooldown = self::email_cooldown_seconds();
		if ( $cooldown <= 0 ) {
			return true;
		}

		$key      = self::PREFIX . self::ACTION_LINK_EMAIL_CD . '_' . $email_hmac;
		$existing = get_transient( $key );
		if ( false !== $existing ) {
			return false;
		}

		$expires_at = time() + $cooldown;
		set_transient( $key, $expires_at, $cooldown );
		self::register_key( $key );
		return true;
	}

	/** Remaining seconds on an active per-email cooldown, or 0. */
	public static function email_cooldown_remaining( string $email_hmac ): int {
		$key      = self::PREFIX . self::ACTION_LINK_EMAIL_CD . '_' . $email_hmac;
		$existing = get_transient( $key );
		if ( false === $existing ) {
			return 0;
		}
		$remaining = (int) $existing - time();
		return $remaining > 0 ? $remaining : 0;
	}

	/** Allow / deny a link-request POST for an IP. */
	public static function allow_link_request_ip( string $ip_hmac ): bool {
		$throttle = self::throttle_settings();
		$window   = max( 1, (int) ( $throttle['per_ip_window_hours'] ?? 1 ) ) * HOUR_IN_SECONDS;
		$max      = max( 1, (int) ( $throttle['per_ip_max'] ?? 10 ) );
		$count    = self::increment( self::ACTION_LINK_IP, $ip_hmac, $window, $max );
		return $count <= $max;
	}

	/** Allow / deny a code-submission POST for an IP. */
	public static function allow_code_submit_ip( string $ip_hmac ): bool {
		$throttle = self::throttle_settings();
		$window   = max( 1, (int) ( $throttle['per_ip_code_window_hours'] ?? 1 ) ) * HOUR_IN_SECONDS;
		$max      = max( 1, (int) ( $throttle['per_ip_code_max'] ?? 20 ) );
		$count    = self::increment( self::ACTION_CODE_IP, $ip_hmac, $window, $max );
		return $count <= $max;
	}

	/**
	 * Allow / deny a password-submission POST for an IP.
	 * Tighter than code-submit: one correct guess is full takeover, no per-row cap to fall back on.
	 */
	public static function allow_password_submit_ip( string $ip_hmac ): bool {
		$throttle = self::throttle_settings();
		$window   = max( 1, (int) ( $throttle['per_ip_password_window_min'] ?? 15 ) ) * MINUTE_IN_SECONDS;
		$max      = max( 1, (int) ( $throttle['per_ip_password_max'] ?? 5 ) );
		$count    = self::increment( self::ACTION_PASSWORD_IP, $ip_hmac, $window, $max );
		return $count <= $max;
	}

	/**
	 * Allow / deny a password-reset request POST for an IP.
	 * Separate bucket: reset sends mail — cap protects deliverability and blocks inbox-flood harassment.
	 */
	public static function allow_password_reset_ip( string $ip_hmac ): bool {
		$throttle = self::throttle_settings();
		$window   = max( 1, (int) ( $throttle['per_ip_password_reset_window_min'] ?? 60 ) ) * MINUTE_IN_SECONDS;
		$max      = max( 1, (int) ( $throttle['per_ip_password_reset_max'] ?? 5 ) );
		$count    = self::increment( self::ACTION_PASSWORD_RESET_IP, $ip_hmac, $window, $max );
		return $count <= $max;
	}

	/**
	 * One-shot marker per 24h window: first call returns true and sets it; subsequent return false.
	 * Boolean (not counter) — defends a disabled user's inbox from spam-via-request-form.
	 */
	public static function allow_disabled_notice( string $email_hmac ): bool {
		$key = self::PREFIX . self::ACTION_DISABLED_NOTICE . '_' . $email_hmac;
		if ( get_transient( $key ) ) {
			return false;
		}
		set_transient( $key, 1, DAY_IN_SECONDS );
		self::register_key( $key );
		return true;
	}

	/** Eraser hook: drop email-keyed counters. No stable IP HMAC for a former user, so IP-side counters expire naturally. */
	public static function reset_for_email( string $email_hmac ): void {
		self::reset( self::ACTION_LINK_EMAIL, $email_hmac );
		self::reset( self::ACTION_LINK_EMAIL_CD, $email_hmac );
		self::reset( self::ACTION_DISABLED_NOTICE, $email_hmac );
	}

	/** Drop IP-side counters for a known IP HMAC (when caller can compute it at eraser time). */
	public static function reset_for_ip( string $ip_hmac ): void {
		self::reset( self::ACTION_LINK_IP, $ip_hmac );
		self::reset( self::ACTION_CODE_IP, $ip_hmac );
		self::reset( self::ACTION_PASSWORD_IP, $ip_hmac );
		self::reset( self::ACTION_PASSWORD_RESET_IP, $ip_hmac );
	}

	/**
	 * Admin "Reset throttle counters": delete every magicauth throttle transient.
	 * v1.3.6 rewrite — registry is authoritative because the old wp_options LIKE
	 * scan no-ops on object-cache backends. LIKE scan kept as defense-in-depth
	 * for pre-1.3.6 keys. Fires `magicauth_throttle_keys_flushed`.
	 */
	public static function admin_flush_all(): int {
		self::hydrate_registry();
		$registered     = is_array( self::$registry_cache ) ? array_keys( self::$registry_cache ) : [];
		$registered_set = array_fill_keys( $registered, true );
		$keys_to_clear  = $registered;

		// Defense-in-depth: pick up any pre-1.3.6 keys written before the registry.
		// Redis-backed sites return no rows here; expected — registry covers new keys.
		global $wpdb;
		if ( isset( $wpdb ) ) {
			$value_like = '_transient_' . self::PREFIX . '%';
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$names = (array) $wpdb->get_col(
				$wpdb->prepare( "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s", $value_like )
			);
			foreach ( $names as $name ) {
				$key = (string) preg_replace( '/^_transient_/', '', (string) $name );
				if ( '' === $key || isset( $registered_set[ $key ] ) ) {
					continue;
				}
				$keys_to_clear[] = $key;
			}
		}

		// Fast path on external object cache (WP 6.0+). delete_transient still runs
		// below so the wp_options fallback row gets cleaned and the count is accurate.
		if (
			! empty( $keys_to_clear )
			&& function_exists( 'wp_using_ext_object_cache' ) && wp_using_ext_object_cache()
			&& function_exists( 'wp_cache_supports' ) && wp_cache_supports( 'delete_multiple' )
			&& function_exists( 'wp_cache_delete_multiple' )
		) {
			wp_cache_delete_multiple( $keys_to_clear, 'transient' );
		}

		$count = 0;
		foreach ( $keys_to_clear as $key ) {
			if ( delete_transient( $key ) ) {
				$count++;
			}
		}

		// Sweep orphaned _transient_timeout_ rows the per-key delete missed.
		if ( isset( $wpdb ) ) {
			$timeout_like = '_transient_timeout_' . self::PREFIX . '%';
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $timeout_like ) );
		}

		// Wipe registry — everything it tracked is gone; future register_key rebuilds.
		self::$registry_cache = [];
		self::$registry_dirty = false;
		if ( function_exists( 'delete_option' ) ) {
			delete_option( self::REGISTRY_OPTION );
		}

		if ( function_exists( 'do_action' ) ) {
			do_action( 'magicauth_throttle_keys_flushed', $count, $keys_to_clear );
		}

		return $count;
	}

	/** Test-only: delete every magicauth throttle transient. Filter-gated so prod no-ops. */
	public static function reset_all(): void {
		if ( ! function_exists( 'apply_filters' ) ) {
			return;
		}
		if ( ! apply_filters( 'magicauth_throttle_allow_reset_all', defined( 'MAGICAUTH_TESTING' ) && MAGICAUTH_TESTING ) ) {
			return;
		}

		self::$registry_cache = null;
		self::$registry_dirty = false;

		global $wpdb;
		if ( ! isset( $wpdb ) ) {
			return;
		}
		$like_a = '_transient_' . self::PREFIX . '%';
		$like_b = '_transient_timeout_' . self::PREFIX . '%';
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $like_a, $like_b ) );
	}

	/** Test-only: drop in-process registry cache. No-op outside MAGICAUTH_TESTING. */
	public static function reset_runtime_state_for_tests(): void {
		if ( defined( 'MAGICAUTH_TESTING' ) && MAGICAUTH_TESTING ) {
			self::$registry_cache = null;
			self::$registry_dirty = false;
		}
	}

	/**
	 * Increment counter; return post-increment count.
	 *
	 * Past the cap (count > max+1) we stop re-stamping so TTL drains. Otherwise
	 * set_transient resets TTL on every hit and a 1 POST/min attacker pins the
	 * bucket forever, locking legit users out. First over-cap call still
	 * re-stamps so TTL anchors to "moment we started rejecting."
	 */
	private static function increment( string $action, string $hmac, int $ttl, int $max = PHP_INT_MAX ): int {
		$name  = self::PREFIX . $action . '_' . $hmac;
		$count = (int) get_transient( $name );
		++$count;
		if ( $count <= $max + 1 ) {
			set_transient( $name, $count, $ttl );
		}
		// Register on first creation only — avoids an update_option per request.
		if ( 1 === $count ) {
			self::register_key( $name );
		}
		return $count;
	}

	/** Drop a single counter. */
	private static function reset( string $action, string $hmac ): void {
		delete_transient( self::PREFIX . $action . '_' . $hmac );
	}

	/** Buffer key in the in-process registry; flush deferred to shutdown so N regs = 1 update_option. */
	private static function register_key( string $key ): void {
		self::hydrate_registry();
		if ( null === self::$registry_cache ) {
			return;
		}
		if ( isset( self::$registry_cache[ $key ] ) ) {
			return;
		}

		self::$registry_cache[ $key ] = 1;

		$cap = self::REGISTRY_MAX;
		if ( function_exists( 'apply_filters' ) ) {
			$filtered = apply_filters( 'magicauth_throttle_registry_max', $cap );
			if ( is_int( $filtered ) && $filtered > 0 ) {
				$cap = $filtered;
			}
		}
		while ( count( self::$registry_cache ) > $cap ) {
			array_shift( self::$registry_cache );
		}

		if ( ! self::$registry_dirty ) {
			self::$registry_dirty = true;
			if ( function_exists( 'register_shutdown_function' ) ) {
				register_shutdown_function( [ self::class, 'flush_registry_writes' ] );
			}
		}
	}

	/** Persist buffered registry. Public for register_shutdown_function; safe to call repeatedly. */
	public static function flush_registry_writes(): void {
		if ( ! self::$registry_dirty || null === self::$registry_cache ) {
			return;
		}
		self::$registry_dirty = false;

		if ( ! function_exists( 'update_option' ) ) {
			return;
		}
		// autoload=false: only read by admin recovery, never on the front-end counter path.
		update_option( self::REGISTRY_OPTION, self::$registry_cache, false );
	}

	/** Lazy-load the registry from wp_options into the in-process cache. */
	private static function hydrate_registry(): void {
		if ( null !== self::$registry_cache ) {
			return;
		}
		$loaded = function_exists( 'get_option' ) ? get_option( self::REGISTRY_OPTION, [] ) : [];
		self::$registry_cache = is_array( $loaded ) ? $loaded : [];
	}

	/** Configured per-email cooldown in seconds. Clamped to [0, 600]; 0 disables. */
	private static function email_cooldown_seconds(): int {
		$throttle = self::throttle_settings();
		$value    = (int) ( $throttle['per_email_cooldown_sec'] ?? 60 );
		if ( $value < 0 ) {
			return 0;
		}
		if ( $value > 600 ) {
			return 600;
		}
		return $value;
	}

	/**
	 * Throttle subarray of settings.
	 *
	 * @return array<string,int>
	 */
	private static function throttle_settings(): array {
		$throttle = magicauth_get_setting( 'throttle', [] );
		return is_array( $throttle ) ? $throttle : [];
	}
}
