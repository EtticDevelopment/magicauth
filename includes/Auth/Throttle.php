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

use MagicAuth\Passkeys\Clock;

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

	// Passkey buckets (SPEC 6.9). IP keys are magicauth_hash_ip( magicauth_ip_bucket( $ip ) ).
	public const ACTION_PASSKEY_OPTS_GLOBAL      = 'passkey_opts_global';
	public const ACTION_PASSKEY_OPTS_IP          = 'passkey_opts_ip';
	public const ACTION_PASSKEY_FAIL_IP          = 'passkey_fail_ip';
	public const ACTION_PASSKEY_REG_USER         = 'passkey_reg_user';
	public const ACTION_PASSKEY_STALE_USER       = 'passkey_stale_user';
	public const ACTION_PASSKEY_REGFAIL_USER     = 'passkey_regfail_user';
	public const ACTION_PASSKEY_MANAGE_USER      = 'passkey_manage_user';
	public const ACTION_PASSKEY_REAUTH_CD        = 'passkey_reauth_cd';
	public const ACTION_PASSKEY_REAUTH_MAIL_USER = 'passkey_reauth_mail_user';
	public const ACTION_PASSKEY_REAUTH_TRY_USER  = 'passkey_reauth_try_user';
	public const ACTION_PASSKEY_REAUTH_OPTS_USER = 'passkey_reauth_opts_user';

	/** Per-user passkey buckets: [ max, window in seconds ] for allow_passkey_user(). */
	public const PASSKEY_USER_LIMITS = [
		self::ACTION_PASSKEY_REG_USER         => [ 20, 3600 ],
		self::ACTION_PASSKEY_STALE_USER       => [ 60, 3600 ],
		self::ACTION_PASSKEY_REGFAIL_USER     => [ 10, 3600 ],
		self::ACTION_PASSKEY_MANAGE_USER      => [ 60, 3600 ],
		self::ACTION_PASSKEY_REAUTH_MAIL_USER => [ 5, 3600 ],
		self::ACTION_PASSKEY_REAUTH_TRY_USER  => [ 20, 3600 ],
		self::ACTION_PASSKEY_REAUTH_OPTS_USER => [ 30, 3600 ],
	];

	/** signin_options issuance window, global and per network. */
	private const PASSKEY_OPTS_WINDOW = 600;

	private const PASSKEY_OPTS_GLOBAL_MAX = 5000;

	private const PASSKEY_OPTS_IP_MAX = 300;

	/** Step-up email cooldown (passkey_reauth_cd). */
	private const PASSKEY_REAUTH_COOLDOWN = 60;

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

	/**
	 * Global signin_options ceiling: 5000 per 10 minutes (filter
	 * magicauth_passkey_options_global_max, clamped to [500, 100000]). Not in
	 * the registry: anonymous traffic, expires on its own.
	 */
	public static function allow_passkey_options_global(): bool {
		$max   = self::filtered_max( 'magicauth_passkey_options_global_max', self::PASSKEY_OPTS_GLOBAL_MAX, 500, 100000 );
		$count = self::bump( self::ACTION_PASSKEY_OPTS_GLOBAL, 'all', self::PASSKEY_OPTS_WINDOW, $max, false );
		return $count <= $max;
	}

	/**
	 * signin_options per network bucket: 300 per 10 minutes (filter
	 * magicauth_passkey_options_ip_max, clamped to [30, 5000]). Not in the
	 * registry: one key per network would rewrite it on every new visitor.
	 *
	 * @param string $bucket_hmac magicauth_hash_ip( magicauth_ip_bucket( $ip ) ).
	 */
	public static function allow_passkey_options_ip( string $bucket_hmac ): bool {
		$max   = self::filtered_max( 'magicauth_passkey_options_ip_max', self::PASSKEY_OPTS_IP_MAX, 30, 5000 );
		$count = self::bump( self::ACTION_PASSKEY_OPTS_IP, $bucket_hmac, self::PASSKEY_OPTS_WINDOW, $max, false );
		return $count <= $max;
	}

	/**
	 * Peek, no increment: true once per_ip_passkey_max failed passkey sign-ins
	 * were recorded for the network bucket inside the window.
	 *
	 * @param string $bucket_hmac magicauth_hash_ip( magicauth_ip_bucket( $ip ) ).
	 */
	public static function passkey_signin_blocked( string $bucket_hmac ): bool {
		$limits = self::passkey_fail_limits();
		return self::peek( self::PREFIX . self::ACTION_PASSKEY_FAIL_IP . '_' . $bucket_hmac ) >= $limits['max'];
	}

	/**
	 * Count one failed passkey sign-in. Callers count only failures after a
	 * bound signin challenge was consumed (6.3), never database errors.
	 *
	 * @param string $bucket_hmac magicauth_hash_ip( magicauth_ip_bucket( $ip ) ).
	 */
	public static function record_passkey_signin_failure( string $bucket_hmac ): void {
		$limits = self::passkey_fail_limits();
		self::bump( self::ACTION_PASSKEY_FAIL_IP, $bucket_hmac, $limits['window'], $limits['max'], true );
	}

	/**
	 * Per-user passkey bucket (key u{ID}); limits in PASSKEY_USER_LIMITS.
	 * Unknown bucket or user: denied.
	 *
	 * @param string $bucket  One of the PASSKEY_USER_LIMITS keys.
	 * @param int    $user_id Signed-in user.
	 * @param int    $max     Calls allowed in the window.
	 * @param int    $window  Window in seconds.
	 */
	public static function allow_passkey_user( string $bucket, int $user_id, int $max, int $window ): bool {
		if ( ! isset( self::PASSKEY_USER_LIMITS[ $bucket ] ) || $user_id <= 0 ) {
			return false;
		}
		$max   = max( 1, $max );
		$count = self::bump( $bucket, 'u' . $user_id, max( 1, $window ), $max, true );
		return $count <= $max;
	}

	/**
	 * Peek, no increment: true once $max calls were counted in the per-user
	 * bucket (passkey_regfail_user is checked before a register and counted
	 * only when it fails). Unknown bucket or user: true (denied).
	 *
	 * @param string $bucket  One of the PASSKEY_USER_LIMITS keys.
	 * @param int    $user_id Signed-in user.
	 * @param int    $max     Calls allowed in the window.
	 */
	public static function passkey_user_exhausted( string $bucket, int $user_id, int $max ): bool {
		if ( ! isset( self::PASSKEY_USER_LIMITS[ $bucket ] ) || $user_id <= 0 ) {
			return true;
		}
		return self::peek( self::PREFIX . $bucket . '_u' . $user_id ) >= max( 1, $max );
	}

	/**
	 * Step-up email cooldown, one per 60 s per user. The value is the absolute
	 * expiry, for passkey_reauth_cooldown_remaining().
	 */
	public static function allow_passkey_reauth_cooldown( int $user_id ): bool {
		if ( $user_id <= 0 ) {
			return false;
		}
		$key = self::PREFIX . self::ACTION_PASSKEY_REAUTH_CD . '_u' . $user_id;
		if ( false !== get_transient( $key ) ) {
			return false;
		}
		set_transient( $key, Clock::now() + self::PASSKEY_REAUTH_COOLDOWN, self::PASSKEY_REAUTH_COOLDOWN );
		self::register_key( $key );
		return true;
	}

	/** Seconds left on the step-up email cooldown, or 0. */
	public static function passkey_reauth_cooldown_remaining( int $user_id ): int {
		$existing = get_transient( self::PREFIX . self::ACTION_PASSKEY_REAUTH_CD . '_u' . $user_id );
		if ( false === $existing ) {
			return 0;
		}
		$remaining = (int) $existing - Clock::now();
		return max( 0, min( self::PASSKEY_REAUTH_COOLDOWN, $remaining ) );
	}

	/** Eraser hook: drop email-keyed counters. No stable IP HMAC for a former user, so IP-side counters expire naturally. */
	public static function reset_for_email( string $email_hmac ): void {
		self::reset( self::ACTION_LINK_EMAIL, $email_hmac );
		self::reset( self::ACTION_LINK_EMAIL_CD, $email_hmac );
		self::reset( self::ACTION_DISABLED_NOTICE, $email_hmac );
	}

	/**
	 * Drop IP-side counters for a known IP HMAC (when caller can compute it at eraser time).
	 * The passkey IP buckets are keyed by network: pass the address as $ip so
	 * an IPv6 /64 is found; without it the IP HMAC is used (equal for IPv4).
	 */
	public static function reset_for_ip( string $ip_hmac, string $ip = '' ): void {
		self::reset( self::ACTION_LINK_IP, $ip_hmac );
		self::reset( self::ACTION_CODE_IP, $ip_hmac );
		self::reset( self::ACTION_PASSWORD_IP, $ip_hmac );
		self::reset( self::ACTION_PASSWORD_RESET_IP, $ip_hmac );

		$bucket_hmac = '' !== $ip ? magicauth_hash_ip( magicauth_ip_bucket( $ip ) ) : $ip_hmac;
		self::reset( self::ACTION_PASSKEY_OPTS_IP, $bucket_hmac );
		self::reset( self::ACTION_PASSKEY_FAIL_IP, $bucket_hmac );
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

	/**
	 * Passkey bucket counter (SPEC 6.9): a fixed window that opens with the
	 * bucket's first call and is never extended by later calls, so a limit
	 * means N per window, not N per gap-free run. The increment is atomic, so
	 * parallel requests cannot lose counts: wp_cache_add()/wp_cache_incr() on
	 * a persistent object cache (the transient group, so get_transient(),
	 * delete_transient() and the admin flush see the same value), otherwise
	 * one UPDATE option_value = option_value + 1 on the transient row, read
	 * back. A call that finds the bucket past $max writes nothing, so the
	 * count stops at max+1 and the window drains. $register: add the key to
	 * the registry (the admin flush); anonymous buckets stay out of it, since
	 * one key per network would rewrite the registry on every new visitor.
	 *
	 * @return int Count after this call; refused when above $max.
	 */
	private static function bump( string $action, string $key, int $ttl, int $max, bool $register ): int {
		$name  = self::PREFIX . $action . '_' . $key;
		$count = self::peek( $name );
		if ( $count > $max ) {
			return $count;
		}
		$after = self::ext_cache() ? self::bump_cache( $name, $ttl, $count ) : self::bump_db( $name, $ttl, $count );
		if ( 1 === $after && $register ) {
			self::register_key( $name );
		}
		return $after;
	}

	/**
	 * Object cache path of bump(): add opens the window, incr keeps its expiry.
	 *
	 * Some drop-ins (Redis Object Cache: INCRBY, or GET then SET on its
	 * igbinary path) do not return false for a missing key: they create it at
	 * the offset with no expiry. An incr result at or below what peek() saw
	 * (or 1 after a failed add) means the key expired or was evicted since the
	 * peek and was recreated that way, so it is written again with the TTL as
	 * a new window (review r2-endpoints-01); a bucket without an expiry would
	 * otherwise refuse for good once past its cap.
	 */
	private static function bump_cache( string $name, int $ttl, int $count ): int {
		if ( 0 === $count && wp_cache_add( $name, 1, 'transient', $ttl ) ) {
			return 1;
		}
		$after = wp_cache_incr( $name, 1, 'transient' );
		if ( false === $after && wp_cache_add( $name, 1, 'transient', $ttl ) ) {
			// Expired or evicted since the peek: a new window.
			return 1;
		}
		if ( false === $after ) {
			$after = wp_cache_incr( $name, 1, 'transient' );
		}
		if ( false === $after ) {
			// A cache that cannot increment still counts, as the old read-then-write did.
			wp_cache_set( $name, $count + 1, 'transient', $ttl );
			return $count + 1;
		}
		$after = (int) $after;
		if ( $after <= max( 1, $count ) ) {
			// Recreated without an expiry since the peek: a new window with the TTL.
			$after = max( 1, $after );
			wp_cache_set( $name, $after, 'transient', $ttl );
			return $after;
		}
		return max( $count + 1, $after );
	}

	/**
	 * Database path of bump(). set_transient() only opens a window; later
	 * calls touch the value row alone, so the timeout row keeps the window's
	 * end. The read-back may include a parallel request's increment, which
	 * only makes the answer stricter.
	 */
	private static function bump_db( string $name, int $ttl, int $count ): int {
		global $wpdb;
		if ( 0 === $count || ! isset( $wpdb ) ) {
			set_transient( $name, $count + 1, $ttl );
			return $count + 1;
		}
		$option = '_transient_' . $name;
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- atomic increment of our own transient row; the options cache is dropped below.
		$updated = $wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->options} SET option_value = option_value + 1 WHERE option_name = %s", $option ) );
		wp_cache_delete( $option, 'options' );
		if ( false === $updated ) {
			return $count + 1;
		}
		if ( 1 !== $updated ) {
			// The row expired or was flushed since the peek: a new window.
			set_transient( $name, 1, $ttl );
			return 1;
		}
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- read-back of the increment above.
		$after = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $option ) );
		return is_numeric( $after ) ? max( $count + 1, (int) $after ) : $count + 1;
	}

	/** Current count of a passkey bucket, 0 when absent or expired. */
	private static function peek( string $name ): int {
		if ( self::ext_cache() ) {
			return (int) wp_cache_get( $name, 'transient' );
		}
		return (int) get_transient( $name );
	}

	/** Whether transients live in a persistent object cache (core's own test). */
	private static function ext_cache(): bool {
		return function_exists( 'wp_using_ext_object_cache' ) && wp_using_ext_object_cache();
	}

	/** Filtered limit; non-numeric -> $default, then clamped to [$min, $max]. */
	private static function filtered_max( string $filter, int $default, int $min, int $max ): int {
		$value = apply_filters( $filter, $default );
		$value = is_numeric( $value ) ? (int) $value : $default;
		return max( $min, min( $max, $value ) );
	}

	/**
	 * passkey_fail_ip limits from the settings (4.7), clamped as sanitize does.
	 *
	 * @return array{max:int,window:int}
	 */
	private static function passkey_fail_limits(): array {
		$throttle = self::throttle_settings();
		return [
			'max'    => max( 1, min( 1000, (int) ( $throttle['per_ip_passkey_max'] ?? 30 ) ) ),
			'window' => max( 1, min( 1440, (int) ( $throttle['per_ip_passkey_window_min'] ?? 15 ) ) ) * MINUTE_IN_SECONDS,
		];
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
