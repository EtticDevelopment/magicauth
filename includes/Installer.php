<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth;

defined( 'ABSPATH' ) || exit;

final class Installer {

	private const SALT_NOTICE_KEY = 'magicauth_salt_notice';

	/**
	 * Site option set when an admin dismisses the weak-salt notice. Site-wide
	 * (a single option, not per-user meta), so one admin dismissing hides the
	 * notice for every admin. check_salts() clears it if salts ever return to
	 * strong, so the notice re-arms on a future regression.
	 */
	private const SALT_NOTICE_DISMISSED_OPTION = 'magicauth_salt_notice_dismissed';

	/** Nonce action backing the AJAX dismissal of the weak-salt notice. */
	private const SALT_NOTICE_DISMISS_NONCE = 'magicauth_dismiss_salt_notice';

	/** The eight key/salt constants WordPress derives wp_salt() from. */
	private const SALT_CONSTANTS = [
		'AUTH_KEY',
		'SECURE_AUTH_KEY',
		'LOGGED_IN_KEY',
		'NONCE_KEY',
		'AUTH_SALT',
		'SECURE_AUTH_SALT',
		'LOGGED_IN_SALT',
		'NONCE_SALT',
	];

	/** Substrings that mark a salt as the shipped wp-config-sample placeholder. */
	private const PLACEHOLDER_MARKERS = [ 'put your unique phrase here' ];

	/** Canonical documentation page that walks an admin through fixing weak salts. */
	public const DOCS_SALTS_URL = 'https://docs.ettic.nl/docs/magicauth/weak-salts';

	/** Option holding the upgrade lock: "<unix time>:<16 hex>", autoload off, present only while migrating. */
	private const UPGRADE_LOCK = 'magicauth_upgrade_lock';

	/** A lock older than this is taken over (the holder died or its schema check failed). */
	private const UPGRADE_LOCK_TTL = 600;

	/**
	 * Option set while the schema check keeps failing: array{at:int,n:int},
	 * autoloaded, so a request inside the backoff window costs no query.
	 */
	private const UPGRADE_RETRY = 'magicauth_upgrade_retry';

	/** Longest wait between two upgrade attempts after repeated failures. */
	private const UPGRADE_RETRY_MAX = DAY_IN_SECONDS;

	/**
	 * Activation: schema (through the upgrade lock, even at the current
	 * version, so reactivation repairs a missing table), defaults, cron, salt
	 * check. Order matters.
	 */
	public static function activate(): void {
		self::upgrade( true );

		if ( false === get_option( 'magicauth_settings' ) ) {
			$seed                 = self::default_settings();
			$seed['company_name'] = (string) get_bloginfo( 'name' );
			add_option( 'magicauth_settings', $seed );
		}

		// Also when another request holds the upgrade lock.
		self::ensure_cron();

		self::check_salts();
	}

	/**
	 * Runs on wp_loaded:1. File deploys never run activation, so the first
	 * request after one migrates. One autoloaded option read when current.
	 */
	public static function maybe_upgrade(): void {
		self::upgrade( false );
	}

	/**
	 * Locked migration. add_option() is not atomic (it pre-checks get_option()
	 * and then runs INSERT ... ON DUPLICATE KEY UPDATE, which reports success
	 * for a second writer), so the lock is a raw INSERT IGNORE; a stale lock is
	 * taken over by compare-and-swap, so exactly one request migrates. The
	 * version is bumped only after the schema is verified.
	 *
	 * @param bool $force Run even when the stored version is current (activation).
	 */
	private static function upgrade( bool $force ): void {
		global $wpdb;

		$installed = (int) get_option( 'magicauth_db_version', 0 );
		if ( ! $force && $installed >= MAGICAUTH_DB_VERSION ) {
			return;
		}

		// After a failed schema check: no lock queries and no dbDelta until
		// the backoff ends, except on the MagicAuth settings screen, whose S8f
		// reason tells the admin to reload to retry.
		if ( ! $force && Passkeys\Clock::now() < self::retry_at() && ! self::is_settings_request() ) {
			return;
		}

		// Unique per request; (int) of it is the time the lock was taken.
		$lock = Passkeys\Clock::now() . ':' . bin2hex( random_bytes( 8 ) );
		$mine = false;
		$prev = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$got = $wpdb->query(
				$wpdb->prepare(
					"INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'off')",
					self::UPGRADE_LOCK,
					$lock
				)
			);
			if ( 1 !== $got ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
				$held = (string) $wpdb->get_var(
					$wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", self::UPGRADE_LOCK )
				);
				if ( Passkeys\Clock::now() - (int) $held < self::UPGRADE_LOCK_TTL ) {
					return; // Another request is migrating.
				}
				// Stale lock: compare-and-swap takeover; exactly one request wins.
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
				$got = $wpdb->query(
					$wpdb->prepare(
						"UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s AND option_value = %s",
						$lock,
						self::UPGRADE_LOCK,
						$held
					)
				);
				if ( 1 !== $got ) {
					return;
				}
			}
			$mine = true;
			wp_cache_delete( self::UPGRADE_LOCK, 'options' );

			self::install_schema();
			if ( ! self::schema_ok() ) {
				magicauth_debug_log( 'maybe_upgrade: schema verification failed' );
				self::schedule_retry();
				// Keep the lock: the next attempt is the stale takeover, not every request.
				$mine = false;
				return;
			}

			// v1 -> v2: 1.0.5 did not record who created a link, so a row
			// still outstanding would sign in as 'link' even when an
			// administrator created it (5.8). Every such row is void.
			if ( $installed < 2 && ! self::void_unattributed_requests() ) {
				magicauth_debug_log( 'maybe_upgrade: voiding 1.0.5 sign-in links failed' );
				self::schedule_retry();
				$mine = false;
				return;
			}

			self::ensure_cron();
			update_option( 'magicauth_db_version', MAGICAUTH_DB_VERSION );
			delete_option( self::UPGRADE_RETRY );
			self::sweep_orphans( 1000 );
		} finally {
			if ( $mine ) {
				// Releases only our own lock; a takeover's value stays.
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
				$wpdb->query(
					$wpdb->prepare(
						"DELETE FROM {$wpdb->options} WHERE option_name = %s AND option_value = %s",
						self::UPGRADE_LOCK,
						$lock
					)
				);
				wp_cache_delete( self::UPGRADE_LOCK, 'options' );
			}
			$wpdb->suppress_errors( $prev );
		}
	}

	/**
	 * Marks every outstanding requests row consumed (the v1 to v2 step).
	 * Callers suppress errors.
	 */
	private static function void_unattributed_requests(): bool {
		global $wpdb;

		$requests = $wpdb->prefix . 'magicauth_requests';
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix; one-time migration.
		$done = $wpdb->query( $wpdb->prepare( "UPDATE {$requests} SET consumed_at = %s WHERE consumed_at IS NULL", gmdate( 'Y-m-d H:i:s', Passkeys\Clock::now() ) ) );
		return false !== $done;
	}

	/** End of the current upgrade backoff, 0 when none. */
	private static function retry_at(): int {
		$retry = get_option( self::UPGRADE_RETRY, [] );
		return is_array( $retry ) ? (int) ( $retry['at'] ?? 0 ) : 0;
	}

	/**
	 * Exponential backoff after a failed schema check: the lock TTL, doubled
	 * per consecutive failure, at most a day. Autoloaded (read on every
	 * request while the version is behind).
	 */
	private static function schedule_retry(): void {
		$retry = get_option( self::UPGRADE_RETRY, [] );
		$n     = min( 10, ( is_array( $retry ) ? (int) ( $retry['n'] ?? 0 ) : 0 ) + 1 );
		$delay = min( self::UPGRADE_RETRY_MAX, self::UPGRADE_LOCK_TTL * ( 2 ** ( $n - 1 ) ) );
		update_option(
			self::UPGRADE_RETRY,
			[
				'at' => Passkeys\Clock::now() + $delay,
				'n'  => $n,
			],
			true
		);
	}

	/** An administrator viewing the MagicAuth settings screen. */
	private static function is_settings_request(): bool {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only screen check.
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		return 'magicauth' === $page && is_admin() && current_user_can( 'manage_options' );
	}

	/**
	 * Every table answers a query and the requests table has issued_by.
	 * Portable to the SQLite test shim (no SHOW TABLES). Callers suppress errors.
	 */
	private static function schema_ok(): bool {
		global $wpdb;

		foreach ( self::tables() as $table ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$wpdb->query( "SELECT 1 FROM {$table} LIMIT 1" );
			if ( '' !== $wpdb->last_error ) {
				return false;
			}
		}
		$requests = $wpdb->prefix . 'magicauth_requests';
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
		$wpdb->query( "SELECT issued_by FROM {$requests} LIMIT 1" );
		return '' === $wpdb->last_error;
	}

	/**
	 * The four tables of DB version 2, in schema() order.
	 *
	 * @return array<int,string>
	 */
	private static function tables(): array {
		global $wpdb;
		return [
			$wpdb->prefix . 'magicauth_requests',
			$wpdb->prefix . 'magicauth_passkeys',
			$wpdb->prefix . 'magicauth_passkey_challenges',
			$wpdb->prefix . 'magicauth_passkey_sessions',
		];
	}

	/**
	 * Rows of users that no longer exist (delete_user did not run: plugin off
	 * or MAGICAUTH_DISABLE at deletion time, direct SQL, bulk tools). Up to
	 * $limit per table: credentials, challenges with a user, session state.
	 * SELECT then DELETE ... IN (portable; SQLite rejects DELETE ... LIMIT).
	 *
	 * @internal
	 * @param int $limit Maximum rows per table.
	 * @return int Rows deleted.
	 */
	public static function sweep_orphans( int $limit ): int {
		global $wpdb;

		$limit   = max( 1, $limit );
		$targets = [
			[ $wpdb->prefix . 'magicauth_passkeys', 'id', '%d', '' ],
			[ $wpdb->prefix . 'magicauth_passkey_challenges', 'id', '%d', ' AND t.user_id > 0' ],
			[ $wpdb->prefix . 'magicauth_passkey_sessions', 'session_hash', '%s', '' ],
		];
		$deleted = 0;
		$prev    = $wpdb->suppress_errors( true );
		try {
			foreach ( $targets as [ $table, $key, $format, $extra ] ) {
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table and column names are constants above.
				$ids = $wpdb->get_col( $wpdb->prepare( "SELECT t.{$key} FROM {$table} t LEFT JOIN {$wpdb->users} u ON u.ID = t.user_id WHERE u.ID IS NULL{$extra} LIMIT %d", $limit ) );
				if ( '' !== $wpdb->last_error ) {
					magicauth_debug_log( 'sweep_orphans: select failed' );
					continue;
				}
				if ( [] === $ids ) {
					continue;
				}
				$in = implode( ',', array_fill( 0, count( $ids ), $format ) );
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- one placeholder per id.
				$done = $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE {$key} IN ({$in})", $ids ) );
				if ( false === $done ) {
					magicauth_debug_log( 'sweep_orphans: delete failed' );
					continue;
				}
				$deleted += (int) $done;
			}
		} finally {
			$wpdb->suppress_errors( $prev );
		}
		return $deleted;
	}

	/** Cron self-heal: reschedules the daily cleanup when it went missing. */
	private static function ensure_cron(): void {
		if ( ! wp_next_scheduled( 'magicauth_daily_cleanup' ) ) {
			wp_schedule_event( time() + DAY_IN_SECONDS, 'daily', 'magicauth_daily_cleanup' );
		}
	}

	/** Deactivation: clears cron only. Never touches data. */
	public static function deactivate(): void {
		wp_clear_scheduled_hook( 'magicauth_daily_cleanup' );
	}

	/**
	 * Daily cron: sweeps consumed, expired, fully-used request rows; challenge
	 * rows expired over an hour ago; expired session state rows; rows of
	 * deleted users (5.4).
	 */
	public static function daily_cleanup(): void {
		global $wpdb;

		$table     = $wpdb->prefix . 'magicauth_requests';
		$max_uses  = (int) magicauth_get_setting( 'max_link_uses', 2 );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix.
				"DELETE FROM {$table}
				 WHERE consumed_at IS NOT NULL
				    OR expires_at < %s
				    OR use_count >= %d
				 LIMIT 1000",
				current_time( 'mysql', true ),
				$max_uses
			)
		);

		Passkeys\ChallengeStore::purge_expired( 5000, HOUR_IN_SECONDS );
		Passkeys\SessionState::purge_expired( 5000 );
		self::sweep_orphans( 1000 );
	}

	/**
	 * delete_user: the user's sign-in rows go with the account instead of
	 * waiting for cron (B10). On multisite the hook fires when the user is
	 * removed from this site, and the table is per site. Errors suppressed: the
	 * table is missing before the first migration, and deleting a user must
	 * not print SQL into the page.
	 *
	 * @param int $user_id ID of the user being deleted.
	 */
	public static function on_delete_user( int $user_id ): void {
		global $wpdb;

		if ( $user_id <= 0 ) {
			return;
		}
		$table = $wpdb->prefix . 'magicauth_requests';
		$prev  = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$done = $wpdb->query(
				$wpdb->prepare(
					// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix.
					"DELETE FROM {$table} WHERE user_id = %d",
					$user_id
				)
			);
		} finally {
			$wpdb->suppress_errors( $prev );
		}
		if ( false === $done ) {
			magicauth_debug_log( 'delete_user: requests cleanup failed' );
		}
	}

	/** dbDelta installer: all four tables in one call. Run through upgrade() (errors suppressed, locked). */
	private static function install_schema(): void {
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		dbDelta( self::schema() );
	}

	/**
	 * The CREATE TABLE strings of DB version 2 (5.1, 5.2, 5.6, 5.8): requests
	 * (with issued_by), passkeys, passkey challenges, passkey sessions.
	 * dbDelta quirks: two spaces after PRIMARY KEY, lowercase types, no
	 * backticks, KEY (not INDEX). Do not "tidy" these strings.
	 *
	 * @internal Public for the DDL parity tests and the real-database harness.
	 * @return array<int,string>
	 */
	public static function schema(): array {
		global $wpdb;

		[ $requests, $passkeys, $challenges, $sessions ] = self::tables();
		$charset_collate = $wpdb->get_charset_collate();

		return [
			"CREATE TABLE {$requests} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  selector char(16) NOT NULL,
  link_verifier_hash char(64) NOT NULL,
  code_verifier_hash char(64) NOT NULL,
  user_id bigint(20) unsigned NOT NULL,
  email_hmac char(64) NOT NULL,
  ip_hmac char(16) NOT NULL,
  created_at datetime NOT NULL,
  expires_at datetime NOT NULL,
  consumed_at datetime DEFAULT NULL,
  use_count tinyint(3) unsigned NOT NULL DEFAULT 0,
  code_attempts tinyint(3) unsigned NOT NULL DEFAULT 0,
  issued_by bigint(20) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY  (id),
  UNIQUE KEY selector (selector),
  KEY email_hmac_consumed (email_hmac, consumed_at),
  KEY user_id (user_id)
) {$charset_collate};",
			"CREATE TABLE {$passkeys} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  user_id bigint(20) unsigned NOT NULL,
  rp_id varchar(253) NOT NULL,
  credential_id varchar(1400) NOT NULL,
  credential_hash char(64) NOT NULL,
  user_handle varchar(88) NOT NULL,
  public_key text NOT NULL,
  alg smallint(6) NOT NULL,
  sign_count int(10) unsigned NOT NULL DEFAULT 0,
  backup_eligible tinyint(1) unsigned NOT NULL DEFAULT 0,
  backup_state tinyint(1) unsigned NOT NULL DEFAULT 0,
  transports varchar(64) NOT NULL DEFAULT '',
  aaguid char(36) NOT NULL DEFAULT '',
  name varchar(64) NOT NULL DEFAULT '',
  user_registered char(19) NOT NULL DEFAULT '',
  created_at datetime NOT NULL,
  last_used_at datetime DEFAULT NULL,
  counter_anomaly_at datetime DEFAULT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY credential_hash (credential_hash),
  KEY user_id (user_id)
) {$charset_collate};",
			"CREATE TABLE {$challenges} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  lookup_hash char(64) NOT NULL,
  ceremony varchar(16) NOT NULL,
  user_id bigint(20) unsigned NOT NULL DEFAULT 0,
  session_hash char(64) NOT NULL DEFAULT '',
  binding_hash char(64) NOT NULL DEFAULT '',
  secret_hash char(64) NOT NULL DEFAULT '',
  user_handle varchar(88) NOT NULL DEFAULT '',
  algs varchar(32) NOT NULL DEFAULT '',
  attempts tinyint(3) unsigned NOT NULL DEFAULT 0,
  created_at datetime NOT NULL,
  expires_at datetime NOT NULL,
  consumed_at datetime DEFAULT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY lookup_hash (lookup_hash),
  KEY expires_at (expires_at),
  KEY user_id (user_id)
) {$charset_collate};",
			"CREATE TABLE {$sessions} (
  session_hash char(64) NOT NULL,
  user_id bigint(20) unsigned NOT NULL,
  reauth_at int(10) unsigned NOT NULL DEFAULT 0,
  reauth_method varchar(16) NOT NULL DEFAULT '',
  fresh_hash char(64) NOT NULL DEFAULT '',
  prompt_done tinyint(1) unsigned NOT NULL DEFAULT 0,
  signals_at int(10) unsigned NOT NULL DEFAULT 0,
  expires_at datetime NOT NULL,
  PRIMARY KEY  (session_hash),
  KEY user_id (user_id),
  KEY expires_at (expires_at)
) {$charset_collate};",
		];
	}

	/**
	 * Default settings — mirrors plan §4.
	 *
	 * @return array<string,mixed>
	 */
	public static function default_settings(): array {
		return [
			'ttl_minutes'            => 10,
			'max_link_uses'          => 2,
			'throttle'               => [
				'per_email_cooldown_sec'           => 60,
				'per_ip_window_hours'              => 1,
				'per_ip_max'                       => 10,
				'per_ip_code_window_hours'         => 1,
				'per_ip_code_max'                  => 20,
				'per_ip_password_window_min'       => 15,
				'per_ip_password_max'              => 5,
				'per_ip_password_reset_window_min' => 60,
				'per_ip_password_reset_max'        => 5,
				'per_ip_passkey_window_min'        => 15,
				'per_ip_passkey_max'               => 30,
			],
			'replace_default'        => false,
			'company_name'           => '',
			'logo_attachment_id'     => 0,
			'brand_color'            => '#2271b1',
			'agency_credit_name'     => '',
			'agency_credit_url'      => '',
			'agency_credit_icon_id'  => 0,
			'agency_credit_label'    => '',
			'redirect_to_default'    => 'auto',
			'allow_password_login'   => true,
			'hide_language_switcher' => false,
			'from_email_local'       => 'login',
			'db_version'             => MAGICAUTH_DB_VERSION,
			// Passkeys module (SPEC 4.7); off by default.
			'passkeys_enabled'             => false,
			'passkeys_prompt'              => true,
			'passkeys_manage_page_id'      => 0,
			'passkeys_email_reverify_days' => 0,
		];
	}

	/**
	 * True when the live wp_salt() inputs are weak: any of the eight constants is
	 * undefined, empty, or still the shipped placeholder. Reads the runtime
	 * constants, so it reflects whatever wp-config.php (plus any environment- or
	 * include-provided salts) actually loaded for this request — the authoritative
	 * source of truth, and correct for managed hosts (Bedrock, WP Engine, Pantheon)
	 * that define salts outside a literal wp-config.php define().
	 */
	private static function runtime_salts_weak(): bool {
		foreach ( self::SALT_CONSTANTS as $constant ) {
			$value = defined( $constant ) ? constant( $constant ) : '';
			if ( ! is_string( $value ) || '' === $value ) {
				return true;
			}
			foreach ( self::PLACEHOLDER_MARKERS as $marker ) {
				if ( false !== stripos( $value, $marker ) ) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Keep the weak-salt admin-notice transient in sync with runtime reality.
	 * Runs on activation and on every admin_init, so a site whose salts are
	 * provided by the environment, or fixed by hand, clears the notice on its
	 * own without a false "still weak" nag. Writes only on a state change. When
	 * salts test strong again it also drops the site-wide dismissal so a later
	 * regression re-arms the notice.
	 */
	public static function check_salts(): void {
		$weak    = self::runtime_salts_weak();
		$flagged = (bool) get_transient( self::SALT_NOTICE_KEY );
		if ( $weak && ! $flagged ) {
			set_transient( self::SALT_NOTICE_KEY, 1, WEEK_IN_SECONDS );
		} elseif ( ! $weak && $flagged ) {
			delete_transient( self::SALT_NOTICE_KEY );
		}

		// Re-arm the dismissible notice if salts return to strong. Guarded so we
		// only write on an actual state change.
		if ( ! $weak && false !== get_option( self::SALT_NOTICE_DISMISSED_OPTION, false ) ) {
			delete_option( self::SALT_NOTICE_DISMISSED_OPTION );
		}
	}

	/** Whether the weak-salt notice is raised. Drives the notice and the toggle warning. */
	public static function has_weak_salts(): bool {
		return (bool) get_transient( self::SALT_NOTICE_KEY );
	}

	/**
	 * Admin notice when fastcgi_finish_request is unavailable. Without it,
	 * magicauth_dispatch_after_response can't actually flush early, so SMTP
	 * latency leaks back into response time and reopens the timing oracle.
	 * Only shown to manage_options users on dashboard/plugins/settings screens.
	 */
	public static function render_fpm_notice(): void {
		if ( function_exists( 'fastcgi_finish_request' ) || function_exists( 'litespeed_finish_request' ) ) {
			return;
		}
		if ( ! function_exists( 'current_user_can' ) || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		$id     = $screen ? (string) $screen->id : '';
		if ( ! in_array( $id, [ 'dashboard', 'plugins', 'settings_page_magicauth' ], true ) ) {
			return;
		}
		?>
		<div class="notice notice-warning">
			<p>
				<strong><?php esc_html_e( 'MagicAuth: response-flush helper unavailable.', 'magicauth' ); ?></strong>
				<?php esc_html_e( 'Your PHP runtime does not provide fastcgi_finish_request(). MagicAuth cannot defer email sending until after the response, so SMTP latency may leak whether an account exists. Switch to PHP-FPM (or LiteSpeed) for full timing parity.', 'magicauth' ); ?>
			</p>
		</div>
		<?php
	}

	/**
	 * Admin notice for weak salts. Shown to manage_options users on every admin
	 * screen until the salts are fixed or an admin dismisses it. MagicAuth does
	 * not generate salts or edit wp-config.php; the notice points to the docs,
	 * where the fix is "generate at api.wordpress.org, paste into wp-config.php,
	 * reload". Dismissal is site-wide (one option) and persisted via the AJAX
	 * handler below; check_salts() re-arms it if salts ever regress. The notice
	 * carries a small self-contained dismiss script because it renders on admin
	 * screens where magicauth-admin.js is not enqueued.
	 */
	public static function render_salt_notice(): void {
		if ( ! self::has_weak_salts() ) {
			return;
		}
		if ( get_option( self::SALT_NOTICE_DISMISSED_OPTION ) ) {
			return;
		}
		if ( ! function_exists( 'current_user_can' ) || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$nonce = wp_create_nonce( self::SALT_NOTICE_DISMISS_NONCE );
		?>
		<div class="notice notice-warning is-dismissible magicauth-salt-notice"
			data-magicauth-salt-notice
			data-nonce="<?php echo esc_attr( $nonce ); ?>"
			data-ajaxurl="<?php echo esc_url( admin_url( 'admin-ajax.php' ) ); ?>">
			<p>
				<strong><?php esc_html_e( 'MagicAuth: weak WordPress salts detected.', 'magicauth' ); ?></strong>
				<?php esc_html_e( 'Your security keys still hold placeholder or empty values, so token and session secrets are not unique to this site. Your magic links stay safe (each carries its own random secret), but fixing this is recommended — especially before turning on the branded login replacement.', 'magicauth' ); ?>
			</p>
			<p>
				<a href="<?php echo esc_url( self::DOCS_SALTS_URL ); ?>" class="button button-primary" target="_blank" rel="noopener"><?php esc_html_e( 'Learn how to fix this', 'magicauth' ); ?></a>
			</p>
		</div>
		<script>
		( function () {
			document.addEventListener( 'click', function ( ev ) {
				var dismiss = ev.target.closest ? ev.target.closest( '.notice-dismiss' ) : null;
				if ( ! dismiss ) { return; }
				var notice = dismiss.closest( '[data-magicauth-salt-notice]' );
				if ( ! notice ) { return; }
				fetch( notice.getAttribute( 'data-ajaxurl' ), {
					method: 'POST',
					credentials: 'same-origin',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
					body: new URLSearchParams( {
						action: 'magicauth_dismiss_salt_notice',
						_ajax_nonce: notice.getAttribute( 'data-nonce' )
					} )
				} );
			} );
		} )();
		</script>
		<?php
	}

	/**
	 * AJAX: persist a site-wide dismissal of the weak-salt notice. One admin
	 * dismissing hides it for every admin (a single site option, not per-user
	 * meta). check_salts() clears the option if salts ever return to strong, so
	 * the notice re-arms on a future regression.
	 */
	public static function ajax_dismiss_salt_notice(): void {
		check_ajax_referer( self::SALT_NOTICE_DISMISS_NONCE );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( [ 'message' => __( 'You are not allowed to do this.', 'magicauth' ) ], 403 );
		}
		update_option( self::SALT_NOTICE_DISMISSED_OPTION, 1 );
		wp_send_json_success();
	}
}
