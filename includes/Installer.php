<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth;

defined( 'ABSPATH' ) || exit;

final class Installer {

	private const SALT_NOTICE_KEY = 'magicauth_salt_notice';

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

	/** Activation: schema, defaults, cron, salt check. Order matters. */
	public static function activate(): void {
		self::install_schema();

		if ( false === get_option( 'magicauth_settings' ) ) {
			$seed                 = self::default_settings();
			$seed['company_name'] = (string) get_bloginfo( 'name' );
			add_option( 'magicauth_settings', $seed );
		}

		update_option( 'magicauth_db_version', MAGICAUTH_DB_VERSION );

		if ( ! wp_next_scheduled( 'magicauth_daily_cleanup' ) ) {
			wp_schedule_event( time() + DAY_IN_SECONDS, 'daily', 'magicauth_daily_cleanup' );
		}

		self::check_salts();
	}

	/** Deactivation: clears cron only. Never touches data. */
	public static function deactivate(): void {
		wp_clear_scheduled_hook( 'magicauth_daily_cleanup' );
	}

	/** Daily cron: sweeps consumed, expired, fully-used rows. */
	public static function daily_cleanup(): void {
		global $wpdb;

		$table     = $wpdb->prefix . 'magicauth_requests';
		$max_uses  = (int) magicauth_get_setting( 'max_link_uses', 2 );

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$table}
				 WHERE consumed_at IS NOT NULL
				    OR expires_at < %s
				    OR use_count >= %d
				 LIMIT 1000",
				current_time( 'mysql', true ),
				$max_uses
			)
		);
	}

	/** dbDelta installer. Schema: plan.md §3. */
	private static function install_schema(): void {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$table           = $wpdb->prefix . 'magicauth_requests';
		$charset_collate = $wpdb->get_charset_collate();

		// dbDelta quirks: two spaces after PRIMARY KEY, lowercase types,
		// no backticks, KEY (not INDEX). Do not "tidy" this string.
		$sql = "CREATE TABLE {$table} (
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
  PRIMARY KEY  (id),
  UNIQUE KEY selector (selector),
  KEY email_hmac_consumed (email_hmac, consumed_at),
  KEY user_id (user_id)
) {$charset_collate};";

		dbDelta( $sql );
	}

	/**
	 * Default settings — mirrors plan §4.
	 *
	 * @return array<string,mixed>
	 */
	public static function default_settings(): array {
		return [
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
			'agency_credit_name'    => '',
			'agency_credit_url'     => '',
			'agency_credit_icon_id' => 0,
			'agency_credit_label'   => '',
			'redirect_to_default'   => 'auto',
			'allow_password_login'  => true,
			'db_version'            => MAGICAUTH_DB_VERSION,
		];
	}

	/**
	 * Detect placeholder salts in wp-config. Sets transient picked up by admin
	 * notice. Never blocks activation; only refuses replace_default.
	 */
	public static function check_salts(): void {
		foreach ( self::SALT_CONSTANTS as $constant ) {
			$value = defined( $constant ) ? constant( $constant ) : '';
			if ( ! is_string( $value ) || '' === $value ) {
				set_transient( self::SALT_NOTICE_KEY, 1, WEEK_IN_SECONDS );
				return;
			}
			foreach ( self::PLACEHOLDER_MARKERS as $marker ) {
				if ( false !== stripos( $value, $marker ) ) {
					set_transient( self::SALT_NOTICE_KEY, 1, WEEK_IN_SECONDS );
					return;
				}
			}
		}

		delete_transient( self::SALT_NOTICE_KEY );
	}

	/** Settings::sanitize uses this to refuse replace_default=true. */
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

	/** Admin notice for weak salts. */
	public static function render_salt_notice(): void {
		if ( ! self::has_weak_salts() ) {
			return;
		}
		if ( ! function_exists( 'current_user_can' ) || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$fix_url = add_query_arg(
			[
				'page'                => 'magicauth',
				'magicauth-fix-salts' => '1',
			],
			admin_url( 'options-general.php' )
		);
		?>
		<div class="notice notice-error">
			<p>
				<strong><?php esc_html_e( 'MagicAuth: weak WordPress salts detected.', 'magicauth' ); ?></strong>
				<?php esc_html_e( 'Your security keys still hold placeholder or empty values, so token and session secrets are not unique to this site. Branded login replacement is disabled until this is resolved.', 'magicauth' ); ?>
			</p>
			<p>
				<a href="<?php echo esc_url( $fix_url ); ?>" class="button button-primary"><?php esc_html_e( 'Fix it for me', 'magicauth' ); ?></a>
				<?php
				echo ' ';
				echo wp_kses(
					sprintf(
						/* translators: %s: salt generator URL */
						__( 'or generate them yourself at <a href="%s" target="_blank" rel="noopener">api.wordpress.org/secret-key</a> and paste into <code>wp-config.php</code>.', 'magicauth' ),
						'https://api.wordpress.org/secret-key/1.1/salt/'
					),
					[
						'a'    => [
							'href'   => true,
							'target' => true,
							'rel'    => true,
						],
						'code' => [],
					]
				);
				?>
			</p>
		</div>
		<?php
	}

	/** Local fallback: one strong salt value (random_bytes, base64 — quote-safe). */
	public static function generate_salt_value(): string {
		return base64_encode( random_bytes( 48 ) );
	}

	/**
	 * Fetch fresh salts from the official WordPress generator, the same source
	 * core's installer uses. Returns a name => value map for all eight constants,
	 * or null on any failure so the caller can fall back to local generation.
	 *
	 * Values are rejected if they contain a single quote or backslash, preserving
	 * the invariant that every salt is safe to splice into a single-quoted literal.
	 *
	 * @return array<string,string>|null
	 */
	private static function fetch_salts_from_api(): ?array {
		if ( ! function_exists( 'wp_remote_get' ) ) {
			return null;
		}
		$response = wp_remote_get(
			'https://api.wordpress.org/secret-key/1.1/salt/',
			[ 'timeout' => 8 ]
		);
		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}
		$body = wp_remote_retrieve_body( $response );
		if ( '' === $body ) {
			return null;
		}

		$values = [];
		foreach ( self::SALT_CONSTANTS as $name ) {
			if ( ! preg_match( self::define_pattern( $name ), $body, $matches ) ) {
				return null;
			}
			$value = $matches[3];
			if ( '' === trim( $value ) || false !== strpbrk( $value, "'\\" ) ) {
				return null;
			}
			foreach ( self::PLACEHOLDER_MARKERS as $marker ) {
				if ( false !== stripos( $value, $marker ) ) {
					return null;
				}
			}
			$values[ $name ] = $value;
		}
		return $values;
	}

	/**
	 * The eight salt values to write: the WordPress API first, local generation
	 * as a fallback (offline, firewalled, or air-gapped sites — common where
	 * placeholder salts occur).
	 *
	 * @return array<string,string>
	 */
	private static function salt_values(): array {
		$api = self::fetch_salts_from_api();
		if ( null !== $api ) {
			return $api;
		}
		$values = [];
		foreach ( self::SALT_CONSTANTS as $name ) {
			$values[ $name ] = self::generate_salt_value();
		}
		return $values;
	}

	/**
	 * Build a ready-to-paste block of all eight define() lines with fresh salts.
	 * Used for the manual copy-and-paste path when wp-config.php is not writable.
	 */
	public static function generate_salt_block(): string {
		$lines = [];
		foreach ( self::salt_values() as $name => $value ) {
			$lines[] = sprintf( "define( '%s', '%s' );", $name, $value );
		}
		return implode( "\n", $lines );
	}

	/** Regex capturing a single define() with its quote style and value (group 3). */
	private static function define_pattern( string $name ): string {
		return '/define\(\s*([\'"])' . preg_quote( $name, '/' ) . '\1\s*,\s*([\'"])(.*?)\2\s*\)\s*;/s';
	}

	/** True only when all eight salt defines are present in the given config text. */
	private static function defines_present( string $contents ): bool {
		foreach ( self::SALT_CONSTANTS as $name ) {
			if ( ! preg_match( self::define_pattern( $name ), $contents ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * File-based weak-salt detection (operates on wp-config text, not runtime
	 * constants). A salt is weak if missing, empty, or placeholder.
	 */
	public static function config_has_weak_salts( string $contents ): bool {
		foreach ( self::SALT_CONSTANTS as $name ) {
			if ( ! preg_match( self::define_pattern( $name ), $contents, $matches ) ) {
				return true;
			}
			$value = $matches[3];
			if ( '' === trim( $value ) ) {
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
	 * Replace every salt define's value with the supplied one, preserving the
	 * rest of the line verbatim. Pure string transform — returns null if any of
	 * the eight defines is absent or has no value (caller falls back to paste).
	 *
	 * @param array<string,string> $values Salt values keyed by constant name.
	 */
	public static function rewrite_salt_defines( string $contents, array $values ): ?string {
		foreach ( self::SALT_CONSTANTS as $name ) {
			if ( ! isset( $values[ $name ] ) || '' === $values[ $name ] ) {
				return null;
			}
			$value   = $values[ $name ];
			$pattern = '/(define\(\s*([\'"])' . preg_quote( $name, '/' ) . '\2\s*,\s*)([\'"]).*?\3(\s*\)\s*;)/s';
			$count   = 0;
			$result  = preg_replace_callback(
				$pattern,
				static function ( array $matches ) use ( $value ): string {
					return (string) $matches[1] . "'" . $value . "'" . (string) $matches[4];
				},
				$contents,
				1,
				$count
			);
			if ( ! is_string( $result ) || 1 !== $count ) {
				return null;
			}
			$contents = $result;
		}
		return $contents;
	}

	/** Resolve wp-config.php the same way wp-load.php does (ABSPATH or one level up). */
	public static function locate_wp_config(): ?string {
		$candidate = ABSPATH . 'wp-config.php';
		if ( file_exists( $candidate ) ) {
			return $candidate;
		}
		$parent = dirname( ABSPATH ) . '/wp-config.php';
		if ( file_exists( $parent ) && ! file_exists( dirname( ABSPATH ) . '/wp-settings.php' ) ) {
			return $parent;
		}
		return null;
	}

	/** WP_Filesystem in the credential-free 'direct' mode, or null if unavailable. */
	private static function filesystem(): ?\WP_Filesystem_Base {
		if ( ! function_exists( 'WP_Filesystem' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		if ( 'direct' !== get_filesystem_method() ) {
			return null;
		}
		if ( ! WP_Filesystem() ) {
			return null;
		}
		global $wp_filesystem;
		return $wp_filesystem instanceof \WP_Filesystem_Base ? $wp_filesystem : null;
	}

	/**
	 * Can we rewrite wp-config.php in place? Requires the file located, the
	 * direct filesystem method, write permission, and all eight defines present.
	 */
	public static function salt_autofix_available(): bool {
		$path = self::locate_wp_config();
		if ( null === $path ) {
			return false;
		}
		$filesystem = self::filesystem();
		if ( null === $filesystem || ! $filesystem->is_writable( $path ) ) {
			return false;
		}
		$contents = $filesystem->get_contents( $path );
		return is_string( $contents ) && '' !== $contents && self::defines_present( $contents );
	}

	/**
	 * Write fresh salts into wp-config.php via an atomic temp-file swap. No
	 * backup file is left in the document root — a readable wp-config.php.bak
	 * would expose DB credentials. Clears the weak-salt notice on success.
	 *
	 * @return array{ok:bool,message:string}
	 */
	public static function apply_salt_fix(): array {
		$path = self::locate_wp_config();
		if ( null === $path ) {
			return [
				'ok'      => false,
				'message' => __( 'Could not locate wp-config.php.', 'magicauth' ),
			];
		}
		$filesystem = self::filesystem();
		if ( null === $filesystem || ! $filesystem->is_writable( $path ) ) {
			return [
				'ok'      => false,
				'message' => __( 'wp-config.php is not writable on this server. Use the manual copy-and-paste option instead.', 'magicauth' ),
			];
		}
		$original = $filesystem->get_contents( $path );
		if ( ! is_string( $original ) || '' === $original ) {
			return [
				'ok'      => false,
				'message' => __( 'Could not read wp-config.php.', 'magicauth' ),
			];
		}
		$updated = self::rewrite_salt_defines( $original, self::salt_values() );
		if ( null === $updated ) {
			return [
				'ok'      => false,
				'message' => __( 'wp-config.php does not contain the expected salt definitions. Use the manual copy-and-paste option instead.', 'magicauth' ),
			];
		}
		// Safety gate: result must still be PHP and must no longer look weak.
		if ( 0 !== strpos( ltrim( $updated ), '<?php' ) || self::config_has_weak_salts( $updated ) ) {
			return [
				'ok'      => false,
				'message' => __( 'The generated configuration failed a safety check, so nothing was written.', 'magicauth' ),
			];
		}
		$temp = dirname( $path ) . '/.magicauth-wpconfig-' . bin2hex( random_bytes( 8 ) ) . '.tmp';
		if ( ! $filesystem->put_contents( $temp, $updated, FS_CHMOD_FILE ) ) {
			return [
				'ok'      => false,
				'message' => __( 'Could not write the new configuration. No changes were made.', 'magicauth' ),
			];
		}
		if ( ! $filesystem->move( $temp, $path, true ) ) {
			$filesystem->delete( $temp );
			return [
				'ok'      => false,
				'message' => __( 'Could not replace wp-config.php. No changes were made.', 'magicauth' ),
			];
		}
		delete_transient( self::SALT_NOTICE_KEY );
		magicauth_debug_log( sprintf( 'salt fix: rewrote %s by user_id=%d', $path, (int) get_current_user_id() ) );
		return [
			'ok'      => true,
			'message' => __( 'Fresh salts written to wp-config.php. Everyone, including you, will be signed out — sign in again to continue.', 'magicauth' ),
		];
	}

	/**
	 * Re-read wp-config.php and clear the weak-salt notice if it is now clean.
	 * Backs the manual copy-and-paste path, which we cannot verify from runtime
	 * constants (those were loaded before the file was edited).
	 *
	 * @return array{ok:bool,message:string}
	 */
	public static function recheck_salts_from_file(): array {
		$path = self::locate_wp_config();
		if ( null === $path ) {
			return [
				'ok'      => false,
				'message' => __( 'Could not locate wp-config.php to verify.', 'magicauth' ),
			];
		}
		$filesystem = self::filesystem();
		$contents   = null !== $filesystem ? $filesystem->get_contents( $path ) : null;
		if ( ! is_string( $contents ) || '' === $contents ) {
			return [
				'ok'      => false,
				'message' => __( 'Could not read wp-config.php to verify.', 'magicauth' ),
			];
		}
		if ( self::config_has_weak_salts( $contents ) ) {
			return [
				'ok'      => false,
				'message' => __( 'Still detecting placeholder or empty salts. Make sure you replaced all eight lines and saved wp-config.php.', 'magicauth' ),
			];
		}
		delete_transient( self::SALT_NOTICE_KEY );
		return [
			'ok'      => true,
			'message' => __( 'Salts look good now. Branded login replacement is available again.', 'magicauth' ),
		];
	}
}
