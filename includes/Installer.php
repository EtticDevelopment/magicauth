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

	/** Canonical documentation page that walks an admin through fixing weak salts. */
	public const DOCS_SALTS_URL = 'https://docs.ettic.nl/docs/magicauth/weak-salts';

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
	 * provided by the environment, or fixed outside the wizard, clears the notice
	 * on its own without a false "still weak" nag. Writes only on a state change.
	 */
	public static function check_salts(): void {
		$weak    = self::runtime_salts_weak();
		$flagged = (bool) get_transient( self::SALT_NOTICE_KEY );
		if ( $weak && ! $flagged ) {
			set_transient( self::SALT_NOTICE_KEY, 1, WEEK_IN_SECONDS );
		} elseif ( ! $weak && $flagged ) {
			delete_transient( self::SALT_NOTICE_KEY );
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
		<div class="notice notice-warning">
			<p>
				<strong><?php esc_html_e( 'MagicAuth: weak WordPress salts detected.', 'magicauth' ); ?></strong>
				<?php esc_html_e( 'Your security keys still hold placeholder or empty values, so token and session secrets are not unique to this site. Your magic links stay safe (each carries its own random secret), but fixing this is recommended — especially before turning on the branded login replacement.', 'magicauth' ); ?>
			</p>
			<p>
				<a href="<?php echo esc_url( $fix_url ); ?>" class="button button-primary"><?php esc_html_e( 'Fix it for me', 'magicauth' ); ?></a>
				<?php
				echo ' ';
				echo wp_kses(
					sprintf(
						/* translators: 1: documentation guide URL, 2: salt generator URL */
						__( 'Read the <a href="%1$s" target="_blank" rel="noopener">step-by-step guide</a>, or generate fresh salts at <a href="%2$s" target="_blank" rel="noopener">api.wordpress.org/secret-key</a> and paste them into <code>wp-config.php</code>.', 'magicauth' ),
						esc_url( self::DOCS_SALTS_URL ),
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

	/** One strong salt value: 48 random bytes, base64-encoded (64 chars, quote-safe). */
	public static function generate_salt_value(): string {
		return base64_encode( random_bytes( 48 ) );
	}

	/**
	 * The eight fresh salt values for the copy-and-paste block. Generated locally
	 * with random_bytes and never sent over the network, so the secrets the admin
	 * is about to paste are never transmitted, observed, or tampered with in
	 * transit. Local generation is strictly safer than fetching a remote endpoint
	 * for a value we only ever display for the admin to paste themselves.
	 *
	 * @return array<string,string>
	 */
	private static function salt_values(): array {
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

	/**
	 * Regex capturing a single define() with its quote style and value (group 3).
	 * Anchored to a line start (multiline) so commented-out lines such as
	 * `// define( 'AUTH_KEY', ... );` are skipped — PHP honours the first active
	 * define, and matching a comment instead would corrupt detection/rewrite.
	 */
	private static function define_pattern( string $name ): string {
		return '/^[ \t]*define\(\s*([\'"])' . preg_quote( $name, '/' ) . '\1\s*,\s*([\'"])(.*?)\2\s*\)\s*;/m';
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
	 * Verify salts after a manual edit and clear the notice if they are now strong.
	 * The running AJAX request has already reloaded wp-config.php, so the runtime
	 * constants are authoritative and cover environment- or include-provided salts
	 * that never appear as a literal define(). The located wp-config.php text is a
	 * secondary signal only.
	 *
	 * @return array{ok:bool,message:string}
	 */
	public static function recheck_salts_from_file(): array {
		$ok_message = __( 'Salts look good now. You can enable the branded login replacement whenever you like.', 'magicauth' );

		// Authoritative: runtime constants reflect the current file plus any
		// environment/included salts. If they are strong, the salts are fixed.
		if ( ! self::runtime_salts_weak() ) {
			delete_transient( self::SALT_NOTICE_KEY );
			return [
				'ok'      => true,
				'message' => $ok_message,
			];
		}

		// Secondary: scan the located wp-config.php directly, in case this request
		// did not pick up the edit.
		$path = self::locate_wp_config();
		if ( null !== $path ) {
			$filesystem = self::filesystem();
			$contents   = null !== $filesystem ? $filesystem->get_contents( $path ) : null;
			if ( is_string( $contents ) && '' !== $contents && ! self::config_has_weak_salts( $contents ) ) {
				delete_transient( self::SALT_NOTICE_KEY );
				return [
					'ok'      => true,
					'message' => $ok_message,
				];
			}
		}

		return [
			'ok'      => false,
			'message' => __( 'Still detecting placeholder or empty salts. Make sure you replaced all eight lines and saved wp-config.php.', 'magicauth' ),
		];
	}
}
