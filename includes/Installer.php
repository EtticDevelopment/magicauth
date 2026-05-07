<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth;

final class Installer {

	private const SALT_NOTICE_KEY = 'magicauth_salt_notice';

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
		$placeholder_markers = [
			'put your unique phrase here',
		];

		$keys = [ 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY' ];
		foreach ( $keys as $constant ) {
			$value = defined( $constant ) ? constant( $constant ) : '';
			if ( ! is_string( $value ) || '' === $value ) {
				set_transient( self::SALT_NOTICE_KEY, 1, WEEK_IN_SECONDS );
				return;
			}
			foreach ( $placeholder_markers as $marker ) {
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
		?>
		<div class="notice notice-error">
			<p>
				<strong><?php esc_html_e( 'MagicAuth: weak WordPress salts detected.', 'magicauth' ); ?></strong>
				<?php
				echo wp_kses(
					sprintf(
						/* translators: %s: salt generator URL */
						__( 'Generate fresh salts at <a href="%s" target="_blank" rel="noopener">api.wordpress.org/secret-key</a> and paste them into <code>wp-config.php</code>. Branded login replacement is disabled until this is resolved.', 'magicauth' ),
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
}
