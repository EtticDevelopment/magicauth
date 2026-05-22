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
