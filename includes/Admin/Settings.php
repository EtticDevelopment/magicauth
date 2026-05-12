<?php
/**
 * Settings page. Single option, single sanitize callback. Manual render
 * (bypasses do_settings_sections) so we control the design-system markup;
 * register_setting() still handles the option + sanitize wiring.
 *
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Admin;

defined( 'ABSPATH' ) || exit;

use MagicAuth\Auth\Throttle;
use MagicAuth\Auth\TokenManager;
use MagicAuth\Email\Mailer;
use MagicAuth\Installer;

final class Settings {

	private const OPTION_GROUP = 'magicauth';
	private const OPTION_NAME  = 'magicauth_settings';
	private const PAGE_SLUG    = 'magicauth';

	private const REDIRECT_OPTIONS = [ 'auto', 'home', 'admin' ];

	private const MAX_LINK_USES_PRESETS = [ 1, 2, 3, 5, 10 ];

	private const FONT_STACK_KEYS = [ 'system', 'sans-modern', 'serif', 'mono', 'rounded' ];

	private const COLOR_MODE_KEYS = [ 'light', 'dark', 'auto' ];

	// Curated dark-mode surface — must match the value emitted by magicauth.css
	// for body.magicauth-mode-dark / .magicauth-mode-auto. Used by the
	// brand-color contrast check below.
	private const DARK_SURFACE_HEX = '#181c22';

	// Keyed by extension regex (wp_check_filetype_and_ext format); membership checks hit values.
	private const LOGO_MIMES = [
		'png'      => 'image/png',
		'jpg|jpeg' => 'image/jpeg',
		'webp'     => 'image/webp',
		'svg'      => 'image/svg+xml',
	];

	// Background images: raster only. SVG explicitly excluded — larger attack
	// surface than logos and no rendering benefit at full-page scale.
	private const BACKGROUND_MIMES = [
		'png'      => 'image/png',
		'jpg|jpeg' => 'image/jpeg',
		'webp'     => 'image/webp',
	];

	public static function setup(): void {
		add_action( 'admin_init', [ self::class, 'register' ] );
		add_action( 'admin_menu', [ self::class, 'menu' ] );
		add_action( 'admin_enqueue_scripts', [ self::class, 'enqueue' ] );
		add_action( 'admin_post_magicauth_send_test_email', [ self::class, 'handle_test_send' ] );
		add_action( 'wp_ajax_magicauth_admin_revoke_all_tokens', [ self::class, 'ajax_revoke_all_tokens' ] );
		add_action( 'wp_ajax_magicauth_admin_reset_throttle', [ self::class, 'ajax_reset_throttle' ] );
		add_action( 'current_screen', [ self::class, 'suppress_foreign_notices' ] );
		add_filter( 'plugin_action_links_' . plugin_basename( MAGICAUTH_FILE ), [ self::class, 'plugin_action_links' ] );
	}

	/**
	 * Scrub third-party admin notices on our settings screen — they wreck the
	 * dark hero layout. Scoped strictly to settings_page_magicauth. WP's own
	 * "Settings saved" pipeline runs through options-head.php and is unaffected.
	 * Salt warning is also rendered inline in Branding, so no info is lost.
	 */
	public static function suppress_foreign_notices(): void {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || 'settings_page_' . self::PAGE_SLUG !== $screen->id ) {
			return;
		}
		remove_all_actions( 'admin_notices' );
		remove_all_actions( 'all_admin_notices' );
		remove_all_actions( 'user_admin_notices' );
		remove_all_actions( 'network_admin_notices' );
	}

	/**
	 * Prepend "Settings" link on the plugin row.
	 *
	 * @param array<int|string,string> $links
	 * @return array<int|string,string>
	 */
	public static function plugin_action_links( array $links ): array {
		$settings_link = sprintf(
			'<a href="%s">%s</a>',
			esc_url( admin_url( 'options-general.php?page=' . self::PAGE_SLUG ) ),
			esc_html__( 'Settings', 'magicauth' )
		);
		array_unshift( $links, $settings_link );
		return $links;
	}

	// Single option + sanitize. No add_settings_section/field — rendering is manual.
	public static function register(): void {
		register_setting(
			self::OPTION_GROUP,
			self::OPTION_NAME,
			[
				'type'              => 'array',
				'show_in_rest'      => false,
				'sanitize_callback' => [ self::class, 'sanitize' ],
				'default'           => Installer::default_settings(),
			]
		);
	}

	public static function menu(): void {
		add_options_page(
			__( 'MagicAuth', 'magicauth' ),
			__( 'MagicAuth', 'magicauth' ),
			'manage_options',
			self::PAGE_SLUG,
			[ self::class, 'render_page' ]
		);
	}

	public static function enqueue( string $hook ): void {
		if ( 'settings_page_' . self::PAGE_SLUG !== $hook ) {
			return;
		}

		wp_enqueue_media();
		wp_enqueue_style( 'magicauth-admin', MAGICAUTH_URL . 'assets/css/magicauth-admin.css', [], MAGICAUTH_VERSION );
		wp_enqueue_script(
			'magicauth-admin',
			MAGICAUTH_URL . 'assets/js/magicauth-admin.js',
			[],
			MAGICAUTH_VERSION,
			true
		);
	}

	public static function render_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$weak_salts = Installer::has_weak_salts();
		?>
		<div class="wrap magicauth-admin">
			<form method="post" action="options.php" class="magicauth-form">
				<?php settings_fields( self::OPTION_GROUP ); ?>

				<div class="magicauth-topbar__bar" role="banner">
					<div class="magicauth-topbar__brand">
						<svg class="magicauth-topbar__mark" viewBox="0 0 26 26" fill="none" xmlns="http://www.w3.org/2000/svg" aria-label="MagicAuth">
							<rect width="26" height="26" rx="6" fill="#0F5CFA"/>
							<path d="M8 8V18H18V16.2H9.7V13.85H16.1V12.05H9.7V9.8H18V8H8Z" fill="white"/>
						</svg>
						<span class="magicauth-topbar__name"><?php esc_html_e( 'MagicAuth', 'magicauth' ); ?></span>
						<span class="magicauth-topbar__version">v<?php echo esc_html( MAGICAUTH_VERSION ); ?></span>
					</div>

					<div class="magicauth-topbar__right">
						<div class="magicauth-topbar__dirty is-clean" aria-live="polite" data-dirty>
							<span class="magicauth-topbar__dirty-dot" aria-hidden="true"></span>
							<span><span class="magicauth-topbar__dirty-num" data-dirty-num>0</span><span data-dirty-label></span></span>
						</div>

						<div class="magicauth-topbar__actions">
							<button type="button" class="magicauth-btn magicauth-btn--ghost-dark" data-discard disabled><?php esc_html_e( 'Discard', 'magicauth' ); ?></button>
							<button type="submit" class="magicauth-btn magicauth-btn--primary" data-save name="submit" disabled><?php esc_html_e( 'Save changes', 'magicauth' ); ?></button>
						</div>
					</div>
				</div>

				<div class="magicauth-topbar__head">
					<h1><?php esc_html_e( 'MagicAuth', 'magicauth' ); ?></h1>
					<p><?php esc_html_e( 'Passwordless sign-in via magic link or 6-character code. Configure how it looks, how it behaves, and how it recovers from edge cases. All on one page.', 'magicauth' ); ?></p>
				</div>

				<div class="magicauth-stack">
					<?php self::render_section_general(); ?>
					<?php self::render_section_branding( $weak_salts ); ?>
					<?php self::render_section_appearance(); ?>
					<?php self::render_section_agency_credit(); ?>
					<?php self::render_section_security(); ?>
					<?php self::render_section_diagnostics(); ?>
				</div>
			</form>
			<?php Footer::render(); ?>
		</div>
		<?php
	}

	private static function render_section_general(): void {
		?>
		<details class="magicauth-block" open>
			<summary class="magicauth-block__head">
				<h2><?php esc_html_e( 'General', 'magicauth' ); ?></h2>
				<p><?php esc_html_e( 'How long links live and where users land afterwards.', 'magicauth' ); ?></p>
			</summary>
			<div class="magicauth-card">
				<?php self::field_ttl_minutes(); ?>
				<?php self::field_max_link_uses(); ?>
				<?php self::field_redirect_to_default(); ?>
			</div>
		</details>
		<?php
	}

	private static function render_section_branding( bool $weak_salts ): void {
		?>
		<details class="magicauth-block" open>
			<summary class="magicauth-block__head">
				<h2><?php esc_html_e( 'Branding', 'magicauth' ); ?></h2>
				<p><?php esc_html_e( 'How the sign-in card looks. Settings render on the branded login screen and in transactional emails.', 'magicauth' ); ?></p>
			</summary>
			<div class="magicauth-card">
				<?php self::field_replace_default( $weak_salts ); ?>
				<?php self::field_company_name(); ?>
				<?php self::field_logo(); ?>
				<?php self::field_brand_color(); ?>
				<?php self::field_link_color(); ?>
			</div>
		</details>
		<?php
	}

	private static function render_section_appearance(): void {
		?>
		<details class="magicauth-block" open>
			<summary class="magicauth-block__head">
				<h2><?php esc_html_e( 'Appearance', 'magicauth' ); ?></h2>
				<p><?php esc_html_e( 'Layout and theme of the sign-in card. Color mode, page background, sizing, and typography.', 'magicauth' ); ?></p>
			</summary>
			<div class="magicauth-card">
				<?php self::field_color_mode(); ?>
				<?php self::field_page_color(); ?>
				<?php self::field_background_image(); ?>
				<?php self::field_card_radius(); ?>
				<?php self::field_card_width(); ?>
				<?php self::field_font_stack(); ?>
			</div>
		</details>
		<?php
	}

	private static function render_section_agency_credit(): void {
		?>
		<details class="magicauth-block" open>
			<summary class="magicauth-block__head">
				<h2><?php esc_html_e( 'Agency credit', 'magicauth' ); ?></h2>
				<p><?php esc_html_e( 'Optional "Built by [Brand]" line below the sign-in card. Renders only when name, URL, and favicon are all filled.', 'magicauth' ); ?></p>
			</summary>
			<div class="magicauth-card">
				<?php self::field_agency_credit_name(); ?>
				<?php self::field_agency_credit_url(); ?>
				<?php self::field_agency_credit_icon(); ?>
				<?php self::field_agency_credit_label(); ?>
			</div>
		</details>
		<?php
	}

	private static function render_section_security(): void {
		?>
		<details class="magicauth-block" open>
			<summary class="magicauth-block__head">
				<h2><?php esc_html_e( 'Security &amp; throttling', 'magicauth' ); ?></h2>
				<p><?php esc_html_e( 'Recovery layers and rate-limit caps. The "Sign in with password" link is the unconditional safety net. Disable it only after site-wide password auth is already off.', 'magicauth' ); ?></p>
			</summary>
			<div class="magicauth-card">
				<?php self::field_allow_password_login(); ?>
				<?php self::field_throttle(); ?>
			</div>
		</details>
		<?php
	}

	private static function render_section_diagnostics(): void {
		$test_nonce     = wp_create_nonce( 'magicauth_send_test_email' );
		$test_url       = admin_url( 'admin-post.php?action=magicauth_send_test_email&_wpnonce=' . $test_nonce );
		$recovery_nonce = wp_create_nonce( 'magicauth-admin-recovery' );
		$ajaxurl        = admin_url( 'admin-ajax.php' );
		?>
		<details class="magicauth-block" open>
			<summary class="magicauth-block__head">
				<h2><?php esc_html_e( 'Diagnostics &amp; recovery', 'magicauth' ); ?></h2>
				<p><?php esc_html_e( 'One-shot tools for debugging and unsticking the plugin. Destructive actions ask for confirmation.', 'magicauth' ); ?></p>
			</summary>
			<div class="magicauth-card magicauth-recovery"
				data-ajaxurl="<?php echo esc_url( $ajaxurl ); ?>"
				data-nonce="<?php echo esc_attr( $recovery_nonce ); ?>">

				<div class="magicauth-action-row">
					<div class="magicauth-action-row__main">
						<h3><?php esc_html_e( 'Send test email', 'magicauth' ); ?></h3>
						<p><?php esc_html_e( 'One-shot diagnostic. No tokens are issued. Forces the default brand color to verify rendering.', 'magicauth' ); ?></p>
					</div>
					<a href="<?php echo esc_url( $test_url ); ?>" class="magicauth-btn magicauth-btn--ghost magicauth-btn--sm">
						<?php esc_html_e( 'Send to my account', 'magicauth' ); ?>
					</a>
				</div>

				<div class="magicauth-action-row">
					<div class="magicauth-action-row__main">
						<h3><?php esc_html_e( 'Revoke all magic-links and codes', 'magicauth' ); ?></h3>
						<p><?php esc_html_e( 'Marks every unconsumed token consumed site-wide. Already-active sessions are not signed out.', 'magicauth' ); ?></p>
					</div>
					<button type="button" class="magicauth-btn magicauth-btn--ghost magicauth-btn--sm" data-magicauth-admin-recovery="revoke_all_tokens">
						<?php esc_html_e( 'Revoke now', 'magicauth' ); ?>
					</button>
				</div>

				<div class="magicauth-action-row">
					<div class="magicauth-action-row__main">
						<h3><?php esc_html_e( 'Reset throttle counters', 'magicauth' ); ?></h3>
						<p><?php esc_html_e( 'Deletes every magicauth_throttle_* transient. Object-cache safe.', 'magicauth' ); ?></p>
					</div>
					<button type="button" class="magicauth-btn magicauth-btn--ghost magicauth-btn--sm" data-magicauth-admin-recovery="reset_throttle">
						<?php esc_html_e( 'Reset now', 'magicauth' ); ?>
					</button>
				</div>
			</div>
		</details>
		<?php
	}

	/**
	 * Sanitize callback — security-critical, mutates the stored array atomically.
	 *
	 * @param mixed $input
	 * @return array<string,mixed>
	 */
	public static function sanitize( $input ): array {
		$current = get_option( self::OPTION_NAME, Installer::default_settings() );
		if ( ! is_array( $current ) ) {
			$current = Installer::default_settings();
		}
		if ( ! is_array( $input ) ) {
			return $current;
		}

		$out = $current;

		if ( isset( $input['ttl_minutes'] ) ) {
			$out['ttl_minutes'] = max( 1, min( 30, absint( $input['ttl_minutes'] ) ) );
		}

		if ( isset( $input['max_link_uses'] ) ) {
			$out['max_link_uses'] = max( 1, min( 10, absint( $input['max_link_uses'] ) ) );
		}

		if ( isset( $input['throttle'] ) && is_array( $input['throttle'] ) ) {
			$throttle = is_array( $current['throttle'] ?? null ) ? $current['throttle'] : [];
			// Cooldown 0–600s. Replaces the old per-email hard cap, which was a
			// DoS primitive (any IP could lock out any victim email).
			if ( isset( $input['throttle']['per_email_cooldown_sec'] ) ) {
				$throttle['per_email_cooldown_sec'] = max( 0, min( 600, absint( $input['throttle']['per_email_cooldown_sec'] ) ) );
			}
			foreach ( [ 'per_ip_window_hours', 'per_ip_max', 'per_ip_code_window_hours', 'per_ip_code_max' ] as $key ) {
				if ( isset( $input['throttle'][ $key ] ) ) {
					$throttle[ $key ] = max( 1, absint( $input['throttle'][ $key ] ) );
				}
			}
			$out['throttle'] = $throttle;
		}

		// replace_default gated by salt strength.
		$wants_replace = ! empty( $input['replace_default'] );
		if ( $wants_replace && Installer::has_weak_salts() ) {
			add_settings_error(
				self::OPTION_NAME,
				'magicauth_weak_salts',
				__( 'Replace-default sign-in is unavailable while wp-config.php contains placeholder salts. Generate fresh salts and re-save.', 'magicauth' ),
				'error'
			);
			$out['replace_default'] = false;
		} else {
			$out['replace_default'] = (bool) $wants_replace;
		}

		if ( isset( $input['company_name'] ) ) {
			$out['company_name'] = self::sanitize_company_name( (string) $input['company_name'] );
		}

		if ( isset( $input['logo_attachment_id'] ) ) {
			$out['logo_attachment_id'] = self::sanitize_logo( absint( $input['logo_attachment_id'] ) );
		}

		if ( isset( $input['agency_credit_name'] ) ) {
			$out['agency_credit_name'] = self::sanitize_company_name( (string) $input['agency_credit_name'] );
		}

		if ( isset( $input['agency_credit_url'] ) ) {
			$out['agency_credit_url'] = self::sanitize_agency_url( (string) $input['agency_credit_url'] );
		}

		if ( isset( $input['agency_credit_icon_id'] ) ) {
			$out['agency_credit_icon_id'] = self::sanitize_logo( absint( $input['agency_credit_icon_id'] ) );
		}

		if ( isset( $input['agency_credit_label'] ) ) {
			$out['agency_credit_label'] = self::sanitize_credit_label( (string) $input['agency_credit_label'] );
		}

		if ( isset( $input['brand_color'] ) ) {
			$sanitized            = sanitize_hex_color( (string) $input['brand_color'] );
			$out['brand_color']   = $sanitized ? $sanitized : '#2271b1';
		}

		// is_scalar guards prevent (string) cast on array/object from emitting
		// "Array" notices on probe traffic. Mirrors throttle's is_array guard.
		if ( isset( $input['page_color'] ) && is_scalar( $input['page_color'] ) ) {
			$sanitized         = sanitize_hex_color( (string) $input['page_color'] );
			$out['page_color'] = $sanitized ? $sanitized : '#eeeeee';
		}

		if ( isset( $input['card_radius'] ) && is_scalar( $input['card_radius'] ) ) {
			$out['card_radius'] = max( 0, min( 32, absint( $input['card_radius'] ) ) );
		}

		if ( isset( $input['card_width'] ) && is_scalar( $input['card_width'] ) ) {
			$out['card_width'] = max( 360, min( 640, absint( $input['card_width'] ) ) );
		}

		if ( isset( $input['font_stack'] ) && is_scalar( $input['font_stack'] ) ) {
			$candidate         = sanitize_key( (string) $input['font_stack'] );
			$out['font_stack'] = in_array( $candidate, self::FONT_STACK_KEYS, true ) ? $candidate : 'system';
		}

		if ( isset( $input['background_attachment_id'] ) ) {
			$out['background_attachment_id'] = self::sanitize_background( absint( $input['background_attachment_id'] ) );
		}

		if ( isset( $input['link_color'] ) && is_scalar( $input['link_color'] ) ) {
			$out['link_color'] = self::sanitize_link_color(
				(string) $input['link_color'],
				(string) ( $current['link_color'] ?? '' )
			);
		}

		if ( isset( $input['color_mode'] ) && is_scalar( $input['color_mode'] ) ) {
			$candidate         = sanitize_key( (string) $input['color_mode'] );
			$out['color_mode'] = in_array( $candidate, self::COLOR_MODE_KEYS, true ) ? $candidate : 'light';
		}

		// Brand color × dark surface. Runs AFTER brand_color and color_mode
		// are settled. SC 1.4.11 wants ≥3:1 for non-text UI; the focus ring
		// on a dark surface is the at-risk element. Warn only — admins keep
		// brand color sovereignty.
		if ( in_array( ( $out['color_mode'] ?? 'light' ), [ 'dark', 'auto' ], true ) ) {
			$brand_for_check = (string) ( $out['brand_color'] ?? '' );
			if ( '' !== $brand_for_check ) {
				$ratio = magicauth_contrast_ratio( $brand_for_check, self::DARK_SURFACE_HEX );
				if ( $ratio < 3.0 ) {
					add_settings_error(
						self::OPTION_NAME,
						'magicauth_brand_dark_contrast',
						sprintf(
							/* translators: %s: contrast ratio */
							__( 'Brand color note: contrast against the dark-mode surface is %s — below the 3:1 minimum for UI elements. Focus indicators may be hard to see for visitors using dark mode.', 'magicauth' ),
							number_format( $ratio, 2 )
						),
						'warning'
					);
				}
			}
		}

		if ( isset( $input['redirect_to_default'] ) ) {
			$candidate                  = (string) $input['redirect_to_default'];
			$out['redirect_to_default'] = in_array( $candidate, self::REDIRECT_OPTIONS, true ) ? $candidate : 'auto';
		}

		$out['allow_password_login'] = ! empty( $input['allow_password_login'] );

		return $out;
	}

	// Cap 60 chars. Subjects clip past ~70 and our format eats ~10 for "XXX-XXX is your -code".
	private static function sanitize_company_name( string $value ): string {
		$clean = sanitize_text_field( $value );
		if ( function_exists( 'mb_substr' ) ) {
			return mb_substr( $clean, 0, 60 );
		}
		return substr( $clean, 0, 60 );
	}

	private static function sanitize_credit_label( string $value ): string {
		$clean = sanitize_text_field( $value );
		if ( function_exists( 'mb_substr' ) ) {
			return mb_substr( $clean, 0, 40 );
		}
		return substr( $clean, 0, 40 );
	}

	// Empty = inherit from brand. Graded against the fixed #ffffff card surface:
	// <2.5:1 rejects (restore previous), 2.5–4.5 saves with warning, AA+ silent.
	private static function sanitize_link_color( string $raw, string $current ): string {
		$raw = trim( $raw );
		if ( '' === $raw ) {
			return '';
		}

		$sanitized = sanitize_hex_color( $raw );
		if ( ! $sanitized ) {
			add_settings_error(
				self::OPTION_NAME,
				'magicauth_link_color_invalid',
				__( 'Link color: invalid hex value, change ignored.', 'magicauth' ),
				'error'
			);
			return $current;
		}

		$ratio   = magicauth_contrast_ratio( $sanitized, '#ffffff' );
		$verdict = magicauth_contrast_evaluate( $ratio, 'normal' );

		if ( 'fail' === $verdict ) {
			add_settings_error(
				self::OPTION_NAME,
				'magicauth_link_color_unreadable',
				sprintf(
					/* translators: %s: contrast ratio */
					__( 'Link color: contrast ratio %s against the card surface is below the 2.5:1 readability floor. Change ignored.', 'magicauth' ),
					number_format( $ratio, 2 )
				),
				'error'
			);
			return $current;
		}

		if ( 'warn' === $verdict ) {
			add_settings_error(
				self::OPTION_NAME,
				'magicauth_link_color_low_contrast',
				sprintf(
					/* translators: %s: contrast ratio */
					__( 'Link color saved. Contrast against the card surface is %s — below the WCAG AA target of 4.5:1 for body text. Visitors may struggle to read the link.', 'magicauth' ),
					number_format( $ratio, 2 )
				),
				'warning'
			);
		}

		return $sanitized;
	}

	// Allowlist http(s) only — esc_url_raw alone permits mailto:/javascript:/etc.
	private static function sanitize_agency_url( string $value ): string {
		$value = trim( $value );
		if ( '' === $value ) {
			return '';
		}
		$clean = esc_url_raw( $value, [ 'http', 'https' ] );
		return is_string( $clean ) ? $clean : '';
	}

	// Validate logo attachment; returns 0 on failure.
	private static function sanitize_logo( int $attachment_id ): int {
		if ( $attachment_id <= 0 ) {
			return 0;
		}
		if ( ! wp_attachment_is_image( $attachment_id ) ) {
			add_settings_error( self::OPTION_NAME, 'magicauth_logo_not_image', __( 'Logo: selected attachment is not an image.', 'magicauth' ), 'error' );
			return 0;
		}
		$path = get_attached_file( $attachment_id );
		if ( ! is_string( $path ) || ! is_readable( $path ) ) {
			return 0;
		}

		$is_svg = 'svg' === strtolower( (string) pathinfo( $path, PATHINFO_EXTENSION ) );

		// SVG: skip wp_check_filetype_and_ext (libmagic returns text/xml and
		// false-rejects), but scan content for active payloads. Direct loads
		// of the asset URL would otherwise execute inline scripts.
		if ( $is_svg ) {
			$svg = (string) file_get_contents( $path );
			if ( '' === $svg || preg_match( '/<\s*script\b|on[a-z]+\s*=|javascript\s*:|<\s*foreignObject\b/i', $svg ) ) {
				add_settings_error( self::OPTION_NAME, 'magicauth_logo_unsafe_svg', __( 'Logo: SVG contains active content (script / event handlers / javascript:). Re-export without scripting.', 'magicauth' ), 'error' );
				return 0;
			}
			return $attachment_id;
		}

		$check = wp_check_filetype_and_ext( $path, basename( $path ), self::LOGO_MIMES );
		if ( empty( $check['type'] ) || ! in_array( $check['type'], self::LOGO_MIMES, true ) ) {
			add_settings_error( self::OPTION_NAME, 'magicauth_logo_bad_ext', __( 'Logo: only PNG, JPG, WebP, or SVG are allowed.', 'magicauth' ), 'error' );
			return 0;
		}

		if ( function_exists( 'finfo_open' ) ) {
			$finfo = finfo_open( FILEINFO_MIME_TYPE );
			if ( $finfo ) {
				// finfo_close() is deprecated as of PHP 8.5 (objects auto-free)
				// and a no-op on earlier versions once $finfo falls out of scope.
				$mime = finfo_file( $finfo, $path );
				if ( ! is_string( $mime ) || ! in_array( $mime, self::LOGO_MIMES, true ) ) {
					add_settings_error( self::OPTION_NAME, 'magicauth_logo_bad_mime', __( 'Logo: file content does not match a supported image format.', 'magicauth' ), 'error' );
					return 0;
				}
			}
		}

		return $attachment_id;
	}

	// Validate background attachment. Raster only; SVG forbidden. Soft-warns
	// above 1 MB but never blocks — admin knows their hosting better than we do.
	private static function sanitize_background( int $attachment_id ): int {
		if ( $attachment_id <= 0 ) {
			return 0;
		}
		if ( ! wp_attachment_is_image( $attachment_id ) ) {
			add_settings_error(
				self::OPTION_NAME,
				'magicauth_bg_not_image',
				__( 'Background: selected attachment is not an image.', 'magicauth' ),
				'error'
			);
			return 0;
		}
		$path = get_attached_file( $attachment_id );
		if ( ! is_string( $path ) || ! is_readable( $path ) ) {
			return 0;
		}

		$check = wp_check_filetype_and_ext( $path, basename( $path ), self::BACKGROUND_MIMES );
		if ( empty( $check['type'] ) || ! in_array( $check['type'], self::BACKGROUND_MIMES, true ) ) {
			add_settings_error(
				self::OPTION_NAME,
				'magicauth_bg_bad_ext',
				__( 'Background: only PNG, JPG, or WebP are allowed.', 'magicauth' ),
				'error'
			);
			return 0;
		}

		if ( function_exists( 'finfo_open' ) ) {
			$finfo = finfo_open( FILEINFO_MIME_TYPE );
			if ( $finfo ) {
				// finfo_close() is deprecated as of PHP 8.5 (objects auto-free)
				// and a no-op on earlier versions once $finfo falls out of scope.
				$mime = finfo_file( $finfo, $path );
				if ( ! is_string( $mime ) || ! in_array( $mime, self::BACKGROUND_MIMES, true ) ) {
					add_settings_error(
						self::OPTION_NAME,
						'magicauth_bg_bad_mime',
						__( 'Background: file content does not match a supported image format.', 'magicauth' ),
						'error'
					);
					return 0;
				}
			}
		}

		$size = (int) @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( $size > 1024 * 1024 ) {
			add_settings_error(
				self::OPTION_NAME,
				'magicauth_bg_large',
				sprintf(
					/* translators: %s: file size in MB */
					__( 'Background image saved. File is %s MB — consider compressing for faster page load.', 'magicauth' ),
					number_format( $size / ( 1024 * 1024 ), 1 )
				),
				'warning'
			);
		}

		return $attachment_id;
	}

	public static function field_ttl_minutes(): void {
		$value = (int) magicauth_get_setting( 'ttl_minutes', 10 );
		$name  = sprintf( '%s[ttl_minutes]', self::OPTION_NAME );
		?>
		<div class="magicauth-row">
			<div class="magicauth-row__main">
				<span class="magicauth-row__label"><?php esc_html_e( 'Link &amp; code lifetime', 'magicauth' ); ?></span>
				<p class="magicauth-row__help"><?php esc_html_e( 'Both the magic link and the typeable code share one expiry. Range 1–30 minutes.', 'magicauth' ); ?></p>
			</div>
			<div class="magicauth-row__control">
				<input type="number" class="magicauth-input magicauth-input--num" name="<?php echo esc_attr( $name ); ?>" value="<?php echo esc_attr( (string) $value ); ?>" min="1" max="30">
				<span style="font-size:13px;color:var(--tx-muted);"><?php esc_html_e( 'minutes', 'magicauth' ); ?></span>
			</div>
		</div>
		<?php
	}

	public static function field_max_link_uses(): void {
		$value = (int) magicauth_get_setting( 'max_link_uses', 2 );
		$name  = sprintf( '%s[max_link_uses]', self::OPTION_NAME );
		?>
		<div class="magicauth-row">
			<div class="magicauth-row__main">
				<span class="magicauth-row__label"><?php esc_html_e( 'Max link uses', 'magicauth' ); ?></span>
				<p class="magicauth-row__help"><?php esc_html_e( '2 absorbs URL-scanner prefetch plus the user\'s click. Set to 1 for strict single-use.', 'magicauth' ); ?></p>
			</div>
			<div class="magicauth-row__control">
				<div class="magicauth-seg" role="radiogroup" aria-label="<?php esc_attr_e( 'Max link uses', 'magicauth' ); ?>">
					<?php foreach ( self::MAX_LINK_USES_PRESETS as $opt ) : ?>
						<label class="magicauth-seg__btn">
							<input class="magicauth-seg__input" type="radio" name="<?php echo esc_attr( $name ); ?>" value="<?php echo esc_attr( (string) $opt ); ?>" <?php checked( $value, $opt ); ?>>
							<?php echo esc_html( (string) $opt ); ?>
						</label>
					<?php endforeach; ?>
				</div>
			</div>
		</div>
		<?php
	}

	public static function field_redirect_to_default(): void {
		self::render_select_field(
			'redirect_to_default',
			(string) magicauth_get_setting( 'redirect_to_default', 'auto' ),
			__( 'Default redirect after sign-in', 'magicauth' ),
			__( 'Where users land when no specific destination was requested.', 'magicauth' ),
			[
				'auto'  => __( 'Auto (admin or home, by capability)', 'magicauth' ),
				'home'  => __( 'Site home', 'magicauth' ),
				'admin' => __( 'Admin dashboard', 'magicauth' ),
			]
		);
	}

	public static function field_replace_default( bool $weak_salts = false ): void {
		$value = (bool) magicauth_get_setting( 'replace_default', false );
		$name  = sprintf( '%s[replace_default]', self::OPTION_NAME );
		?>
		<div class="magicauth-row">
			<div class="magicauth-row__main">
				<span class="magicauth-row__label">
					<?php esc_html_e( 'Replace WordPress login screen', 'magicauth' ); ?>
					<?php if ( $weak_salts ) : ?>
						<button class="magicauth-tooltip-trigger" type="button" aria-label="<?php esc_attr_e( 'Why is this disabled?', 'magicauth' ); ?>">?<span class="magicauth-tooltip" role="tooltip"><strong><?php esc_html_e( 'Disabled: weak salts', 'magicauth' ); ?></strong><?php esc_html_e( 'Replace-default needs strong values in', 'magicauth' ); ?> <code style="background:rgba(255,255,255,0.06);color:#FFB070;padding:1px 5px;border-radius:3px;font-family:var(--ff-mono);font-size:11.5px;">wp-config.php</code>. <a href="https://api.wordpress.org/secret-key/1.1/salt/" target="_blank" rel="noopener"><?php esc_html_e( 'Generate fresh salts →', 'magicauth' ); ?></a></span></button>
					<?php endif; ?>
				</span>
				<p class="magicauth-row__help"><?php esc_html_e( 'Intercepts wp-login.php and serves the branded MagicAuth screen. The native form stays available at ?magicauth=off as a recovery path.', 'magicauth' ); ?></p>
			</div>
			<div class="magicauth-row__control">
				<input type="hidden" name="<?php echo esc_attr( $name ); ?>" value="0">
				<label class="magicauth-toggle">
					<input class="magicauth-toggle__input" type="checkbox" name="<?php echo esc_attr( $name ); ?>" value="1" <?php checked( $value ); ?> <?php disabled( $weak_salts ); ?>>
					<span class="magicauth-toggle__thumb"></span>
				</label>
			</div>
		</div>
		<?php
	}

	public static function field_company_name(): void {
		$value = (string) magicauth_get_setting( 'company_name', '' );
		$name  = sprintf( '%s[company_name]', self::OPTION_NAME );
		?>
		<div class="magicauth-row">
			<div class="magicauth-row__main">
				<span class="magicauth-row__label"><?php esc_html_e( 'Company name', 'magicauth' ); ?></span>
				<p class="magicauth-row__help"><?php esc_html_e( 'Your short business name. No taglines, slogans, or separators.', 'magicauth' ); ?></p>
			</div>
			<div class="magicauth-row__control magicauth-row__control--stack">
				<input type="text" class="magicauth-input magicauth-input--md" name="<?php echo esc_attr( $name ); ?>" value="<?php echo esc_attr( $value ); ?>" maxlength="60" data-counter>
			</div>
		</div>
		<?php
	}

	public static function field_logo(): void {
		self::render_media_picker_field(
			'logo_attachment_id',
			(int) magicauth_get_setting( 'logo_attachment_id', 0 ),
			__( 'Logo', 'magicauth' ),
			__( 'PNG, JPG, or WebP. Existing SVG attachments may also be selected. Capped at 48px height on the sign-in card.', 'magicauth' )
		);
	}

	public static function field_brand_color(): void {
		$value    = (string) magicauth_get_setting( 'brand_color', '#2271b1' );
		$name     = sprintf( '%s[brand_color]', self::OPTION_NAME );
		$contrast = magicauth_yiq_text_color( $value );
		?>
		<div class="magicauth-row">
			<div class="magicauth-row__main">
				<span class="magicauth-row__label"><?php esc_html_e( 'Brand color', 'magicauth' ); ?></span>
				<p class="magicauth-row__help">
					<?php esc_html_e( 'Auto-derives readable button text via YIQ luminance. Current contrast:', 'magicauth' ); ?>
					<code><?php echo esc_html( $contrast ); ?></code>
				</p>
			</div>
			<div class="magicauth-row__control magicauth-row__control--stack">
				<div class="magicauth-color">
					<input type="color" value="<?php echo esc_attr( $value ); ?>" aria-label="<?php esc_attr_e( 'Color picker', 'magicauth' ); ?>">
					<input type="text" class="magicauth-input magicauth-input--mono" name="<?php echo esc_attr( $name ); ?>" value="<?php echo esc_attr( $value ); ?>" maxlength="7" data-validate-hex>
				</div>
			</div>
		</div>
		<?php
	}

	public static function field_page_color(): void {
		$value = (string) magicauth_get_setting( 'page_color', '#eeeeee' );
		$name  = sprintf( '%s[page_color]', self::OPTION_NAME );
		?>
		<div class="magicauth-row">
			<div class="magicauth-row__main">
				<span class="magicauth-row__label"><?php esc_html_e( 'Page background', 'magicauth' ); ?></span>
				<p class="magicauth-row__help"><?php esc_html_e( 'Color behind the sign-in card. Choose a value distinct from white so the card stays visible.', 'magicauth' ); ?></p>
			</div>
			<div class="magicauth-row__control magicauth-row__control--stack">
				<div class="magicauth-color">
					<input type="color" value="<?php echo esc_attr( $value ); ?>" aria-label="<?php esc_attr_e( 'Color picker', 'magicauth' ); ?>">
					<input type="text" class="magicauth-input magicauth-input--mono" name="<?php echo esc_attr( $name ); ?>" value="<?php echo esc_attr( $value ); ?>" maxlength="7" data-validate-hex>
				</div>
			</div>
		</div>
		<?php
	}

	public static function field_card_radius(): void {
		$value = (int) magicauth_get_setting( 'card_radius', 6 );
		$name  = sprintf( '%s[card_radius]', self::OPTION_NAME );
		?>
		<div class="magicauth-row">
			<div class="magicauth-row__main">
				<span class="magicauth-row__label"><?php esc_html_e( 'Card corner radius', 'magicauth' ); ?></span>
				<p class="magicauth-row__help"><?php esc_html_e( 'Sign-in card corner softness, in pixels. 0 is sharp; 32 is heavily rounded.', 'magicauth' ); ?></p>
			</div>
			<div class="magicauth-row__control">
				<input type="number" class="magicauth-input magicauth-input--num" name="<?php echo esc_attr( $name ); ?>" value="<?php echo esc_attr( (string) $value ); ?>" min="0" max="32" step="1">
				<span style="font-size:13px;color:var(--tx-muted);"><?php esc_html_e( 'px', 'magicauth' ); ?></span>
			</div>
		</div>
		<?php
	}

	public static function field_card_width(): void {
		$value = (int) magicauth_get_setting( 'card_width', 480 );
		$name  = sprintf( '%s[card_width]', self::OPTION_NAME );
		?>
		<div class="magicauth-row">
			<div class="magicauth-row__main">
				<span class="magicauth-row__label"><?php esc_html_e( 'Card max width', 'magicauth' ); ?></span>
				<p class="magicauth-row__help"><?php esc_html_e( 'Card max width on desktop, in pixels. Shrinks below this on narrow viewports.', 'magicauth' ); ?></p>
			</div>
			<div class="magicauth-row__control">
				<input type="number" class="magicauth-input magicauth-input--num" name="<?php echo esc_attr( $name ); ?>" value="<?php echo esc_attr( (string) $value ); ?>" min="360" max="640" step="20">
				<span style="font-size:13px;color:var(--tx-muted);"><?php esc_html_e( 'px', 'magicauth' ); ?></span>
			</div>
		</div>
		<?php
	}

	public static function field_font_stack(): void {
		self::render_select_field(
			'font_stack',
			(string) magicauth_get_setting( 'font_stack', 'system' ),
			__( 'Font family', 'magicauth' ),
			__( 'Font used on the sign-in card. Each option is a stack of system-installed fonts — nothing is loaded from the network.', 'magicauth' ),
			[
				'system'      => __( 'System default', 'magicauth' ),
				'sans-modern' => __( 'Modern sans (Inter)', 'magicauth' ),
				'serif'       => __( 'Serif (Georgia)', 'magicauth' ),
				'mono'        => __( 'Monospace', 'magicauth' ),
				'rounded'     => __( 'Rounded', 'magicauth' ),
			]
		);
	}

	public static function field_link_color(): void {
		$value         = (string) magicauth_get_setting( 'link_color', '' );
		$brand_raw     = (string) magicauth_get_setting( 'brand_color', '#2271b1' );
		$brand_default = (string) ( sanitize_hex_color( $brand_raw ) ?: '#2271b1' );
		$name          = sprintf( '%s[link_color]', self::OPTION_NAME );
		?>
		<div class="magicauth-row">
			<div class="magicauth-row__main">
				<span class="magicauth-row__label"><?php esc_html_e( 'Link color', 'magicauth' ); ?></span>
				<p class="magicauth-row__help"><?php esc_html_e( 'Color of text links on the sign-in card. Leave blank to follow brand color. Validated against the card surface for readability.', 'magicauth' ); ?></p>
			</div>
			<div class="magicauth-row__control magicauth-row__control--stack">
				<div class="magicauth-color" data-magicauth-color-follows="brand_color">
					<input type="color" value="<?php echo esc_attr( '' !== $value ? $value : $brand_default ); ?>" aria-label="<?php esc_attr_e( 'Color picker', 'magicauth' ); ?>">
					<input type="text" class="magicauth-input magicauth-input--mono" name="<?php echo esc_attr( $name ); ?>" value="<?php echo esc_attr( $value ); ?>" maxlength="7" placeholder="<?php esc_attr_e( '(brand color)', 'magicauth' ); ?>" data-validate-hex>
				</div>
			</div>
		</div>
		<?php
	}

	public static function field_color_mode(): void {
		self::render_select_field(
			'color_mode',
			(string) magicauth_get_setting( 'color_mode', 'light' ),
			__( 'Color mode', 'magicauth' ),
			__( "Light, dark, or follow the visitor's system preference. Page background color applies in light mode; dark mode uses a curated dark palette.", 'magicauth' ),
			[
				'light' => __( 'Light', 'magicauth' ),
				'dark'  => __( 'Dark', 'magicauth' ),
				'auto'  => __( "Auto (follow visitor's browser preference)", 'magicauth' ),
			]
		);
	}

	public static function field_background_image(): void {
		self::render_media_picker_field(
			'background_attachment_id',
			(int) magicauth_get_setting( 'background_attachment_id', 0 ),
			__( 'Page background image', 'magicauth' ),
			__( 'Optional. PNG, JPG, or WebP. Rendered as a cover-fitted, centered background behind the sign-in card. Page background color shows through transparent areas or if the image fails to load.', 'magicauth' )
		);
	}

	public static function field_agency_credit_name(): void {
		$value = (string) magicauth_get_setting( 'agency_credit_name', '' );
		$name  = sprintf( '%s[agency_credit_name]', self::OPTION_NAME );
		?>
		<div class="magicauth-row">
			<div class="magicauth-row__main">
				<span class="magicauth-row__label"><?php esc_html_e( 'Brand name', 'magicauth' ); ?></span>
				<p class="magicauth-row__help"><?php esc_html_e( 'Shown bold in the credit line.', 'magicauth' ); ?></p>
			</div>
			<div class="magicauth-row__control magicauth-row__control--stack">
				<input type="text" class="magicauth-input magicauth-input--md" name="<?php echo esc_attr( $name ); ?>" value="<?php echo esc_attr( $value ); ?>" maxlength="60" placeholder="<?php esc_attr_e( 'Acme Studio', 'magicauth' ); ?>" data-counter>
			</div>
		</div>
		<?php
	}

	public static function field_agency_credit_url(): void {
		$value = (string) magicauth_get_setting( 'agency_credit_url', '' );
		$name  = sprintf( '%s[agency_credit_url]', self::OPTION_NAME );
		?>
		<div class="magicauth-row">
			<div class="magicauth-row__main">
				<span class="magicauth-row__label"><?php esc_html_e( 'Brand URL', 'magicauth' ); ?></span>
				<p class="magicauth-row__help"><?php esc_html_e( 'Opens in a new tab. Must start with http:// or https://.', 'magicauth' ); ?></p>
			</div>
			<div class="magicauth-row__control">
				<input type="url" class="magicauth-input magicauth-input--md" name="<?php echo esc_attr( $name ); ?>" value="<?php echo esc_attr( $value ); ?>" inputmode="url" placeholder="https://example.com">
			</div>
		</div>
		<?php
	}

	public static function field_agency_credit_icon(): void {
		self::render_media_picker_field(
			'agency_credit_icon_id',
			(int) magicauth_get_setting( 'agency_credit_icon_id', 0 ),
			__( 'Brand favicon', 'magicauth' ),
			__( 'Square 32×32 or larger. PNG, JPG, WebP, or SVG.', 'magicauth' )
		);
	}

	public static function field_agency_credit_label(): void {
		$value = (string) magicauth_get_setting( 'agency_credit_label', '' );
		$name  = sprintf( '%s[agency_credit_label]', self::OPTION_NAME );
		?>
		<div class="magicauth-row">
			<div class="magicauth-row__main">
				<span class="magicauth-row__label"><?php esc_html_e( 'Credit label', 'magicauth' ); ?></span>
				<p class="magicauth-row__help"><?php esc_html_e( 'Text shown before the brand name. Leave blank for the default ("Built by").', 'magicauth' ); ?></p>
			</div>
			<div class="magicauth-row__control magicauth-row__control--stack">
				<input type="text" class="magicauth-input magicauth-input--md" name="<?php echo esc_attr( $name ); ?>" value="<?php echo esc_attr( $value ); ?>" maxlength="40" placeholder="<?php esc_attr_e( 'Built by', 'magicauth' ); ?>" data-counter>
			</div>
		</div>
		<?php
	}

	public static function field_allow_password_login(): void {
		$value = (bool) magicauth_get_setting( 'allow_password_login', true );
		$name  = sprintf( '%s[allow_password_login]', self::OPTION_NAME );
		?>
		<div class="magicauth-row">
			<div class="magicauth-row__main">
				<span class="magicauth-row__label"><?php esc_html_e( '"Sign in with password" link', 'magicauth' ); ?></span>
				<p class="magicauth-row__help"><?php esc_html_e( 'Always-visible recovery link on every form. Only disable this if you have already disabled WordPress password authentication site-wide.', 'magicauth' ); ?></p>
			</div>
			<div class="magicauth-row__control">
				<input type="hidden" name="<?php echo esc_attr( $name ); ?>" value="0">
				<label class="magicauth-toggle">
					<input class="magicauth-toggle__input" type="checkbox" name="<?php echo esc_attr( $name ); ?>" value="1" <?php checked( $value ); ?>>
					<span class="magicauth-toggle__thumb"></span>
				</label>
			</div>
		</div>
		<?php
	}

	public static function field_throttle(): void {
		$throttle = (array) magicauth_get_setting( 'throttle', [] );
		$cooldown = (int) ( $throttle['per_email_cooldown_sec'] ?? 60 );
		$rows     = [
			'per_ip_window_hours'      => __( 'Per-IP window (hours)', 'magicauth' ),
			'per_ip_max'               => __( 'Per-IP max requests', 'magicauth' ),
			'per_ip_code_window_hours' => __( 'Per-IP code window (hours)', 'magicauth' ),
			'per_ip_code_max'          => __( 'Per-IP max code attempts', 'magicauth' ),
		];
		?>
		<div class="magicauth-row">
			<div class="magicauth-row__main">
				<span class="magicauth-row__label"><?php esc_html_e( 'Per-email cooldown', 'magicauth' ); ?></span>
				<p class="magicauth-row__help"><?php esc_html_e( 'Seconds between consecutive link requests for the same email. 0 disables. Default 60. Replaced the per-email hard cap in v1.3.7. That cap was a DoS primitive any IP could weaponize against any victim email.', 'magicauth' ); ?></p>
			</div>
			<div class="magicauth-row__control">
				<input type="number" class="magicauth-input magicauth-input--num" name="<?php echo esc_attr( self::OPTION_NAME ); ?>[throttle][per_email_cooldown_sec]" value="<?php echo esc_attr( (string) $cooldown ); ?>" min="0" max="600">
				<span style="font-size:13px;color:var(--tx-muted);"><?php esc_html_e( 'seconds', 'magicauth' ); ?></span>
			</div>
		</div>
		<?php foreach ( $rows as $key => $label ) :
			$value = (int) ( $throttle[ $key ] ?? 0 );
			?>
			<div class="magicauth-row">
				<div class="magicauth-row__main">
					<span class="magicauth-row__label"><?php echo esc_html( $label ); ?></span>
				</div>
				<div class="magicauth-row__control">
					<input type="number" class="magicauth-input magicauth-input--num" name="<?php echo esc_attr( self::OPTION_NAME ); ?>[throttle][<?php echo esc_attr( $key ); ?>]" value="<?php echo esc_attr( (string) $value ); ?>" min="1">
				</div>
			</div>
		<?php endforeach;
	}

	/**
	 * Shared <select> field markup. Same row scaffold as the v1.0 select fields;
	 * keeps three field_* methods at ~4 LOC each instead of 25.
	 *
	 * @param array<string,string> $options Map of stored value => translated label.
	 */
	private static function render_select_field( string $option_key, string $value, string $label, string $help, array $options ): void {
		$name = sprintf( '%s[%s]', self::OPTION_NAME, $option_key );
		?>
		<div class="magicauth-row">
			<div class="magicauth-row__main">
				<span class="magicauth-row__label"><?php echo esc_html( $label ); ?></span>
				<p class="magicauth-row__help"><?php echo esc_html( $help ); ?></p>
			</div>
			<div class="magicauth-row__control">
				<div class="magicauth-select">
					<select name="<?php echo esc_attr( $name ); ?>">
						<?php foreach ( $options as $opt_value => $opt_label ) : ?>
							<option value="<?php echo esc_attr( (string) $opt_value ); ?>" <?php selected( $value, (string) $opt_value ); ?>>
								<?php echo esc_html( $opt_label ); ?>
							</option>
						<?php endforeach; ?>
					</select>
				</div>
			</div>
		</div>
		<?php
	}

	// Shared media-picker markup. JS binds wp.media to any [data-magicauth-media-picker].
	private static function render_media_picker_field( string $option_key, int $attachment_id, string $label, string $description ): void {
		$src  = $attachment_id ? wp_get_attachment_image_src( $attachment_id, 'medium' ) : false;
		$url  = is_array( $src ) ? (string) $src[0] : '';
		$name = sprintf( '%s[%s]', self::OPTION_NAME, $option_key );
		?>
		<div class="magicauth-row">
			<div class="magicauth-row__main">
				<span class="magicauth-row__label"><?php echo esc_html( $label ); ?></span>
				<p class="magicauth-row__help"><?php echo esc_html( $description ); ?></p>
			</div>
			<div class="magicauth-row__control">
				<div class="magicauth-media" data-magicauth-media-picker="<?php echo esc_attr( $option_key ); ?>">
					<input type="hidden" name="<?php echo esc_attr( $name ); ?>" value="<?php echo esc_attr( (string) $attachment_id ); ?>" data-magicauth-media-id data-dirty-track>
					<div class="magicauth-media__preview <?php echo $url ? 'magicauth-media__preview--filled' : ''; ?>" data-magicauth-media-preview>
						<?php if ( $url ) : ?>
							<img src="<?php echo esc_url( $url ); ?>" alt="">
						<?php endif; ?>
					</div>
					<div class="magicauth-media__controls">
						<button type="button" class="magicauth-btn magicauth-btn--ghost magicauth-btn--sm" data-magicauth-media-pick><?php esc_html_e( 'Replace', 'magicauth' ); ?></button>
						<button type="button" class="magicauth-btn magicauth-btn--text" data-magicauth-media-clear style="<?php echo $attachment_id ? '' : 'display:none;'; ?>"><?php esc_html_e( 'Remove', 'magicauth' ); ?></button>
					</div>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * "Send test email" — diagnostic only. Result flagged in URL for JS toast;
	 * we skip add_settings_error/transient because options-head.php would
	 * auto-render settings errors alongside the toast.
	 */
	public static function handle_test_send(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'magicauth' ), 403 );
		}
		check_admin_referer( 'magicauth_send_test_email' );

		$user_id = get_current_user_id();
		$ok      = Mailer::send_test( $user_id );

		$redirect = add_query_arg(
			[
				'page'           => self::PAGE_SLUG,
				'magicauth-test' => $ok ? 'sent' : 'fail',
			],
			admin_url( 'options-general.php' )
		);

		wp_safe_redirect( $redirect );
		exit;
	}

	// AJAX: revoke every outstanding token site-wide ("Revoke now" button).
	public static function ajax_revoke_all_tokens(): void {
		check_ajax_referer( 'magicauth-admin-recovery' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( [ 'message' => __( 'You are not allowed to do this.', 'magicauth' ) ], 403 );
		}

		$count = TokenManager::invalidate_all_outstanding();

		magicauth_debug_log( sprintf( 'admin recovery: revoke_all_tokens by user_id=%d count=%d', (int) get_current_user_id(), $count ) );

		wp_send_json_success(
			[
				'count'   => $count,
				'message' => sprintf(
					/* translators: %d: number of tokens revoked */
					_n( '%d outstanding token revoked.', '%d outstanding tokens revoked.', $count, 'magicauth' ),
					$count
				),
			]
		);
	}

	// AJAX: clear every magicauth throttle counter ("Reset now" button).
	public static function ajax_reset_throttle(): void {
		check_ajax_referer( 'magicauth-admin-recovery' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( [ 'message' => __( 'You are not allowed to do this.', 'magicauth' ) ], 403 );
		}

		$count = Throttle::admin_flush_all();

		magicauth_debug_log( sprintf( 'admin recovery: reset_throttle by user_id=%d count=%d', (int) get_current_user_id(), $count ) );

		wp_send_json_success(
			[
				'count'   => $count,
				'message' => sprintf(
					/* translators: %d: number of throttle counters cleared */
					_n( '%d throttle counter cleared.', '%d throttle counters cleared.', $count, 'magicauth' ),
					$count
				),
			]
		);
	}
}
