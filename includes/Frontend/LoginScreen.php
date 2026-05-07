<?php
/**
 * Branded wp-login.php replacement.
 *
 * Recovery stack: (1) always-visible "Sign in with password" link,
 * (2) ?magicauth=off URL param, (3) MAGICAUTH_DISABLE constant.
 * Handler wrapped in try/catch (\Throwable) so fatals fall back to native form.
 *
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Frontend;

final class LoginScreen {

	private const ACTION = 'magicauth';

	public static function setup(): void {
		add_action( 'login_init', [ self::class, 'login_init' ], 1 );
		add_action( 'login_form_' . self::ACTION, [ self::class, 'render_login_action' ] );
		add_action( 'login_form_login', [ self::class, 'maybe_redirect_default' ], 10 );
		add_action( 'login_enqueue_scripts', [ self::class, 'enqueue' ] );

		// Brand lost/reset screens too — these hooks render our shell BEFORE
		// core's form HTML and exit, so native never paints.
		add_action( 'login_form_lostpassword', [ self::class, 'render_lostpassword_action' ] );
		add_action( 'login_form_retrievepassword', [ self::class, 'render_lostpassword_action' ] );
		add_action( 'login_form_rp', [ self::class, 'render_resetpass_action' ] );
		add_action( 'login_form_resetpass', [ self::class, 'render_resetpass_action' ] );

		add_filter( 'login_headerurl', [ self::class, 'filter_header_url' ] );
		add_filter( 'login_headertext', [ self::class, 'filter_header_text' ] );
		add_filter( 'login_body_class', [ self::class, 'filter_body_class' ] );
		// lostpassword_url intentionally NOT filtered — core's default lands
		// on our branded state-D via login_form_lostpassword above.
	}

	/**
	 * Earliest login hook. Honors `?magicauth=off` (escape hatch) and sets a
	 * 10-min cookie so a misclicked password attempt doesn't ping-pong back.
	 *
	 * The off-switch GET requires a nonce so an attacker can't downgrade a
	 * victim's login screen via a CSRF-style image tag. The recovery link in
	 * the rendered form is wp_nonce_url'd, so a logged-out browser can still
	 * reach the native form.
	 */
	public static function login_init(): void {
		// nosniff defense-in-depth (pentest H-1).
		header( 'X-Content-Type-Options: nosniff' );

		if ( isset( $_GET['magicauth'] ) && 'off' === $_GET['magicauth'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$nonce = isset( $_GET['_wpnonce'] ) ? sanitize_key( wp_unslash( (string) $_GET['_wpnonce'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( '' === $nonce || ! wp_verify_nonce( $nonce, 'magicauth_off' ) ) {
				return;
			}

			setcookie(
				'magicauth_off',
				'1',
				[
					'expires'  => time() + ( 10 * MINUTE_IN_SECONDS ),
					// Scoped to /wp-login.php; cookie only read in
					// should_replace_default() (pentest E-1).
					'path'     => '/wp-login.php',
					'domain'   => defined( 'COOKIE_DOMAIN' ) && COOKIE_DOMAIN ? COOKIE_DOMAIN : '',
					'secure'   => is_ssl(),
					'httponly' => true,
					'samesite' => 'Lax',
				]
			);
			return;
		}
	}

	/** Off-switch URL with nonce — for password-fallback / recovery links. */
	public static function off_switch_url(): string {
		return wp_nonce_url(
			add_query_arg( 'magicauth', 'off', wp_login_url() ),
			'magicauth_off'
		);
	}

	/** Redirect default login to ?action=magicauth when replace_default is on and visitor hasn't opted out. */
	public static function maybe_redirect_default(): void {
		if ( ! self::should_replace_default() ) {
			return;
		}
		if ( ! empty( $_GET['action'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}

		$args = [ 'action' => self::ACTION ];
		if ( isset( $_GET['redirect_to'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$args['redirect_to'] = esc_url_raw( wp_unslash( (string) $_GET['redirect_to'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		}

		wp_safe_redirect( add_query_arg( $args, wp_login_url() ) );
		exit;
	}

	/** Branded card on `?action=magicauth`. Fatal here falls through to core's form. */
	public static function render_login_action(): void {
		try {
			self::render_branded();
		} catch ( \Throwable $e ) {
			magicauth_debug_log( 'login_form_magicauth threw: ' . $e->getMessage() );
		}
	}

	private static function render_branded(): void {
		// Already-logged-in safety net: post-code-success redirect targets
		// wp-login.php?action=magicauth; without this, the form re-renders
		// instead of bouncing the user to admin.
		if ( is_user_logged_in() ) {
			$incoming = isset( $_GET['redirect_to'] ) ? wp_unslash( (string) $_GET['redirect_to'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$default  = function_exists( 'admin_url' ) ? admin_url() : home_url( '/' );
			$target   = '' !== $incoming ? wp_validate_redirect( $incoming, $default ) : $default;
			if ( '' === $target ) {
				$target = $default;
			}
			wp_safe_redirect( $target );
			exit;
		}

		$state_get  = isset( $_GET['magicauth_step'] ) ? sanitize_key( wp_unslash( (string) $_GET['magicauth_step'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$state      = self::resolve_state( $state_get );
		$session_id = isset( $_GET['magicauth_sid'] ) ? sanitize_key( wp_unslash( (string) $_GET['magicauth_sid'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		$context = self::build_context( $state, $session_id );

		self::render_shell( $context );

		// Feedback via Toast::maybe_render; magicauth.js handles animation,
		// dismissal, and history.replaceState so refresh doesn't re-trigger.
		Toast::maybe_render( $state );

		login_footer();
		exit;
	}

	/** Branded lost-password screen (state D). Falls through on \Throwable to native form. */
	public static function render_lostpassword_action(): void {
		try {
			if ( is_user_logged_in() ) {
				wp_safe_redirect( function_exists( 'admin_url' ) ? admin_url() : home_url( '/' ) );
				exit;
			}

			$context = self::build_context( 'd', '' );
			self::render_shell( $context );

			Toast::maybe_render( 'd' );

			login_footer();
			exit;
		} catch ( \Throwable $e ) {
			magicauth_debug_log( 'render_lostpassword_action threw: ' . $e->getMessage() );
		}
	}

	/**
	 * Branded reset-password screen (state E). Validates key+login on render
	 * so an expired/tampered key bounces to state D instead of silent reject.
	 */
	public static function render_resetpass_action(): void {
		try {
			if ( is_user_logged_in() ) {
				wp_safe_redirect( function_exists( 'admin_url' ) ? admin_url() : home_url( '/' ) );
				exit;
			}

			$key   = isset( $_GET['key'] ) ? trim( (string) wp_unslash( $_GET['key'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$login = isset( $_GET['login'] ) ? trim( (string) wp_unslash( $_GET['login'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

			$user = ( '' !== $key && '' !== $login ) ? check_password_reset_key( $key, $login ) : new \WP_Error( 'invalid_key' );

			// Bad key: bounce to state D with error toast.
			if ( $user instanceof \WP_Error || ! ( $user instanceof \WP_User ) ) {
				wp_safe_redirect(
					add_query_arg(
						[
							'action'                 => 'lostpassword',
							'magicauth_link_invalid' => '1',
						],
						wp_login_url()
					)
				);
				exit;
			}

			$context = self::build_context( 'e', '' );
			$context['reset_key']   = $key;
			$context['reset_login'] = $login;

			self::render_shell( $context );

			Toast::maybe_render( 'e' );

			login_footer();
			exit;
		} catch ( \Throwable $e ) {
			magicauth_debug_log( 'render_resetpass_action threw: ' . $e->getMessage() );
		}
	}

	/** Map magicauth_step query var to internal state code. */
	private static function resolve_state( string $step ): string {
		switch ( $step ) {
			case 'code':
				return 'b';
			case 'password':
				return 'c';
			case 'lostpassword':
				return 'd';
			default:
				return 'a';
		}
	}

	/**
	 * Build template context — centralized so all three render paths stay in sync.
	 *
	 * @return array<string,mixed>
	 */
	private static function build_context( string $state, string $session_id ): array {
		$current_login_url = self::current_login_url();
		$lostpassword_url  = add_query_arg( 'action', 'lostpassword', wp_login_url() );
		$password_url      = add_query_arg(
			[
				'action'         => self::ACTION,
				'magicauth_step' => 'password',
			],
			wp_login_url()
		);
		// "Use magic link instead" — drops step param to land on state A.
		$magic_link_url = add_query_arg( [ 'action' => self::ACTION ], wp_login_url() );

		return [
			'state'             => $state,
			'action_url'        => esc_url( admin_url( 'admin-post.php' ) ),
			'redirect_to'       => esc_url( $current_login_url ),
			'has_error'         => isset( $_GET['magicauth_error'] ), // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			'session_email'     => self::session_email( $session_id ),
			'session_id'        => $session_id,
			'logo_url'          => self::logo_url(),
			'brand_color'       => (string) magicauth_get_setting( 'brand_color', '#2271b1' ),
			'company_name'      => magicauth_get_company_name(),
			'site_name'         => get_bloginfo( 'name' ),
			'password_url'      => esc_url( $password_url ),
			'lostpassword_url'  => esc_url( $lostpassword_url ),
			'magic_link_url'    => esc_url( $magic_link_url ),
		];
	}

	/**
	 * Render shell + form. Caller must follow with toast + login_footer + exit.
	 *
	 * @param array<string,mixed> $context
	 */
	private static function render_shell( array $context ): void {
		login_header( __( 'Sign in', 'magicauth' ), '', null );

		$shell = MAGICAUTH_DIR . 'templates/login-shell.php';
		$form  = MAGICAUTH_DIR . 'templates/login-form.php';

		if ( is_readable( $shell ) ) {
			( static function ( string $tpl, array $args, string $form_path ): void {
				extract( $args, EXTR_SKIP ); // phpcs:ignore WordPress.PHP.DontExtract.extract_extract
				include $tpl;
			} )( $shell, $context + [ 'form_path' => $form ], $form );
		}
	}

	/** Read transient session email hint; prefer explicit $session_id over cookie. */
	private static function session_email( string $session_id = '' ): string {
		if ( '' === $session_id && ! empty( $_COOKIE['magicauth_session'] ) ) {
			$session_id = sanitize_key( wp_unslash( (string) $_COOKIE['magicauth_session'] ) );
		}
		if ( '' === $session_id ) {
			return '';
		}
		$payload = get_transient( 'magicauth_session_' . $session_id );
		if ( ! is_array( $payload ) || empty( $payload['email'] ) ) {
			return '';
		}
		return (string) $payload['email'];
	}

	private static function current_login_url(): string {
		return add_query_arg( 'action', self::ACTION, wp_login_url() );
	}

	private static function logo_url(): string {
		$id = (int) magicauth_get_setting( 'logo_attachment_id', 0 );
		if ( $id <= 0 ) {
			return '';
		}
		$src = wp_get_attachment_image_src( $id, 'medium' );
		return is_array( $src ) ? (string) $src[0] : '';
	}

	/** Enqueue assets on branded login screens. */
	public static function enqueue(): void {
		$action = isset( $_GET['action'] ) ? sanitize_key( wp_unslash( (string) $_GET['action'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		// Always emit brand-color custom prop so password-fallback link
		// respects branding even on the native form. Re-validate hex at output
		// — esc_attr is for HTML attrs, not CSS context.
		$brand_setting = (string) magicauth_get_setting( 'brand_color', '#2271b1' );
		$brand         = function_exists( 'sanitize_hex_color' ) ? (string) sanitize_hex_color( $brand_setting ) : '';
		if ( '' === $brand ) {
			$brand = '#2271b1';
		}
		$brand_txt = magicauth_yiq_text_color( $brand );
		printf(
			'<style id="magicauth-vars">:root{--magicauth-color-primary:%s;--magicauth-color-primary-text:%s;}</style>',
			$brand,
			$brand_txt
		);

		$branded_actions = [ self::ACTION, 'lostpassword', 'retrievepassword', 'rp', 'resetpass' ];
		if ( ! in_array( $action, $branded_actions, true ) ) {
			return;
		}

		wp_enqueue_style(
			'magicauth',
			MAGICAUTH_URL . 'assets/css/magicauth.css',
			[],
			MAGICAUTH_VERSION
		);
		wp_style_add_data( 'magicauth', 'rtl', 'replace' );

		wp_enqueue_script(
			'magicauth',
			MAGICAUTH_URL . 'assets/js/magicauth.js',
			[],
			MAGICAUTH_VERSION,
			[
				'in_footer' => true,
				'strategy'  => 'defer',
			]
		);
	}

	public static function filter_header_url( string $url ): string {
		unset( $url );
		return home_url( '/' );
	}

	public static function filter_header_text( string $text ): string {
		unset( $text );
		return magicauth_get_company_name();
	}

	public static function filter_body_class( array $classes ): array {
		$classes[] = 'magicauth-page';
		return $classes;
	}

	/** True when admin opted in AND visitor hasn't opted out. */
	private static function should_replace_default(): bool {
		if ( ! magicauth_get_setting( 'replace_default', false ) ) {
			return false;
		}
		if ( isset( $_GET['magicauth'] ) && 'off' === $_GET['magicauth'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return false;
		}
		if ( ! empty( $_COOKIE['magicauth_off'] ) ) {
			return false;
		}
		return true;
	}
}
