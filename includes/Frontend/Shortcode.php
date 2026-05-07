<?php
/**
 * [magicauth_login] shortcode. Render adapter only — POST handlers live in Auth\Controller.
 *
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Frontend;

defined( 'ABSPATH' ) || exit;

final class Shortcode {

	private const SHORTCODE = 'magicauth_login';

	public static function setup(): void {
		add_shortcode( self::SHORTCODE, [ self::class, 'render' ] );
		add_action( 'wp_enqueue_scripts', [ self::class, 'enqueue' ] );
		add_action( 'wp', [ self::class, 'maybe_emit_nocache' ] );
	}

	/**
	 * State-B renders interpolate the user's email — page caches must not
	 * persist that response. DONOTCACHEPAGE covers W3TC/WP-Rocket/Batcache;
	 * Cache-Control + Vary cover Cloudflare/Varnish.
	 */
	public static function maybe_emit_nocache(): void {
		if ( is_admin() ) {
			return;
		}
		global $post;
		$force = (bool) apply_filters( 'magicauth_force_frontend_assets', false );
		$has   = $post instanceof \WP_Post && has_shortcode( $post->post_content, self::SHORTCODE );
		if ( ! $force && ! $has ) {
			return;
		}

		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			define( 'DONOTCACHEPAGE', true );
		}

		if ( ! headers_sent() ) {
			nocache_headers();
			header( 'Vary: Cookie', false );
		}
	}

	/** Only loads on pages containing the shortcode (or via magicauth_force_frontend_assets filter). */
	public static function enqueue(): void {
		global $post;

		$force = (bool) apply_filters( 'magicauth_force_frontend_assets', false );
		$has   = $post instanceof \WP_Post && has_shortcode( $post->post_content, self::SHORTCODE );
		if ( ! $force && ! $has ) {
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

	/**
	 * @param array<string,mixed> $atts
	 */
	public static function render( $atts = [] ): string {
		unset( $atts );

		// Already logged in: render notice, not form. Avoids accidental session swaps.
		if ( is_user_logged_in() ) {
			return self::render_logged_in_notice();
		}

		$state      = self::current_state();
		$session_id = isset( $_GET['magicauth_sid'] ) ? sanitize_key( wp_unslash( (string) $_GET['magicauth_sid'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		ob_start();
		$template = MAGICAUTH_DIR . 'templates/login-form.php';
		if ( is_readable( $template ) ) {
			$current_url = self::current_url();
			$context     = [
				'state'            => $state,
				'action_url'       => esc_url( admin_url( 'admin-post.php' ) ),
				'redirect_to'      => esc_url( $current_url ),
				'has_error'        => isset( $_GET['magicauth_error'] ), // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				'session_email'    => self::session_email_hint( $session_id ),
				'session_id'       => $session_id,
				'logo_url'         => '',
				// State-transition links toggle magicauth_step on the current URL — keeps visitor on same page.
				'password_url'     => esc_url( add_query_arg( 'magicauth_step', 'password', remove_query_arg( [ 'magicauth_step', 'magicauth_error', 'magicauth_sent', 'magicauth_link_invalid', 'magicauth_sid' ], $current_url ) ) ),
				'lostpassword_url' => esc_url( wp_lostpassword_url( $current_url ) ),
				'magic_link_url'   => esc_url( remove_query_arg( [ 'magicauth_step', 'magicauth_error', 'magicauth_sent', 'magicauth_link_invalid', 'magicauth_sid' ], $current_url ) ),
			];
			( static function ( string $tpl, array $args ): void {
				extract( $args, EXTR_SKIP ); // phpcs:ignore WordPress.PHP.DontExtract.extract_extract
				include $tpl;
			} )( $template, $context );
		}

		// All toasts flow through the shared dispatcher. magicauth_link_invalid normally hits
		// LoginScreen, but routing here too is free and stays consistent if filters swap verify targets.
		Toast::maybe_render( $state );

		self::render_agency_credit();

		$inner = (string) ob_get_clean();

		// Wrap in shell instead of touching <body> — avoid bleeding classes onto theme elements.
		return sprintf( '<div class="magicauth-shell">%s</div>', $inner );
	}

	/**
	 * 'a' (email), 'b' (code), 'c' (password). States D/E (lost/reset password) are
	 * wp-login.php-only — shortcode's "Forgot password?" routes to wp_lostpassword_url().
	 */
	private static function current_state(): string {
		$step = isset( $_GET['magicauth_step'] ) ? sanitize_key( wp_unslash( (string) $_GET['magicauth_step'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		switch ( $step ) {
			case 'code':
				return 'b';
			case 'password':
				return 'c';
			default:
				return 'a';
		}
	}

	/** State B uses this to pre-render "we sent a code to you@example.com". Same-session only. */
	private static function session_email_hint( string $session_id = '' ): string {
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

	/** Used as the form's hidden redirect_to so Controller returns to the same page. */
	private static function current_url(): string {
		$host = isset( $_SERVER['HTTP_HOST'] ) ? (string) $_SERVER['HTTP_HOST'] : '';
		$req  = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '/';
		$scheme = is_ssl() ? 'https://' : 'http://';
		return $host ? $scheme . $host . $req : home_url( '/' );
	}

	private static function render_logged_in_notice(): string {
		$user = wp_get_current_user();
		ob_start();
		?>
		<div class="magicauth-notice magicauth-notice--info">
			<p>
				<?php
				echo esc_html(
					sprintf(
						/* translators: %s display name */
						__( "You're already signed in as %s.", 'magicauth' ),
						$user->display_name
					)
				);
				?>
			</p>
			<p>
				<a class="magicauth-link" href="<?php echo esc_url( wp_logout_url( self::current_url() ) ); ?>">
					<?php esc_html_e( 'Sign out', 'magicauth' ); ?>
				</a>
			</p>
		</div>
		<?php
		self::render_agency_credit();

		return sprintf( '<div class="magicauth-shell">%s</div>', (string) ob_get_clean() );
	}

	/** Emit "Built by [Brand]" box when configured. */
	private static function render_agency_credit(): void {
		$credit = magicauth_get_agency_credit();
		if ( null === $credit ) {
			return;
		}
		$tpl = MAGICAUTH_DIR . 'templates/agency-credit.php';
		if ( is_readable( $tpl ) ) {
			include $tpl;
		}
	}
}
