<?php
/**
 * Login-side assets, markup and theme contract (SPEC 8.1, 8.5, 8.9, 8.10,
 * 8.11, build step 12): the module-on counterpart of T-OFF-1 (state A differs
 * from the module-off render only by the autocomplete token and the sign-in
 * block; states B to E and the logged-in shortcode not at all), the enqueue
 * rules (state A, logged out, shortcode page or forced assets, the
 * wp-login.php screen), the inline config, the style filters, the
 * magicauth_passkey_signin_markup filter and the two theme helpers.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Frontend\LoginScreen;
use MagicAuth\Frontend\Shortcode;
use MagicAuth\Passkeys\Assets;
use MagicAuth\Passkeys\Module;
use MagicAuth\Tests\Support\Ceremony;
use MagicAuth\Tests\Support\Golden;
use MagicAuth\Tests\Support\Normalise;
use PHPUnit\Framework\TestCase;

final class LoginAssetsTest extends TestCase {

	private const LOGIN_URIS = [
		'a' => '/wp-login.php?action=magicauth',
		'b' => '/wp-login.php?action=magicauth&magicauth_step=code&magicauth_sid=0123456789abcdef0123456789abcdef',
		'c' => '/wp-login.php?action=magicauth&magicauth_step=password',
		'd' => '/wp-login.php?action=lostpassword',
		'e' => '/wp-login.php?action=rp&key=resetkey0123456789&login=student',
	];

	protected function setUp(): void {
		Ceremony::site();
		Ceremony::enable_module();
		$_SERVER['HTTP_HOST'] = 'academy.example.com';
	}

	protected function tearDown(): void {
		global $post;
		$post = null;
		$_GET = [];
		unset( $_SERVER['HTTP_HOST'], $_SERVER['REQUEST_URI'] );
		magicauth_test_reset_state();
	}

	private static function module( bool $on ): void {
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => $on ] );
		Module::reset_for_tests();
	}

	private static function render_state( string $state ): string {
		$_SERVER['REQUEST_URI'] = self::LOGIN_URIS[ $state ];
		$_GET                   = [];
		parse_str( (string) wp_parse_url( self::LOGIN_URIS[ $state ], PHP_URL_QUERY ), $_GET );
		$context = Golden::login_context( $state );
		ob_start();
		( static function ( string $tpl, array $args ): void {
			extract( $args, EXTR_SKIP ); // phpcs:ignore WordPress.PHP.DontExtract.extract_extract
			include $tpl;
		} )( MAGICAUTH_DIR . 'templates/login-form.php', $context );
		return (string) ob_get_clean();
	}

	private static function dom( string $html ): \DOMXPath {
		$dom = new \DOMDocument();
		libxml_use_internal_errors( true );
		$dom->loadHTML( '<!DOCTYPE html><html><body>' . $html . '</body></html>' );
		libxml_clear_errors();
		return new \DOMXPath( $dom );
	}

	private static function node( \DOMXPath $xpath, string $query ): \DOMElement {
		$nodes = $xpath->query( $query );
		if ( false === $nodes || 1 !== $nodes->length || ! $nodes->item( 0 ) instanceof \DOMElement ) {
			throw new \RuntimeException( 'expected one node for ' . $query );
		}
		return $nodes->item( 0 );
	}

	/** @return array<int,string> */
	private static function scripts(): array {
		return array_keys( $GLOBALS['magicauth_test_state']['enqueued_scripts'] ?? [] );
	}

	/** @return array<int,string> */
	private static function styles(): array {
		return array_keys( $GLOBALS['magicauth_test_state']['enqueued_styles'] ?? [] );
	}

	private static function reset_enqueues(): void {
		global $magicauth_test_state;
		unset( $magicauth_test_state['enqueued_scripts'], $magicauth_test_state['enqueued_styles'], $magicauth_test_state['inline_scripts'] );
	}

	/* --------------------------------------------- module-on render (T-OFF-1) */

	public function test_state_a_differs_only_by_the_autocomplete_token_and_the_block(): void {
		self::module( false );
		$off = self::render_state( 'a' );
		self::module( true );
		$on = self::render_state( 'a' );

		$this->assertSame( 1, substr_count( $on, Assets::signin_markup() ), 'the default block, once' );
		$this->assertSame( 1, substr_count( $on, 'autocomplete="username webauthn"' ) );
		$back = str_replace( [ Assets::signin_markup(), 'autocomplete="username webauthn"' ], [ '', 'autocomplete="email"' ], $on );
		$this->assertSame( Normalise::html( $off ), Normalise::html( $back ) );
		$this->assertStringNotContainsString( 'passkey', strtolower( $off ) );
	}

	public function test_states_b_to_e_are_unchanged_with_the_module_on(): void {
		foreach ( [ 'b', 'c', 'd', 'e' ] as $state ) {
			self::module( false );
			$off = Normalise::html( self::render_state( $state ) );
			self::module( true );
			$this->assertSame( $off, Normalise::html( self::render_state( $state ) ), $state );
		}
	}

	public function test_logged_in_shortcode_is_unchanged_with_the_module_on(): void {
		$_SERVER['REQUEST_URI'] = '/login/';
		Ceremony::user( 7 );
		magicauth_test_login_as( 7 );
		self::module( false );
		$off = Shortcode::render( [] );
		self::module( true );
		$this->assertSame( $off, Shortcode::render( [] ) );
	}

	public function test_signin_block_structure(): void {
		$xpath = self::dom( self::render_state( 'a' ) );
		$form  = self::node( $xpath, '//form[contains(@class,"magicauth-form")]' );

		$root = self::node( $xpath, '//*[@data-magicauth-passkey-root]' );
		$this->assertTrue( $root->hasAttribute( 'hidden' ), 'hidden until G1' );
		$this->assertTrue( $form->contains( $root ), 'inside the form' );

		$button = self::node( $xpath, '//button[@data-magicauth-passkey-signin]' );
		$this->assertSame( 'button', $button->getAttribute( 'type' ), 'never submits the email form' );
		$this->assertTrue( $button->hasAttribute( 'hidden' ) );
		$this->assertStringContainsString( 'magicauth-button--secondary', $button->getAttribute( 'class' ) );

		// The email submit stays the form's first submit button (implicit submission).
		$submits = $xpath->query( './/button[@type="submit"]', $form );
		$this->assertNotFalse( $submits );
		$this->assertSame( 1, $submits->length );

		foreach ( [ 'status' => 'data-magicauth-passkey-status', 'alert' => 'data-magicauth-passkey-error' ] as $role => $attr ) {
			$region = self::node( $xpath, '//*[@' . $attr . ']' );
			$this->assertSame( $role, $region->getAttribute( 'role' ) );
			$this->assertFalse( $region->hasAttribute( 'hidden' ), $attr . ' is never hidden itself' );
		}
		$divider = self::node( $xpath, '//p[contains(@class,"magicauth-divider")]' );
		$this->assertSame( 'true', $divider->getAttribute( 'aria-hidden' ) );

		$input = self::node( $xpath, '//input[@name="magicauth_email"]' );
		$this->assertSame( 'email', $input->getAttribute( 'type' ) );
		$this->assertSame( 'email', $input->getAttribute( 'inputmode' ) );
		$this->assertSame( 'magicauth-email', $input->getAttribute( 'id' ) );
	}

	public function test_signin_markup_filter_replaces_the_block_and_gets_the_state(): void {
		$seen = [];
		add_filter(
			'magicauth_passkey_signin_markup',
			static function ( $html, $state ) use ( &$seen ) {
				$seen[] = [ $html, $state ];
				return '<div data-theme-passkey></div>';
			},
			10,
			2
		);
		$html = self::render_state( 'a' );
		$this->assertStringContainsString( '<div data-theme-passkey></div>', $html );
		$this->assertStringNotContainsString( 'data-magicauth-passkey-root', $html );
		$this->assertSame( [ [ Assets::signin_markup(), 'a' ] ], $seen );
	}

	/* ------------------------------------------------------ theme helpers */

	public function test_theme_helpers(): void {
		$this->assertTrue( magicauth_passkeys_enabled() );

		ob_start();
		magicauth_passkey_signin_button( [ 'redirect_to' => 'https://academy.example.com/courses/x/?a=1&b="2"' ] );
		$html  = (string) ob_get_clean();
		$xpath = self::dom( $html );
		$root  = self::node( $xpath, '//*[@data-magicauth-passkey-root]' );
		$this->assertStringStartsWith( 'https://academy.example.com/courses/x/?a=1', $root->getAttribute( 'data-magicauth-redirect-to' ) );
		$this->assertStringNotContainsString( '"2"', $html, 'quotes escaped' );
		self::node( $xpath, '//button[@data-magicauth-passkey-signin][@type="button"]' );

		Ceremony::user( 7 );
		magicauth_test_login_as( 7 );
		ob_start();
		magicauth_passkey_signin_button();
		$this->assertSame( '', (string) ob_get_clean(), 'nothing for a signed-in visitor' );

		wp_set_current_user( 0 );
		self::module( false );
		$this->assertFalse( magicauth_passkeys_enabled() );
		ob_start();
		magicauth_passkey_signin_button();
		$this->assertSame( '', (string) ob_get_clean(), 'nothing with the module off' );
	}

	public function test_signin_markup_without_a_target_has_no_redirect_attribute(): void {
		$this->assertStringNotContainsString( 'data-magicauth-redirect-to', Assets::signin_markup() );
		$this->assertStringNotContainsString( 'data-magicauth-redirect-to', Assets::signin_markup( [ 'redirect_to' => '' ] ) );
		$this->assertStringNotContainsString( 'data-magicauth-redirect-to', Assets::signin_markup( [ 'redirect_to' => [ 'x' ] ] ), 'not a string' );
	}

	/* ------------------------------------------------------------ enqueues */

	/** @return array<string,array{array<string,string>,bool}> */
	public static function shortcode_requests(): array {
		return [
			'state A'      => [ [], true ],
			'unknown step' => [ [ 'magicauth_step' => 'bogus' ], true ],
			'state B'      => [ [ 'magicauth_step' => 'code' ], false ],
			'state C'      => [ [ 'magicauth_step' => 'password' ], false ],
		];
	}

	/**
	 * @dataProvider shortcode_requests
	 * @param array<string,string> $get
	 */
	public function test_shortcode_page_loads_the_login_assets_in_state_a_only( array $get, bool $expected ): void {
		global $post;
		$post = new \WP_Post( '[magicauth_login]' );
		$_GET = $get;
		Shortcode::enqueue();
		Assets::enqueue_front();

		$login = [ Assets::CORE_HANDLE, Assets::LOGIN_HANDLE ];
		if ( $expected ) {
			$this->assertSame( array_merge( [ 'magicauth' ], $login ), self::scripts() );
			$this->assertSame( [ 'magicauth', Assets::LOGIN_STYLE ], self::styles() );
		} else {
			$this->assertSame( [ 'magicauth' ], self::scripts() );
			$this->assertSame( [ 'magicauth' ], self::styles() );
		}
	}

	public function test_login_assets_are_deferred_footer_scripts_with_the_config_before(): void {
		global $post, $magicauth_test_state;
		$post = new \WP_Post( '[magicauth_login]' );
		Assets::enqueue_front();

		$scripts = $magicauth_test_state['enqueued_scripts'];
		$args    = [
			'in_footer' => true,
			'strategy'  => 'defer',
		];
		$this->assertSame( [ MAGICAUTH_URL . 'assets/js/magicauth-passkeys-core.js', [], MAGICAUTH_VERSION, $args ], $scripts[ Assets::CORE_HANDLE ] );
		$this->assertSame( [ MAGICAUTH_URL . 'assets/js/magicauth-passkeys-login.js', [ Assets::CORE_HANDLE ], MAGICAUTH_VERSION, $args ], $scripts[ Assets::LOGIN_HANDLE ] );
		$this->assertSame( MAGICAUTH_URL . 'assets/css/magicauth-passkeys-login.css', $magicauth_test_state['enqueued_styles'][ Assets::LOGIN_STYLE ][0] );

		$inline = $magicauth_test_state['inline_scripts'][ Assets::LOGIN_HANDLE ] ?? [];
		$this->assertCount( 1, $inline );
		[ $data, $position ] = $inline[0];
		$this->assertSame( 'before', $position );
		$this->assertStringStartsWith( 'window.magicauthPasskeysConfig = ', $data );
		$this->assertStringEndsWith( ';', $data );
		$json = substr( $data, strlen( 'window.magicauthPasskeysConfig = ' ), -1 );
		$this->assertSame( Assets::login_config(), json_decode( $json, true ) );
		$this->assertFalse( strpbrk( $json, "<>&'" ), 'tags, ampersands and apostrophes are hex-escaped' );
	}

	public function test_config_cannot_break_out_of_the_inline_script(): void {
		global $post, $magicauth_test_state;
		$post = new \WP_Post( '[magicauth_login]' );
		// Decide enabled() at init (cached), then let a filter put markup into the config.
		do_action( 'init' );
		$this->assertTrue( Module::enabled() );
		add_filter( 'home_url', static fn( $url ) => (string) $url . '</script><script>alert("x&y\'")</script>' );

		Assets::enqueue_front();
		$inline = $magicauth_test_state['inline_scripts'][ Assets::LOGIN_HANDLE ] ?? [];
		$this->assertCount( 1, $inline );
		$this->assertFalse( strpbrk( substr( $inline[0][0], strlen( 'window.magicauthPasskeysConfig = ' ) ), "<>&'" ), 'hex-escaped' );
		$json = substr( $inline[0][0], strlen( 'window.magicauthPasskeysConfig = ' ), -1 );
		$this->assertStringEndsWith( '</script><script>alert("x&y\'")</script>', (string) json_decode( $json, true )['homeUrl'], 'and decodes back' );
	}

	public function test_no_login_assets_for_a_signed_in_visitor_or_with_the_module_off(): void {
		global $post;
		$post = new \WP_Post( '[magicauth_login]' );

		Ceremony::user( 7 );
		magicauth_test_login_as( 7 );
		Assets::enqueue_front();
		$this->assertSame( [], self::scripts(), 'signed in' );

		wp_set_current_user( 0 );
		self::module( false );
		Assets::enqueue_front();
		$this->assertSame( [], self::scripts(), 'module off' );
	}

	public function test_no_login_assets_on_a_page_without_the_form(): void {
		global $post;
		$post = new \WP_Post( 'Just a page.' );
		Assets::enqueue_front();
		$this->assertSame( [], self::scripts() );
	}

	public function test_forced_assets_load_them_for_a_theme_wall(): void {
		add_filter( 'magicauth_force_frontend_assets', static fn() => true );
		Assets::enqueue_front();
		$this->assertSame( [ Assets::CORE_HANDLE, Assets::LOGIN_HANDLE ], self::scripts() );
	}

	public function test_style_filters(): void {
		global $post;
		$post = new \WP_Post( '[magicauth_login]' );

		add_filter( 'magicauth_passkeys_enqueue_style', static fn() => false );
		Assets::enqueue_front();
		$this->assertSame( [], self::styles(), 'no passkey stylesheet' );
		$this->assertSame( [ Assets::CORE_HANDLE, Assets::LOGIN_HANDLE ], self::scripts(), 'scripts still load' );

		self::reset_enqueues();
		add_filter( 'magicauth_enqueue_frontend_style', static fn() => false );
		Shortcode::enqueue();
		$this->assertSame( [], self::styles(), 'magicauth.css skipped by a theme' );
		$this->assertSame( [ 'magicauth' ], self::scripts(), 'magicauth.js still loads' );
	}

	/** @return array<string,array{array<string,string>,bool}> */
	public static function login_screen_requests(): array {
		return [
			'state A'      => [ [ 'action' => 'magicauth' ], true ],
			'unknown step' => [
				[
					'action'         => 'magicauth',
					'magicauth_step' => 'nope',
				],
				true,
			],
			'state B'      => [
				[
					'action'         => 'magicauth',
					'magicauth_step' => 'code',
				],
				false,
			],
			'state C'      => [
				[
					'action'         => 'magicauth',
					'magicauth_step' => 'password',
				],
				false,
			],
			'lostpassword' => [ [ 'action' => 'lostpassword' ], false ],
			'rp'           => [ [ 'action' => 'rp' ], false ],
			'native login' => [ [], false ],
		];
	}

	/**
	 * @dataProvider login_screen_requests
	 * @param array<string,string> $get
	 */
	public function test_login_screen_loads_the_login_assets_in_state_a_only( array $get, bool $expected ): void {
		$_GET = $get;
		Assets::enqueue_login_screen();
		$this->assertSame( $expected ? [ Assets::CORE_HANDLE, Assets::LOGIN_HANDLE ] : [], self::scripts() );
		$this->assertSame( $expected ? [ Assets::LOGIN_STYLE ] : [], self::styles() );
	}

	public function test_login_screen_assets_off_for_a_signed_in_visitor_or_the_module_off(): void {
		$_GET = [ 'action' => 'magicauth' ];
		Ceremony::user( 7 );
		magicauth_test_login_as( 7 );
		Assets::enqueue_login_screen();
		$this->assertSame( [], self::scripts() );

		wp_set_current_user( 0 );
		self::module( false );
		Assets::enqueue_login_screen();
		$this->assertSame( [], self::scripts() );
	}

	public function test_module_registers_the_asset_hooks_after_the_core_ones(): void {
		Module::register();
		$this->assertSame( 20, has_action( 'wp_enqueue_scripts', [ Assets::class, 'enqueue_front' ] ) );
		$this->assertSame( 20, has_action( 'login_enqueue_scripts', [ Assets::class, 'enqueue_login_screen' ] ) );
		$this->assertSame( 'a', LoginScreen::resolve_state( '' ) );
	}
}
