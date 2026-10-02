<?php
/**
 * T-OFF-1, the part build step 4 owns (SPEC 15 step 4, 14.1, G6, 8.11):
 * with the module off the login form, the shortcode and the emails render
 * exactly the 1.0.5 golden fixtures (build step 1) after normalisation,
 * except the listed B5 change (the state A submit button is rendered enabled
 * and magicauth.js disables it). Guest renders and asset enqueues touch no
 * passkey handle and no passkey table.
 *
 * Build step 10 adds T-OFF-3 (a filter a theme adds after plugins_loaded
 * decides Module::enabled() at init 0) and the module-off boot: Plugin::boot()
 * plus init on a guest request with the module off sends no cookie and runs
 * no passkey query. The sign-in half of T-OFF-1 (no magicauth_pk_fresh,
 * session record without magicauth_fresh_hash) is in LoginTest (every method,
 * module off and on) and ControllerIntegrationTest. T-OFF-2 (admin endpoints
 * registered and working with the module off) is in AdminEndpointsTest
 * (build step 13), which also adds its owner hooks here. Build
 * step 12 adds the sign-in and login asset hooks to the T-OFF-3 cases; the
 * enabled-module render counterpart is in LoginAssetsTest. Build step 14
 * adds the prompt choice and the prompt and signals hooks.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Frontend\LoginScreen;
use MagicAuth\Frontend\Shortcode;
use MagicAuth\Passkeys\Module;
use MagicAuth\Plugin;
use MagicAuth\Tests\Support\Ceremony;
use MagicAuth\Tests\Support\Golden;
use PHPUnit\Framework\TestCase;

final class ModuleOffTest extends TestCase {

	/** The state A email submit button as 1.0.5 rendered it (normalised line). */
	private const B5_BEFORE = '<button aria-disabled="true" class="magicauth-button" disabled="disabled" type="submit">';

	/** The same button after B5. */
	private const B5_AFTER = '<button class="magicauth-button" type="submit">';

	/** Fixtures whose only change is B5 (both render state A). */
	private const B5_FILES = [ 'login-form-a.html', 'shortcode-logged-out.html' ];

	protected function setUp(): void {
		magicauth_test_reset_state();
	}

	protected function tearDown(): void {
		global $post;
		$post = null;
		$_GET = [];
		unset( $_SERVER['HTTP_HOST'], $_SERVER['REQUEST_URI'] );
		magicauth_test_reset_state();
	}

	public function test_module_off_output_equals_the_1_0_5_fixtures_except_b5(): void {
		$rendered = Golden::render_all();
		$this->assertSame( Golden::files(), array_keys( $rendered ) );

		foreach ( $rendered as $file => $content ) {
			$fixture = (string) file_get_contents( Golden::DIR . '/' . $file );
			if ( in_array( $file, self::B5_FILES, true ) ) {
				$this->assertSame( 1, substr_count( $fixture, self::B5_BEFORE ), $file . ': fixture holds the 1.0.5 button once' );
				$fixture = str_replace( self::B5_BEFORE, self::B5_AFTER, $fixture );
			}
			$this->assertSame( $fixture, $content, $file );
		}
	}

	public function test_b5_touches_only_the_state_a_email_button(): void {
		$rendered = Golden::render_all();
		foreach ( $rendered as $file => $content ) {
			$fixture = (string) file_get_contents( Golden::DIR . '/' . $file );
			if ( in_array( $file, self::B5_FILES, true ) ) {
				$this->assertNotSame( $fixture, $content, $file . ' changed (B5)' );
				$this->assertStringNotContainsString( 'disabled', $content, $file );
			} else {
				$this->assertSame( $fixture, $content, $file . ' unchanged' );
			}
		}
	}

	public function test_state_a_email_form_submits_without_js(): void {
		$_SERVER['HTTP_HOST']   = 'example.test';
		$_SERVER['REQUEST_URI'] = '/login/';
		$html                   = Shortcode::render( [] );

		$dom = new \DOMDocument();
		libxml_use_internal_errors( true );
		$dom->loadHTML( '<!DOCTYPE html><html><body>' . $html . '</body></html>' );
		libxml_clear_errors();
		$xpath = new \DOMXPath( $dom );

		$forms = $xpath->query( '//form[@method="post"]' );
		$this->assertNotFalse( $forms );
		$this->assertSame( 1, $forms->length );
		$form = $forms->item( 0 );
		$this->assertInstanceOf( \DOMElement::class, $form );
		$this->assertStringEndsWith( '/wp-admin/admin-post.php', $form->getAttribute( 'action' ) );

		$action = $xpath->query( './/input[@name="action"]', $form );
		$this->assertNotFalse( $action );
		$action_input = $action->item( 0 );
		$this->assertInstanceOf( \DOMElement::class, $action_input );
		$this->assertSame( 'magicauth_request', $action_input->getAttribute( 'value' ) );

		$this->assertSame( 1, $this->count_nodes( $xpath, './/input[@name="magicauth_email"][@type="email"]', $form ) );
		$buttons = $xpath->query( './/button[@type="submit"]', $form );
		$this->assertNotFalse( $buttons );
		$this->assertSame( 1, $buttons->length );
		$button = $buttons->item( 0 );
		$this->assertInstanceOf( \DOMElement::class, $button );
		$this->assertFalse( $button->hasAttribute( 'disabled' ), 'a no-JS browser can submit the email form' );
		$this->assertFalse( $button->hasAttribute( 'aria-disabled' ) );
	}

	public function test_no_other_state_rendered_a_disabled_button(): void {
		foreach ( [ 'b', 'c', 'd', 'e' ] as $state ) {
			$fixture = (string) file_get_contents( Golden::DIR . '/login-form-' . $state . '.html' );
			$this->assertStringNotContainsString( 'disabled', $fixture, $state );
		}
	}

	/** magicauth.js still disables the enabled button on init until the value looks like an email. */
	public function test_magicauth_js_disables_the_button_until_the_value_is_an_email(): void {
		$node = $this->node_binary();
		if ( null === $node ) {
			$this->markTestSkipped( 'node is not installed' );
		}

		$empty = $this->run_js( $node, '' );
		$this->assertSame( [ 'aria-disabled' => 'true', 'disabled' => 'disabled' ], $empty['init'] );
		$this->assertSame( [], $empty['valid'], 'typing an email enables it' );
		$this->assertSame( [ 'aria-disabled' => 'true', 'disabled' => 'disabled' ], $empty['invalid'], 'and clearing it disables it again' );

		$prefilled = $this->run_js( $node, 'student@example.test' );
		$this->assertSame( [], $prefilled['init'], 'an autofilled email keeps it enabled' );

		$garbage = $this->run_js( $node, 'not-an-email' );
		$this->assertSame( [ 'aria-disabled' => 'true', 'disabled' => 'disabled' ], $garbage['init'] );
	}

	public function test_no_passkey_handle_is_enqueued_with_the_module_off(): void {
		global $post, $magicauth_test_state;
		$post = new \WP_Post( '[magicauth_login]' );
		Shortcode::enqueue();
		$this->assertSame( [ 'magicauth' ], array_keys( $magicauth_test_state['enqueued_styles'] ?? [] ) );
		$this->assertSame( [ 'magicauth' ], array_keys( $magicauth_test_state['enqueued_scripts'] ?? [] ) );

		magicauth_test_reset_state();
		$_GET = [ 'action' => 'magicauth' ];
		ob_start();
		LoginScreen::enqueue();
		$printed = (string) ob_get_clean();
		$this->assertStringNotContainsString( 'passkey', $printed );
		$this->assertSame( [ 'magicauth' ], array_keys( $magicauth_test_state['enqueued_styles'] ?? [] ) );
		$this->assertSame( [ 'magicauth' ], array_keys( $magicauth_test_state['enqueued_scripts'] ?? [] ) );
		$this->assertSame( MAGICAUTH_URL . 'assets/js/magicauth.js', $magicauth_test_state['enqueued_scripts']['magicauth'][0] );
	}

	public function test_guest_renders_query_no_passkey_table(): void {
		global $wpdb;
		$_SERVER['HTTP_HOST'] = 'example.test';
		$build                = new \ReflectionMethod( LoginScreen::class, 'build_context' );
		$shell                = new \ReflectionMethod( LoginScreen::class, 'render_shell' );
		if ( PHP_VERSION_ID < 80100 ) {
			$build->setAccessible( true );
			$shell->setAccessible( true );
		}

		$wpdb->query_log = [];
		ob_start();
		try {
			foreach ( [ '' => 'a', 'code' => 'b', 'password' => 'c' ] as $step => $state ) {
				$_GET                   = '' === $step ? [] : [ 'magicauth_step' => $step ];
				$_SERVER['REQUEST_URI'] = '/login/';
				$this->assertSame( $state, Shortcode::current_state() );
				echo Shortcode::render( [] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				$this->assertSame( $state, LoginScreen::resolve_state( $step ) );
				$shell->invoke( null, $build->invoke( null, $state, '' ) );
			}
			foreach ( [ 'd', 'e' ] as $state ) {
				$shell->invoke( null, $build->invoke( null, $state, '' ) );
			}
		} finally {
			$html = (string) ob_get_clean();
		}

		$this->assertStringContainsString( 'class="magicauth-card"', $html );
		foreach ( $wpdb->query_log as $sql ) {
			$this->assertStringNotContainsString( 'passkey', strtolower( (string) $sql ) );
		}
		$this->assertStringNotContainsString( 'passkey', strtolower( $html ) );
	}

	/* ----------------------------------------------- T-OFF-3, module-off boot */

	/** Plugin::boot() on plugins_loaded; the textdomain loader is unhooked (no i18n API in the harness). */
	private static function boot(): void {
		$plugin = ( new \ReflectionClass( Plugin::class ) )->newInstanceWithoutConstructor();
		$plugin->boot();
		remove_action( 'init', [ $plugin, 'load_textdomain' ] );
	}

	/** Setting on, https academy host, DB version 2. */
	private static function available_site_with_setting_on(): void {
		Ceremony::site();
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => true ] );
	}

	/** T-OFF-3: a theme's home_url filter, added after plugins_loaded, turns the module off at init 0. */
	public function test_theme_filter_added_after_plugins_loaded_turns_the_module_off(): void {
		self::available_site_with_setting_on();
		self::boot();
		$this->assertTrue( Module::enabled(), 'at plugins_loaded, before the theme' );

		// functions.php: the site is served from an IP address (S8a).
		$ip_host = static fn( $url ) => str_replace( 'academy.example.com', '203.0.113.9', (string) $url );
		add_filter( 'home_url', $ip_host );
		do_action( 'init' );

		$this->assertFalse( Module::enabled(), 'the value before init was not cached' );
		$this->assert_account_hooks( false );
		$this->assert_signin_hooks( false );
		$error = Module::available();
		$this->assertInstanceOf( \WP_Error::class, $error );
		$this->assertSame( 'magicauth_pk_ip_host', $error->get_error_code() );
		remove_filter( 'home_url', $ip_host );
		$this->assertFalse( Module::enabled(), 'decided once at init 0 for the rest of the request' );
	}

	/** T-OFF-3, the other way: a theme filter that makes the site available turns it on at init 0. */
	public function test_theme_filter_added_after_plugins_loaded_turns_the_module_on(): void {
		global $magicauth_test_state;
		self::available_site_with_setting_on();
		$magicauth_test_state['home'] = 'https://academy.example.com/blog';
		self::boot();
		$this->assertFalse( Module::enabled(), 'subfolder home (S8e) before the theme' );

		add_filter( 'home_url', static fn( $url ) => str_replace( '/blog', '', (string) $url ) );
		do_action( 'init' );

		$this->assertTrue( Module::enabled() );
		$this->assert_account_hooks( true );
		$this->assert_signin_hooks( true );
	}

	/** The account endpoints (build step 11): wp_ajax_ only, registered exactly when enabled. */
	private function assert_account_hooks( bool $registered ): void {
		$actions = [ 'register_options', 'register', 'reauth_email', 'reauth_code', 'reauth_options', 'reauth_passkey', 'rename', 'delete', 'signout_others', 'prompt' => 'prompt_choice' ];
		foreach ( $actions as $action => $handler ) {
			$action = is_string( $action ) ? $action : $handler;
			$hook   = 'wp_ajax_magicauth_passkey_' . $action;
			if ( $registered ) {
				$this->assertSame( 10, has_action( $hook, [ \MagicAuth\Passkeys\AccountEndpoints::class, $handler ] ), $hook );
			} else {
				$this->assertFalse( has_action( $hook ), $hook );
			}
			$this->assertFalse( has_action( 'wp_ajax_nopriv_magicauth_passkey_' . $action ), $action . ': never nopriv' );
		}
		// Prompt, signals and management-page headers (build step 14).
		$prompt = \MagicAuth\Passkeys\Prompt::class;
		$this->assertSame( $registered ? PHP_INT_MAX : false, has_action( 'template_redirect', [ $prompt, 'prepare_front' ] ) );
		$this->assertSame( $registered ? 20 : false, has_action( 'wp_footer', [ $prompt, 'render_footer' ] ) );
		$this->assertSame( $registered ? 20 : false, has_action( 'admin_footer', [ $prompt, 'render_footer' ] ) );
		$this->assertSame( $registered ? 10 : false, has_action( 'current_screen', [ $prompt, 'prepare_admin' ] ) );
		$this->assertFalse( has_action( 'template_redirect', [ \MagicAuth\Passkeys\ManageShortcode::class, 'prepare_front' ] ) );
	}

	/** The sign-in endpoints (nopriv and priv) and the login asset hooks (build step 12), registered exactly when enabled. */
	private function assert_signin_hooks( bool $registered ): void {
		$endpoints = [
			'signin_options' => 'options',
			'signin'         => 'verify',
			'complete'       => 'complete',
		];
		foreach ( $endpoints as $action => $method ) {
			foreach ( [ 'wp_ajax_nopriv_', 'wp_ajax_' ] as $prefix ) {
				$hook = $prefix . 'magicauth_passkey_' . $action;
				$this->assertSame( $registered ? 10 : false, has_action( $hook, [ \MagicAuth\Passkeys\SignInEndpoints::class, $method ] ), $hook );
			}
		}
		$this->assertSame( $registered ? 20 : false, has_action( 'wp_enqueue_scripts', [ \MagicAuth\Passkeys\Assets::class, 'enqueue_front' ] ) );
		$this->assertSame( $registered ? 20 : false, has_action( 'login_enqueue_scripts', [ \MagicAuth\Passkeys\Assets::class, 'enqueue_login_screen' ] ) );
	}

	/** register() runs at init 0, before every default-priority init callback a theme adds. */
	public function test_register_runs_before_default_priority_init_callbacks(): void {
		self::available_site_with_setting_on();
		self::boot();
		$seen = null;
		add_action(
			'init',
			static function () use ( &$seen ) {
				update_option( 'magicauth_settings', [ 'passkeys_enabled' => false ] );
				$seen = Module::enabled();
			}
		);

		do_action( 'init' );

		$this->assertTrue( $seen, 'decided at init 0, before a later init callback changed the setting' );
	}

	/** G6: module off, a guest request through boot and init sends no cookie and queries no passkey table. */
	public function test_module_off_boot_sends_no_cookie_and_runs_no_passkey_query(): void {
		global $wpdb, $magicauth_test_state;
		Ceremony::site();
		$wpdb->query_log = [];
		self::boot();

		do_action( 'init' );

		$this->assertFalse( Module::enabled() );
		$this->assertSame( [], $magicauth_test_state['cookies'] ?? [] );
		$this->assertSame( [], $magicauth_test_state['headers'] ?? [] );
		foreach ( $wpdb->query_log as $sql ) {
			$this->assertStringNotContainsString( 'passkey', strtolower( (string) $sql ) );
		}
	}

	/* ------------------------------------------------------------- helpers */

	private function count_nodes( \DOMXPath $xpath, string $query, \DOMNode $context ): int {
		$nodes = $xpath->query( $query, $context );
		return false === $nodes ? 0 : $nodes->length;
	}

	private function node_binary(): ?string {
		$path = trim( (string) shell_exec( 'command -v node 2>/dev/null' ) );
		return '' !== $path && is_executable( $path ) ? $path : null;
	}

	/**
	 * Runs assets/js/magicauth.js against a minimal DOM: one email input with
	 * $value inside a form with one submit button (rendered enabled, as B5).
	 * Returns the button's attributes after init, after typing a valid email
	 * and after typing an invalid value.
	 *
	 * @return array{init:array<string,string>,valid:array<string,string>,invalid:array<string,string>}
	 */
	private function run_js( string $node, string $value ): array {
		$shim = <<<'JS'
const fs = require( 'fs' );
const src = fs.readFileSync( process.argv[2], 'utf8' );
function element() {
	return {
		attrs: {},
		listeners: {},
		setAttribute( k, v ) { this.attrs[ k ] = String( v ); },
		removeAttribute( k ) { delete this.attrs[ k ]; },
		addEventListener( t, f ) { ( this.listeners[ t ] = this.listeners[ t ] || [] ).push( f ); },
		fire( t ) { ( this.listeners[ t ] || [] ).forEach( ( f ) => f( {} ) ); },
		get disabled() { return 'disabled' in this.attrs; },
	};
}
const button = element();
const form = { querySelector: ( s ) => ( s === 'button[type="submit"]' ? button : null ), addEventListener() {} };
const input = element();
input.value = process.argv[3];
input.form = form;
globalThis.window = {};
globalThis.document = {
	readyState: 'complete',
	getElementById: ( id ) => ( id === 'magicauth-email' ? input : null ),
	querySelectorAll: () => [],
	addEventListener() {},
};
new Function( src )();
const out = { init: Object.assign( {}, button.attrs ) };
input.value = 'someone@example.test';
input.fire( 'input' );
out.valid = Object.assign( {}, button.attrs );
input.value = 'someone@';
input.fire( 'input' );
out.invalid = Object.assign( {}, button.attrs );
process.stdout.write( JSON.stringify( out ) );
JS;
		$file = tempnam( sys_get_temp_dir(), 'magicauth-js-' );
		$this->assertNotFalse( $file );
		file_put_contents( $file, $shim );
		try {
			$cmd    = escapeshellarg( $node ) . ' ' . escapeshellarg( $file ) . ' '
				. escapeshellarg( MAGICAUTH_DIR . 'assets/js/magicauth.js' ) . ' ' . escapeshellarg( $value ) . ' 2>&1';
			$output = (string) shell_exec( $cmd );
		} finally {
			unlink( $file );
		}
		$data = json_decode( $output, true );
		$this->assertIsArray( $data, 'node output: ' . $output );
		foreach ( [ 'init', 'valid', 'invalid' ] as $key ) {
			$this->assertIsArray( $data[ $key ] ?? null, $key );
			if ( [] === $data[ $key ] ) {
				// JSON {} decodes to [], keep it an empty map.
				$data[ $key ] = [];
			}
			ksort( $data[ $key ] );
		}
		/** @var array{init:array<string,string>,valid:array<string,string>,invalid:array<string,string>} $data */
		return $data;
	}
}
