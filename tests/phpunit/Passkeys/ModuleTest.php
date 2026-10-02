<?php
/**
 * Passkeys\Module toggle and wiring (SPEC 4.5, 4.6, build step 10): setup()
 * registers the always-on data hooks and register() on init 0; enabled() is
 * the setting AND available(), cached only once init has fired; register()
 * evaluates it at init 0; manage_url() and manage_location() (4.5, 10.2).
 *
 * The late-filter case (T-OFF-3) lives in ModuleOffTest.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Installer;
use MagicAuth\Passkeys\CredentialStore;
use MagicAuth\Passkeys\Module;
use MagicAuth\Plugin;
use MagicAuth\Tests\Support\Ceremony;
use MagicAuth\Tests\Support\SoftAuthenticator;
use PHPUnit\Framework\TestCase;
use WP_User;

final class ModuleTest extends TestCase {

	protected function setUp(): void {
		Ceremony::site();
	}

	protected function tearDown(): void {
		magicauth_test_reset_state();
	}

	private static function turn_on(): void {
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => true ] );
	}

	/** Plugin::boot() as on plugins_loaded; its textdomain loader is unhooked (no i18n API under the harness). */
	private static function boot(): void {
		$plugin = ( new \ReflectionClass( Plugin::class ) )->newInstanceWithoutConstructor();
		$plugin->boot();
		remove_action( 'init', [ $plugin, 'load_textdomain' ] );
	}

	/* ------------------------------------------------------------ setup() */

	public function test_setup_registers_the_data_hooks_and_register_on_init_0(): void {
		Module::setup();

		$this->assertSame( 10, has_action( 'delete_user', [ CredentialStore::class, 'on_delete_user' ] ) );
		$this->assertSame( 10, has_action( 'wpmu_delete_user', [ CredentialStore::class, 'on_wpmu_delete_user' ] ) );
		$this->assertSame( 0, has_action( 'init', [ Module::class, 'register' ] ) );
	}

	public function test_plugin_boot_calls_setup_with_the_module_off_and_outside_admin(): void {
		self::boot();

		$this->assertFalse( is_admin() );
		$this->assertFalse( Module::enabled() );
		$this->assertSame( 0, has_action( 'init', [ Module::class, 'register' ] ) );
		$this->assertSame( 10, has_action( 'delete_user', [ CredentialStore::class, 'on_delete_user' ] ) );
		$this->assertFalse( has_action( 'delete_user', [ Installer::class, 'on_delete_user' ] ) );
	}

	/** delete_user with the module off still removes the requests rows (B10) and the passkey data. */
	public function test_delete_user_through_the_module_hook_cleans_requests_and_passkeys(): void {
		global $wpdb;
		$user = Ceremony::user( 5 );
		Ceremony::enrol( new SoftAuthenticator(), $user );
		$wpdb->insert(
			$wpdb->prefix . 'magicauth_requests',
			[
				'selector'           => 'u5',
				'link_verifier_hash' => 'l',
				'code_verifier_hash' => 'c',
				'user_id'            => 5,
				'email_hmac'         => 'e',
				'ip_hmac'            => 'i',
				'created_at'         => '2026-10-01 00:00:00',
				'expires_at'         => '2026-10-01 00:10:00',
			]
		);
		self::boot();

		do_action( 'delete_user', 5, null, $user );

		$this->assertSame( '0', (string) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}magicauth_requests WHERE user_id = 5" ) );
		$this->assertSame( '0', (string) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}magicauth_passkeys WHERE user_id = 5" ) );
	}

	/* ---------------------------------------------------------- enabled() */

	public function test_off_by_default_even_on_an_available_site(): void {
		$this->assertTrue( Module::available() );
		$this->assertFalse( Module::enabled() );
	}

	public function test_on_when_the_setting_is_on_and_the_site_is_available(): void {
		self::turn_on();
		$this->assertTrue( Module::enabled() );
	}

	public function test_setting_on_but_unavailable_is_off(): void {
		global $magicauth_test_state;
		self::turn_on();
		$magicauth_test_state['home']   = 'http://academy.example.com';
		$magicauth_test_state['is_ssl'] = false;

		$this->assertInstanceOf( \WP_Error::class, Module::available() );
		$this->assertFalse( Module::enabled() );
	}

	public function test_schema_below_version_2_is_off(): void {
		self::turn_on();
		update_option( 'magicauth_db_version', 1 );
		$this->assertFalse( Module::enabled() );
	}

	public function test_not_cached_before_init(): void {
		self::turn_on();
		$this->assertTrue( Module::enabled() );

		update_option( 'magicauth_settings', [ 'passkeys_enabled' => false ] );
		$this->assertFalse( Module::enabled(), 'recomputed: init has not fired' );
	}

	public function test_cached_once_init_has_fired(): void {
		self::turn_on();
		do_action( 'init' );
		$this->assertTrue( Module::enabled() );

		update_option( 'magicauth_settings', [ 'passkeys_enabled' => false ] );
		$this->assertTrue( Module::enabled(), 'evaluated once per request after init' );
	}

	public function test_register_at_init_0_evaluates_and_caches(): void {
		self::boot();
		self::turn_on();

		do_action( 'init' );

		update_option( 'magicauth_settings', [ 'passkeys_enabled' => false ] );
		$this->assertTrue( Module::enabled() );
	}

	public function test_register_with_the_module_off_registers_nothing(): void {
		global $magicauth_test_state;
		self::boot();
		$before = $magicauth_test_state['actions'];

		Module::register();

		$this->assertSame( $before, $magicauth_test_state['actions'] );
	}

	public function test_reset_for_tests_forgets_the_cached_value(): void {
		self::turn_on();
		do_action( 'init' );
		$this->assertTrue( Module::enabled() );

		Module::reset_for_tests();
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => false ] );

		$this->assertFalse( Module::enabled() );
	}

	/** A truthy non-bool stored value counts as on, as the sanitiser would have stored true. */
	public function test_setting_value_shapes(): void {
		foreach ( [ [ '1', true ], [ 1, true ], [ '0', false ], [ '', false ], [ null, false ] ] as [ $stored, $expected ] ) {
			Module::reset_for_tests();
			update_option( 'magicauth_settings', [ 'passkeys_enabled' => $stored ] );
			$this->assertSame( $expected, Module::enabled(), var_export( $stored, true ) );
		}
	}

	/* ------------------------------------------- manage_url(), manage_location() */

	private static function page( int $id, string $status = 'publish', string $type = 'page', string $title = 'Account' ): void {
		global $magicauth_test_state;
		$magicauth_test_state['posts'][ $id ] = [
			'status'    => $status,
			'type'      => $type,
			'title'     => $title,
			'permalink' => 'https://academy.example.com/account/',
		];
	}

	private static function learner(): WP_User {
		return Ceremony::user( 30 );
	}

	private static function editor(): WP_User {
		return magicauth_test_register_user( 31, 'editor@example.test', [ 'editor' ] );
	}

	public function test_manage_url_is_the_published_page(): void {
		self::page( 12 );
		update_option( 'magicauth_settings', [ 'passkeys_manage_page_id' => 12 ] );

		$this->assertSame( 'https://academy.example.com/account/', Module::manage_url( self::learner() ) );
		$this->assertSame( 'https://academy.example.com/account/', Module::manage_url( self::editor() ) );
	}

	public function test_manage_url_falls_back_to_the_profile_for_users_who_can_edit_posts(): void {
		$this->assertSame( 'https://academy.example.com/wp-admin/profile.php#magicauth-passkeys', Module::manage_url( self::editor() ) );
		$this->assertSame( '', Module::manage_url( self::learner() ), 'learners never get a wp-admin link' );
	}

	/** The URL is the target user's, not the actor's: an admin acting on a learner gets ''. */
	public function test_manage_url_follows_the_given_user_not_the_current_one(): void {
		magicauth_test_login_as( (int) self::editor()->ID );
		$this->assertSame( '', Module::manage_url( self::learner() ) );
	}

	public function test_manage_url_ignores_a_page_that_is_not_a_published_page(): void {
		foreach ( [ [ 'draft', 'page' ], [ 'private', 'page' ], [ 'publish', 'post' ] ] as [ $status, $type ] ) {
			self::page( 12, $status, $type );
			update_option( 'magicauth_settings', [ 'passkeys_manage_page_id' => 12 ] );
			$this->assertSame( '', Module::manage_url( self::learner() ), $status . '/' . $type );
		}
		update_option( 'magicauth_settings', [ 'passkeys_manage_page_id' => 99 ] );
		$this->assertSame( '', Module::manage_url( self::learner() ), 'missing post' );
	}

	public function test_manage_url_filter(): void {
		add_filter(
			'magicauth_passkey_manage_url',
			static function ( $url, $user ) {
				return $user instanceof WP_User ? 'https://academy.example.com/my/keys/?x=1' : $url;
			},
			10,
			2
		);
		$this->assertSame( 'https://academy.example.com/my/keys/?x=1', Module::manage_url( self::learner() ) );
	}

	public function test_manage_url_filter_returning_a_non_string_gives_empty(): void {
		add_filter( 'magicauth_passkey_manage_url', static fn() => [ 'x' ] );
		$this->assertSame( '', Module::manage_url( self::editor() ) );
	}

	public function test_manage_location_names_the_page_and_its_path(): void {
		self::page( 12, 'publish', 'page', 'Mijn &#8216;account&#8217; <b>x</b>' );
		update_option( 'magicauth_settings', [ 'passkeys_manage_page_id' => 12 ] );

		$this->assertSame( "Mijn \u{2018}account\u{2019} x (/account/)", Module::manage_location( self::learner() ) );
	}

	public function test_manage_location_for_profile_users_is_m37(): void {
		$this->assertSame( 'your profile in the dashboard', Module::manage_location( self::editor() ) );
	}

	public function test_manage_location_is_empty_without_a_url(): void {
		$this->assertSame( '', Module::manage_location( self::learner() ) );
	}

	public function test_manage_location_of_a_filtered_url_is_its_path_only(): void {
		add_filter( 'magicauth_passkey_manage_url', static fn() => 'https://academy.example.com/my/keys/?x=1' );
		$this->assertSame( '/my/keys/', Module::manage_location( self::learner() ) );
	}

	public function test_manage_location_of_an_untitled_page_is_its_path(): void {
		self::page( 12, 'publish', 'page', '' );
		update_option( 'magicauth_settings', [ 'passkeys_manage_page_id' => 12 ] );
		$this->assertSame( '/account/', Module::manage_location( self::learner() ) );
	}
}
