<?php
/**
 * T-PROFILE and T-OFFER-5 (SPEC 2.3, 2.6 rows 8, 9 and 21, 6.11, 8.5, 8.11,
 * 14.1, build step 13): the wp-admin profile section, its admin_footer
 * dialogs, the [magicauth_passkeys] shortcode, the management-page headers
 * and the account assets.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Passkeys\Assets;
use MagicAuth\Passkeys\CredentialStore;
use MagicAuth\Passkeys\ManageShortcode;
use MagicAuth\Passkeys\Module;
use MagicAuth\Passkeys\ProfileSection;
use MagicAuth\Tests\Support\Ceremony;
use MagicAuth\Tests\Support\SoftAuthenticator;
use PHPUnit\Framework\TestCase;
use WP_User;

final class ProfileSectionTest extends TestCase {

	private WP_User $student;

	/** @var array<string,mixed> */
	private array $server = [];

	protected function setUp(): void {
		$this->server = $_SERVER;
		Ceremony::site();
		self::module( true );
		$roles                        = wp_roles();
		$roles->roles['group_leader'] = [
			'name'         => 'Group Leader',
			'capabilities' => [
				'read'              => true,
				'edit_users'        => true,
				'list_users'        => true,
				'group_leader'      => true,
				'assign_categories' => true,
			],
		];
		$this->student = Ceremony::user( 7 );
		foreach ( [ 1 => 'administrator', 2 => 'group_leader', 3 => 'editor' ] as $id => $role ) {
			$user                  = magicauth_test_register_user( $id, "user{$id}@example.test", [ $role ] );
			$user->user_registered = Ceremony::REGISTERED;
			$user->display_name    = "User {$id}";
		}
	}

	protected function tearDown(): void {
		global $post;
		$post     = null;
		$_SERVER  = $this->server;
		$_GET     = [];
		$_POST    = [];
		$_REQUEST = [];
		$_COOKIE  = [];
		magicauth_test_reset_state();
	}

	/* ------------------------------------------------------------- helpers */

	private static function module( bool $on ): void {
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => $on ] );
		Module::reset_for_tests();
		ProfileSection::reset_for_tests();
	}

	private function enrol( WP_User $user, string $name = '' ): int {
		$id = Ceremony::enrol( new SoftAuthenticator( 'ES256' ), $user );
		if ( '' !== $name ) {
			$this->assertTrue( CredentialStore::rename( (int) $user->ID, $id, $name ) );
		}
		return $id;
	}

	private static function section( WP_User $target ): string {
		ob_start();
		ProfileSection::render( $target );
		return (string) ob_get_clean();
	}

	private static function dialogs(): string {
		ob_start();
		ProfileSection::render_dialogs();
		return (string) ob_get_clean();
	}

	private function assert_form_safe( string $html, string $label ): void {
		$this->assertStringNotContainsString( '<form', $html, $label );
		preg_match_all( '/<button\b[^>]*>/', $html, $m );
		$this->assertNotEmpty( $m[0], $label . ': has buttons' );
		foreach ( $m[0] as $tag ) {
			$this->assertStringContainsString( 'type="button"', $tag, $label . ': ' . $tag );
		}
	}

	/** @return array<string,mixed> */
	private static function config(): array {
		global $magicauth_test_state;
		$inline = $magicauth_test_state['inline_scripts'][ Assets::ACCOUNT_HANDLE ] ?? [];
		self::assertCount( 1, $inline, 'config added once' );
		self::assertSame( 'before', $inline[0][1] );
		self::assertSame( 1, preg_match( '/^window\.magicauthPasskeysConfig = (.*);$/s', $inline[0][0], $m ) );
		return (array) json_decode( $m[1], true );
	}

	private static function page( string $content, int $id = 50 ): void {
		global $post, $magicauth_test_state;
		$post                             = new \WP_Post( $content );
		$magicauth_test_state['queried'] = [
			'id'   => $id,
			'type' => 'page',
			'post' => $post,
		];
	}

	/* ------------------------------------------------------------- T-PROFILE 1 */

	public function test_add_only_on_the_own_profile(): void {
		$this->enrol( $this->student, 'Laptop' );

		magicauth_test_login_as( 7 );
		$own = self::section( $this->student );
		$this->assertStringContainsString( 'data-magicauth-pk-add', $own );
		$this->assertStringContainsString( 'data-magicauth-pk-mode="manage"', $own );
		$this->assertStringContainsString( 'data-magicauth-pk-rename', $own );
		$this->assertStringContainsString( 'data-magicauth-pk-signout-others', $own );
		$this->assertStringNotContainsString( 'data-magicauth-pk-remove-all', $own );

		ProfileSection::reset_for_tests();
		magicauth_test_login_as( 1 );
		$other = self::section( $this->student );
		$this->assertStringContainsString( 'Laptop', $other );
		$this->assertStringContainsString( 'data-magicauth-pk-mode="admin"', $other );
		$this->assertStringNotContainsString( 'data-magicauth-pk-add', $other, 'never Add for another user' );
		$this->assertStringNotContainsString( 'data-magicauth-pk-rename', $other );
		$this->assertStringNotContainsString( 'data-magicauth-pk-signout-others', $other );
		$this->assertStringContainsString( 'data-magicauth-pk-remove-all', $other );
		$this->assertStringNotContainsString( (string) Ceremony::row( 1 )['credential_id'], $other, 'no credential IDs' );
		$this->assertStringContainsString( 'data-magicauth-pk-admin-nonce="' . wp_create_nonce( 'magicauth-passkeys-admin' ) . '"', $other );
		$this->assertStringContainsString( 'data-magicauth-pk-user="7"', $other );
	}

	public function test_editor_and_group_leader_get_no_section_for_another_user(): void {
		$this->enrol( $this->student );
		foreach ( [ 2, 3 ] as $actor ) {
			ProfileSection::reset_for_tests();
			magicauth_test_login_as( $actor );
			$this->assertSame( '', self::section( $this->student ), "actor {$actor}" );
			$this->assertSame( '', self::dialogs() );
		}
	}

	public function test_module_off_own_profile_without_passkeys_shows_nothing(): void {
		self::module( false );
		magicauth_test_login_as( 7 );
		$this->assertSame( '', self::section( $this->student ) );
	}

	public function test_module_off_own_profile_with_passkeys_is_remove_only(): void {
		$this->enrol( $this->student, 'Old phone' );
		self::module( false );
		magicauth_test_login_as( 7 );
		$html = self::section( $this->student );
		$this->assertStringContainsString( 'Old phone', $html );
		$this->assertStringContainsString( 'data-magicauth-pk-mode="admin"', $html, 'removal through the admin endpoint' );
		$this->assertStringContainsString( 'data-magicauth-pk-remove', $html );
		$this->assertStringContainsString( 'Passkeys are turned off for this site. You can still remove stored passkeys.', $html );
		$this->assertStringNotContainsString( 'data-magicauth-pk-add', $html );
		$this->assertStringNotContainsString( 'data-magicauth-pk-rename', $html );
		$this->assertStringNotContainsString( 'data-magicauth-pk-remove-all', $html, 'own profile: per passkey only' );
	}

	public function test_module_off_other_user_with_passkeys(): void {
		$this->enrol( $this->student );
		self::module( false );
		magicauth_test_login_as( 1 );
		$html = self::section( $this->student );
		$this->assertStringContainsString( 'data-magicauth-pk-remove-all', $html );
		$this->assertStringContainsString( 'Passkeys are turned off', $html );
	}

	public function test_other_user_without_passkeys(): void {
		magicauth_test_login_as( 1 );
		$html = self::section( $this->student );
		$this->assertMatchesRegularExpression( '/<p class="magicauth-pk-empty" data-magicauth-pk-empty>This user has no passkeys\.<\/p>/', $html );
		$this->assertMatchesRegularExpression( '/<button [^>]*data-magicauth-pk-remove-all hidden>/', $html );
	}

	/* ------------------------------------------------------------- T-PROFILE 2: no form, dialogs outside */

	public function test_section_has_no_form_no_dialog_no_reauth_view(): void {
		$this->enrol( $this->student, 'Laptop' );
		foreach ( [ 7 => 'own', 1 => 'other' ] as $actor => $label ) {
			ProfileSection::reset_for_tests();
			magicauth_test_login_as( $actor );
			$html = self::section( $this->student );
			$this->assertNotSame( '', $html, $label );
			$this->assert_form_safe( $html, $label );
			$this->assertStringNotContainsString( '<dialog', $html, $label );
			$this->assertStringNotContainsString( 'data-magicauth-pk-view="reauth"', $html, $label );
		}
	}

	public function test_render_dialogs_on_the_own_profile(): void {
		$this->enrol( $this->student, 'Laptop' );
		magicauth_test_login_as( 7 );
		self::section( $this->student );
		$html = self::dialogs();

		$this->assertStringContainsString( 'data-magicauth-pk-remove-dialog data-magicauth-pk-render="' . Assets::render_key() . '"', $html );
		$this->assertStringContainsString( 'Also sign out on all other devices', $html );
		$this->assertMatchesRegularExpression( '/<input type="checkbox" data-magicauth-pk-signout checked>/', $html );
		$this->assertStringContainsString( 'data-magicauth-pk-reauth-dialog data-magicauth-pk-render="' . Assets::render_key() . '"', $html );
		$this->assertStringContainsString( 'data-magicauth-pk-view="reauth"', $html );
		// Its own form; R7 is the only submit button.
		$this->assertSame( 1, substr_count( $html, '<form' ) );
		$this->assertMatchesRegularExpression( '/<form class="magicauth-pk-reauth__code" data-magicauth-pk-reauth-form novalidate hidden>/', $html );
		preg_match_all( '/<button\b[^>]*type="submit"[^>]*>/', $html, $m );
		$this->assertCount( 1, $m[0] );
		$this->assertStringContainsString( 'data-magicauth-pk-reauth-confirm', $m[0][0] );
		$this->assertStringNotContainsString( 'data-magicauth-pk-remove-all-dialog', $html );
		$this->assertStringContainsString( 'autocomplete="one-time-code"', $html );
	}

	/** r1-frontend-01: the section names its footer dialogs by id; section and dialogs carry the request's render key. */
	public function test_section_names_its_footer_dialogs_and_all_carry_the_render_key(): void {
		$this->enrol( $this->student, 'Laptop' );
		foreach ( [ 7 => [ 'remove', 'reauth' ], 1 => [ 'remove', 'remove-all' ] ] as $actor => $kinds ) {
			ProfileSection::reset_for_tests();
			magicauth_test_login_as( $actor );
			$section = self::section( $this->student );
			$dialogs = self::dialogs();
			$key     = Assets::render_key();
			$this->assertMatchesRegularExpression( '/^[0-9a-f]{32}$/', $key );
			$this->assertSame( 1, preg_match( '/<section [^>]*data-magicauth-pk-render="' . $key . '" data-magicauth-pk-dialogs="([^"]+)"/', $section, $m ), (string) $actor );
			$ids = explode( ' ', $m[1] );
			$this->assertCount( count( $kinds ), $ids );
			foreach ( $kinds as $i => $kind ) {
				$this->assertMatchesRegularExpression( '/^magicauth-pk-' . $kind . '-dialog-\d+$/', $ids[ $i ] );
				$this->assertSame( 1, preg_match( '/<dialog class="magicauth-pk-dialog" id="' . $ids[ $i ] . '" data-magicauth-pk-' . $kind . '-dialog data-magicauth-pk-render="' . $key . '"/', $dialogs ), $ids[ $i ] );
			}
		}
		// The shortcode keeps its dialogs inside the section and names none.
		Ceremony::sign_in( $this->student, 'link' );
		$html = ManageShortcode::render();
		$this->assertStringNotContainsString( 'data-magicauth-pk-dialogs', $html );
		$this->assertStringContainsString( 'data-magicauth-pk-render="' . Assets::render_key() . '"', $html );
	}

	public function test_render_dialogs_for_another_user(): void {
		$this->enrol( $this->student, 'Laptop' );
		$this->student->display_name = 'Ada <b>Lovelace</b>';
		magicauth_test_login_as( 1 );
		self::section( $this->student );
		$html = self::dialogs();
		$this->assertStringContainsString( 'data-magicauth-pk-remove-dialog', $html );
		$this->assertStringContainsString( 'data-magicauth-pk-remove-all-dialog', $html );
		$this->assertStringContainsString( 'Remove all passkeys for Ada &lt;b&gt;Lovelace&lt;/b&gt;? They can still sign in with their email.', $html );
		$this->assertStringContainsString( 'Also sign this user out everywhere', $html );
		$this->assertStringNotContainsString( 'data-magicauth-pk-reauth-dialog', $html, 'no step-up for another user' );
		$this->assertStringNotContainsString( '<form', $html );
	}

	public function test_render_dialogs_prints_nothing_without_a_section(): void {
		$this->assertSame( '', self::dialogs() );
	}

	public function test_shortcode_has_the_inline_step_up_without_a_form(): void {
		$this->enrol( $this->student, 'Laptop' );
		Ceremony::sign_in( $this->student, 'link' );
		$html = ManageShortcode::render();
		$this->assert_form_safe( $html, 'shortcode' );
		$this->assertStringContainsString( '<div class="magicauth-pk-reauth" data-magicauth-pk-view="reauth" hidden>', $html );
		$this->assertStringContainsString( 'data-magicauth-pk-remove-dialog data-magicauth-pk-render="' . Assets::render_key() . '"', $html );
		$this->assertStringNotContainsString( 'data-magicauth-pk-reauth-dialog', $html );
		$this->assertStringContainsString( '<noscript>', $html );
		$this->assertStringContainsString( 'Do not add a passkey on a device that other people also use.', $html );
		// No JS: the list is visible, every action control is hidden until the script runs (2.3, 8.13).
		foreach ( [ 'add', 'rename', 'remove', 'signout-others' ] as $control ) {
			$this->assertSame( 1, preg_match_all( '/<button [^>]*data-magicauth-pk-' . $control . '(?=[ >])[^>]*>/', $html, $m ), $control );
			$this->assertStringEndsWith( ' hidden>', $m[0][0], $control . ' hidden' );
		}
		$this->assertMatchesRegularExpression( '/data-magicauth-pk-nocreate hidden>/', $html );
	}

	public function test_list_markup_escapes_names_and_starts_names_with_the_visible_text(): void {
		$this->enrol( $this->student, '<img src=x onerror=alert(1)>Key' );
		$id = $this->enrol( $this->student, 'Laptop' );
		Ceremony::sign_in( $this->student, 'link' );
		$html = ManageShortcode::render();
		$this->assertStringNotContainsString( '<img', $html );
		$this->assertStringContainsString( '<bdi data-magicauth-pk-name>Laptop</bdi>', $html );
		$this->assertStringContainsString( '<li class="magicauth-pk-item" data-magicauth-pk-item data-id="' . $id . '">', $html );
		$this->assertMatchesRegularExpression( '/<button type="button" class="magicauth-pk-btn" data-magicauth-pk-rename hidden>Rename<span class="magicauth-pk-sr-only"> passkey <bdi>Laptop<\/bdi><\/span><\/button>/', $html );
		$this->assertMatchesRegularExpression( '/<button type="button" class="magicauth-pk-btn" data-magicauth-pk-remove hidden>Remove<span class="magicauth-pk-sr-only"> passkey <bdi>Laptop<\/bdi><\/span><\/button>/', $html );
		$this->assertDoesNotMatchRegularExpression( '/aria-label=/', $html, 'no aria-label on the item buttons' );
		$this->assertStringContainsString( 'Passkey ending in', $html );
		$this->assertStringContainsString( '<time datetime="', $html );
		$this->assertStringContainsString( 'Not used yet', $html );
	}

	public function test_blocked_passkey_offers_only_remove(): void {
		global $wpdb;
		$id = $this->enrol( $this->student, 'Key' );
		$wpdb->query( $wpdb->prepare( 'UPDATE ' . CredentialStore::table() . ' SET counter_anomaly_at = %s WHERE id = %d', '2026-09-30 09:00:00', $id ) );
		Ceremony::sign_in( $this->student, 'link' );
		$html = ManageShortcode::render();
		$this->assertStringContainsString( 'This passkey was blocked because it may have been copied.', $html );
		$this->assertStringContainsString( '>Blocked<', $html );
		$this->assertStringNotContainsString( 'data-magicauth-pk-rename', $html );
		$this->assertStringContainsString( 'data-magicauth-pk-remove', $html );
	}

	/* ------------------------------------------------------------- T-OFFER-5 */

	public function test_shortcode_logged_out_renders_nothing(): void {
		$this->assertSame( '', ManageShortcode::render() );
		self::module( false );
		$this->assertSame( '', ManageShortcode::render() );
		global $magicauth_test_state;
		$this->assertArrayNotHasKey( 'enqueued_scripts', $magicauth_test_state );
	}

	public function test_shortcode_module_off_signed_in_renders_nothing(): void {
		self::module( false );
		Ceremony::sign_in( $this->student, 'link' );
		$this->assertSame( '', ManageShortcode::render() );
	}

	public function test_shortcode_registered_always(): void {
		global $magicauth_test_state;
		self::module( false );
		Module::setup();
		$this->assertSame( [ ManageShortcode::class, 'render' ], $magicauth_test_state['shortcodes']['magicauth_passkeys'] ?? null );
	}

	/* ------------------------------------------------------------- T-PROFILE 3: no-store and assets */

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_shortcode_from_a_theme_template_enqueues_and_defines_donotcachepage(): void {
		Ceremony::site();
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => true ] );
		$user = Ceremony::user( 7 );
		Ceremony::sign_in( $user, 'link' );
		// A theme template renders the shortcode; the queried post does not contain it.
		self::page( 'Plain page content' );
		$this->assertFalse( ManageShortcode::is_management_page() );
		$this->assertFalse( defined( 'DONOTCACHEPAGE' ) );

		$html = ManageShortcode::render();

		$this->assertStringContainsString( 'data-magicauth-pk-manage', $html );
		$this->assertTrue( defined( 'DONOTCACHEPAGE' ) && DONOTCACHEPAGE );
		global $magicauth_test_state;
		$this->assertArrayHasKey( Assets::ACCOUNT_HANDLE, $magicauth_test_state['enqueued_scripts'] );
		$this->assertArrayHasKey( Assets::CORE_HANDLE, $magicauth_test_state['enqueued_scripts'] );
		$this->assertArrayHasKey( Assets::ACCOUNT_STYLE, $magicauth_test_state['enqueued_styles'] );
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_management_page_sends_no_store_from_template_redirect(): void {
		global $magicauth_test_state;
		Ceremony::site();
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => true ] );
		Ceremony::sign_in( Ceremony::user( 7 ), 'link' );
		self::page( 'Your account [magicauth_passkeys]' );
		Module::register();
		$this->assertSame( PHP_INT_MAX, has_action( 'template_redirect', [ \MagicAuth\Passkeys\Prompt::class, 'prepare_front' ] ) );

		do_action( 'template_redirect' );

		$this->assertTrue( defined( 'DONOTCACHEPAGE' ) && DONOTCACHEPAGE );
		$this->assertContains( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private', $magicauth_test_state['headers'] ?? [] );
	}

	public function test_prepare_front_does_nothing_elsewhere(): void {
		global $magicauth_test_state;
		// A password session: no prompt, no handle: no signals; only the management page would count.
		Ceremony::sign_in( $this->student, 'password' );
		self::page( 'No shortcode here' );
		\MagicAuth\Passkeys\Prompt::prepare_front();
		$this->assertSame( [], $magicauth_test_state['headers'] ?? [] );

		magicauth_test_login_as( 0 );
		self::page( '[magicauth_passkeys]' );
		\MagicAuth\Passkeys\Prompt::prepare_front();
		$this->assertSame( [], $magicauth_test_state['headers'] ?? [], 'logged out: cacheable, renders nothing' );
	}

	public function test_management_page_definition(): void {
		global $magicauth_test_state;
		$this->assertFalse( ManageShortcode::is_management_page(), 'no singular query' );
		self::page( 'text [magicauth_passkeys] text' );
		$this->assertTrue( ManageShortcode::is_management_page(), 'content holds the shortcode' );
		self::page( 'Account page', 42 );
		$this->assertFalse( ManageShortcode::is_management_page() );
		$magicauth_test_state['posts'][42] = [ 'status' => 'publish', 'type' => 'page' ];
		update_option(
			'magicauth_settings',
			[
				'passkeys_enabled'        => true,
				'passkeys_manage_page_id' => 42,
			]
		);
		$this->assertTrue( ManageShortcode::is_management_page(), 'the chosen page' );
		unset( $magicauth_test_state['queried'] );
		add_filter( 'magicauth_force_passkeys_manage_assets', '__return_true' );
		$this->assertTrue( ManageShortcode::is_management_page(), 'theme filter' );
		$magicauth_test_state['is_admin'] = true;
		$this->assertFalse( ManageShortcode::is_management_page(), 'never in wp-admin' );
	}

	public function test_front_end_account_assets_on_a_management_page(): void {
		global $magicauth_test_state;
		$this->enrol( $this->student );
		self::page( '[magicauth_passkeys]' );
		Assets::enqueue_front();
		$this->assertArrayNotHasKey( 'enqueued_scripts', $magicauth_test_state, 'logged out: no account script' );

		Ceremony::sign_in( $this->student, 'link' );
		Assets::enqueue_front();
		ManageShortcode::render(); // The shortcode asks again: still one config.
		$scripts = $magicauth_test_state['enqueued_scripts'];
		$this->assertSame( [ Assets::CORE_HANDLE ], $scripts[ Assets::ACCOUNT_HANDLE ][1] );
		$this->assertSame( [ 'in_footer' => true, 'strategy' => 'defer' ], $scripts[ Assets::ACCOUNT_HANDLE ][3] );
		$this->assertArrayNotHasKey( Assets::LOGIN_HANDLE, $scripts );
		$this->assertStringEndsWith( 'assets/css/magicauth-passkeys.css', $magicauth_test_state['enqueued_styles'][ Assets::ACCOUNT_STYLE ][0] );

		$config = self::config();
		$this->assertSame(
			[ 'ajaxUrl', 'rpId', 'nonce', 'manageUrl', 'account', 'prompt', 'signals', 'passkeys', 'reauth', 'actions', 'i18n', 'render' ],
			array_keys( $config )
		);
		$this->assertSame( wp_create_nonce( 'magicauth_passkeys' ), $config['nonce'] );
		$handle = CredentialStore::user_handle( 7, false );
		$this->assertSame( substr( hash( 'sha256', (string) $handle ), 0, 16 ), $config['account']['key'] );
		$this->assertSame( [ 'show' => false, 'hasPasskeys' => true ], $config['prompt'] );
		$this->assertCount( 1, $config['passkeys'] );
		$this->assertArrayHasKey( 'credential_id', $config['passkeys'][0] );
		$this->assertSame( $handle, $config['signals']['userId'] );
		$this->assertSame( [ 'email_code', 'passkey' ], $config['reauth']['methods'] );
		$this->assertSame( 'Add a passkey', $config['i18n']['M4'] );
	}

	public function test_no_account_assets_off_a_management_page_or_with_the_module_off(): void {
		global $magicauth_test_state;
		Ceremony::sign_in( $this->student, 'link' );
		self::page( 'Nothing here' );
		Assets::enqueue_front();
		$this->assertArrayNotHasKey( 'enqueued_scripts', $magicauth_test_state );

		self::module( false );
		self::page( '[magicauth_passkeys]' );
		Assets::enqueue_front();
		$this->assertArrayNotHasKey( 'enqueued_scripts', $magicauth_test_state );
	}

	public function test_admin_assets_own_profile(): void {
		global $magicauth_test_state;
		$this->enrol( $this->student );
		magicauth_test_login_as( 7 );
		Assets::enqueue_admin( 'index.php' );
		$this->assertArrayNotHasKey( 'enqueued_scripts', $magicauth_test_state );

		Assets::enqueue_admin( 'profile.php' );
		$config = self::config();
		$this->assertArrayHasKey( 'nonce', $config );
		$this->assertArrayHasKey( 'signals', $config );
	}

	public function test_admin_assets_for_another_user_carry_no_account_data(): void {
		global $magicauth_test_state;
		$this->enrol( $this->student );
		magicauth_test_login_as( 1 );
		$_GET['user_id'] = '7';
		Assets::enqueue_admin( 'user-edit.php' );
		$config = self::config();
		$this->assertSame( [ 'ajaxUrl', 'actions', 'i18n', 'render' ], array_keys( $config ) );
		$this->assertSame( Assets::render_key(), $config['render'] );
		$this->assertSame( 'magicauth_admin_passkey_revoke_all', $config['actions']['adminRevokeAll'] );
		$this->assertStringNotContainsString( (string) Ceremony::row( 1 )['credential_id'], (string) wp_json_encode( $config ) );

		magicauth_test_reset_state();
		Ceremony::site();
		magicauth_test_register_user( 3, 'user3@example.test', [ 'editor' ] );
		Ceremony::user( 7 );
		magicauth_test_login_as( 3 );
		$_GET['user_id'] = '7';
		Assets::enqueue_admin( 'user-edit.php' );
		$this->assertArrayNotHasKey( 'enqueued_scripts', $magicauth_test_state, 'no section, no assets' );
	}

	public function test_admin_hooks_registered_whatever_the_toggle(): void {
		global $magicauth_test_state;
		self::module( false );
		$magicauth_test_state['is_admin'] = true;
		Module::setup();
		$this->assertSame( 9, has_action( 'show_user_profile', [ ProfileSection::class, 'render' ] ) );
		$this->assertSame( 9, has_action( 'edit_user_profile', [ ProfileSection::class, 'render' ] ) );
		$this->assertSame( 20, has_action( 'admin_footer', [ ProfileSection::class, 'render_dialogs' ] ) );
		$this->assertSame( 20, has_action( 'admin_enqueue_scripts', [ Assets::class, 'enqueue_admin' ] ) );
	}

	/* ------------------------------------------------------------- A6, A7 */

	public function test_disable_checkbox_labels_name_passkeys(): void {
		magicauth_test_register_user( 1, 'user1@example.test', [ 'administrator' ] );
		magicauth_test_login_as( 7 );
		ob_start();
		\MagicAuth\Admin\UserProfile::render_fields( $this->student );
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'Disable MagicAuth sign-in for this user (email link, code and passkeys)', $html );
		$this->assertStringContainsString( 'Saving with this checked cancels all outstanding sign-in links for this user and blocks passkey sign-in. Passkeys are kept and work again when you clear this option.', $html );
	}

	/* ------------------------------------------------------------- template override */

	public function test_theme_can_override_the_management_template(): void {
		global $magicauth_test_state;
		$dir = sys_get_temp_dir() . '/magicauth-theme-' . bin2hex( random_bytes( 4 ) );
		mkdir( $dir . '/magicauth', 0777, true );
		file_put_contents( $dir . '/magicauth/passkeys-manage.php', '<?php echo "THEME LIST " . count( $items ) . " " . esc_html( $strings["M1"] );' );
		$magicauth_test_state['stylesheet_directory'] = $dir;
		try {
			$this->enrol( $this->student );
			Ceremony::sign_in( $this->student, 'link' );
			$this->assertSame( 'THEME LIST 1 Passkeys', ManageShortcode::render() );
		} finally {
			unlink( $dir . '/magicauth/passkeys-manage.php' );
			rmdir( $dir . '/magicauth' );
			rmdir( $dir );
		}
	}

	public function test_manage_strings_filter_replaces_known_keys_only(): void {
		add_filter(
			'magicauth_passkey_manage_strings',
			static function ( $strings ) {
				$strings['M4']    = 'Voeg toe';
				$strings['M1']    = 42;
				$strings['EXTRA'] = 'x';
				return $strings;
			}
		);
		$strings = ManageShortcode::strings();
		$this->assertSame( 'Voeg toe', $strings['M4'] );
		$this->assertSame( 'Passkeys', $strings['M1'], 'non-string ignored' );
		$this->assertArrayNotHasKey( 'EXTRA', $strings );
	}

	/* ------------------------------------------------------------- stylesheet (8.10) */

	public function test_stylesheet_state_rules(): void {
		$css = (string) preg_replace( '#/\*.*?\*/#s', '', (string) file_get_contents( MAGICAUTH_DIR . 'assets/css/magicauth-passkeys.css' ) );
		$this->assertStringContainsString( "[data-magicauth-passkey-root][hidden],\n[data-magicauth-passkey-signin][hidden],\n[data-magicauth-pk-add][hidden],\n[data-magicauth-pk-view][hidden] {\n\tdisplay: none !important;\n}", $css );
		$this->assertSame( 1, preg_match_all( '/:[^;{}]*!important/', $css ), 'the single justified !important' );
		// The scoped [hidden] rule ties with .magicauth-pk-manage .magicauth-pk-btn (0,2,0): it must come after every such rule.
		$rule   = ".magicauth-pk-manage [hidden],\n.magicauth-pk-dialog [hidden] {\n\tdisplay: none;\n}";
		$hidden = strpos( $css, $rule );
		$media  = strpos( $css, '@media' );
		$this->assertIsInt( $hidden );
		$this->assertIsInt( $media );
		$this->assertGreaterThan( (int) strpos( $css, '.magicauth-pk-manage .magicauth-pk-btn,' ), $hidden, 'after the button rules' );
		$this->assertStringNotContainsString( 'display:', substr( $css, $hidden + strlen( $rule ), $media - $hidden - strlen( $rule ) ), 'no display rule after it' );
		$this->assertStringContainsString( 'background: var(--magicauth-pk-backdrop, rgb(0 0 0 / 0.5));', $css );
		$this->assertStringContainsString( '@media (forced-colors: active)', $css );
		$this->assertStringContainsString( '@media (prefers-reduced-motion: reduce)', $css );
		$this->assertDoesNotMatchRegularExpression( '/^\s*--magicauth-[a-z-]+\s*:/m', $css, 'tokens are read, never redeclared' );
		$this->assertDoesNotMatchRegularExpression( '/(margin|padding)-(left|right)|\b(left|right)\s*:/', $css, 'logical properties only' );
	}
}
