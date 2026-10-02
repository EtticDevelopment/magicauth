<?php
/**
 * T-PROMPT (SPEC 2.1, 2.6 rows 7 and 14, 5.3, 6.8, 6.11, 8.5, 14.1, build
 * step 14): the eligibility matrix (one case per condition), the check
 * order, the decision on template_redirect / current_screen and the commit in
 * the footer, the cadence of the four choices through the endpoint, the
 * shared-device cookie, the account key and the prompt template.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Passkeys\Assets;
use MagicAuth\Passkeys\CredentialStore;
use MagicAuth\Passkeys\Freshness;
use MagicAuth\Passkeys\Module;
use MagicAuth\Passkeys\Prompt;
use MagicAuth\Passkeys\SessionState;
use MagicAuth\Tests\Stubs\RedirectSent;
use MagicAuth\Tests\Support\Ceremony;
use MagicAuth\Tests\Support\SoftAuthenticator;
use PHPUnit\Framework\TestCase;
use WP_User;

final class PromptTest extends TestCase {

	private const DAY = 86400;

	private WP_User $user;

	/** @var array<string,mixed> */
	private array $server = [];

	protected function setUp(): void {
		$this->server = $_SERVER;
		Ceremony::site();
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => true ] );
		Module::reset_for_tests();
		$this->user = Ceremony::user( 7 );
		Ceremony::user( 8 );
		// A link sign-in a minute ago, on a plain front-end page.
		Ceremony::sign_in( $this->user, 'link', Ceremony::NOW - 60 );
	}

	protected function tearDown(): void {
		global $wpdb, $post;
		$post     = null;
		$_SERVER  = $this->server;
		$_POST    = [];
		$_REQUEST = [];
		$_COOKIE  = [];
		$wpdb->show_errors( false );
		magicauth_test_reset_state();
	}

	/* ------------------------------------------------------------- helpers */

	private function enrol( WP_User $user ): int {
		return Ceremony::enrol( new SoftAuthenticator( 'ES256' ), $user );
	}

	/** @return array<string,mixed>|null The current session's state row. */
	private static function state(): ?array {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . SessionState::table() . ' WHERE session_hash = %s', Freshness::session_hash() ), ARRAY_A );
		return is_array( $row ) ? $row : null;
	}

	private static function prompt_done(): int {
		return (int) ( self::state()['prompt_done'] ?? 0 );
	}

	private static function page( string $content, int $id = 50 ): void {
		global $post, $magicauth_test_state;
		$post                            = new \WP_Post( $content );
		$magicauth_test_state['queried'] = [
			'id'   => $id,
			'type' => 'page',
			'post' => $post,
		];
	}

	private static function footer(): string {
		ob_start();
		Prompt::render_footer();
		return (string) ob_get_clean();
	}

	/** A new request in the same session: nothing decided yet, nothing enqueued. */
	private static function next_request(): void {
		global $magicauth_test_state;
		Prompt::reset_for_tests();
		Assets::reset_for_tests();
		unset( $magicauth_test_state['enqueued_scripts'], $magicauth_test_state['enqueued_styles'], $magicauth_test_state['inline_scripts'] );
		$magicauth_test_state['headers'] = [];
	}

	/**
	 * @param array<string,mixed> $fields
	 * @return array{status:?int,success:bool,data:array<string,mixed>,body:string}
	 */
	private static function choose( string $choice, array $fields = [] ): array {
		Ceremony::account_post( [ 'choice' => $choice ] + $fields );
		return Ceremony::call( 'prompt_choice' );
	}

	/** @return array{declines:int,next_at:int} */
	private static function cadence(): array {
		return Prompt::cadence( 7 );
	}

	private function dashboard( string $id = 'dashboard' ): void {
		global $magicauth_test_state;
		$screen                           = new \WP_Screen();
		$screen->id                       = $id;
		$magicauth_test_state['screen']   = $screen;
		$magicauth_test_state['is_admin'] = true;
	}

	/* ------------------------------------------------------------- eligibility, one condition at a time */

	public function test_link_and_code_sessions_are_eligible(): void {
		$this->assertTrue( Prompt::eligible( $this->user ), 'link' );
		Ceremony::sign_in( $this->user, 'code' );
		$this->assertTrue( Prompt::eligible( $this->user ), 'code' );
	}

	/** 1: module on, prompt setting on, available. */
	public function test_1_module_and_setting(): void {
		update_option(
			'magicauth_settings',
			[
				'passkeys_enabled' => true,
				'passkeys_prompt'  => false,
			]
		);
		Module::reset_for_tests();
		$this->assertFalse( Prompt::eligible( $this->user ), 'passkeys_prompt off' );

		update_option( 'magicauth_settings', [ 'passkeys_enabled' => false ] );
		Module::reset_for_tests();
		$this->assertFalse( Prompt::eligible( $this->user ), 'module off' );

		update_option( 'magicauth_settings', [ 'passkeys_enabled' => true ] );
		update_option( 'magicauth_db_version', 1 );
		Module::reset_for_tests();
		$this->assertFalse( Prompt::eligible( $this->user ), 'not available (S8f)' );
	}

	/** @return array<string,array{string}> */
	public static function non_html_requests(): array {
		return [
			'json'      => [ 'wp_is_json_request' ],
			'feed'      => [ 'is_feed' ],
			'embed'     => [ 'is_embed' ],
			'customize' => [ 'is_customize_preview' ],
			'robots'    => [ 'is_robots' ],
		];
	}

	/**
	 * 2: front-end HTML pages only.
	 *
	 * @dataProvider non_html_requests
	 */
	public function test_2_not_on_other_front_end_requests( string $conditional ): void {
		global $magicauth_test_state;
		$magicauth_test_state['request'][ $conditional ] = true;
		$this->assertFalse( Prompt::eligible( $this->user ) );
	}

	public function test_2_not_during_ajax(): void {
		global $magicauth_test_state;
		$magicauth_test_state['doing_ajax'] = true;
		$this->assertFalse( Prompt::eligible( $this->user ) );
	}

	public function test_2_not_on_a_management_page(): void {
		self::page( 'Your account [magicauth_passkeys]' );
		$this->assertFalse( Prompt::eligible( $this->user ) );
		self::page( 'An ordinary lesson' );
		$this->assertTrue( Prompt::eligible( $this->user ) );
	}

	public function test_2_in_wp_admin_only_the_dashboard(): void {
		$this->dashboard( 'profile' );
		$this->assertFalse( Prompt::eligible( $this->user ), 'profile.php' );
		$this->dashboard( 'edit-post' );
		$this->assertFalse( Prompt::eligible( $this->user ) );
		$this->dashboard();
		$this->assertTrue( Prompt::eligible( $this->user ), 'dashboard' );
		global $magicauth_test_state;
		unset( $magicauth_test_state['screen'] );
		$this->assertFalse( Prompt::eligible( $this->user ), 'no screen' );
	}

	/** 3: the theme escape hatch, with the user. */
	public function test_3_filter(): void {
		$seen = null;
		add_filter(
			'magicauth_passkey_prompt_eligible',
			static function ( $eligible, $user ) use ( &$seen ) {
				$seen = [ $eligible, $user->ID ];
				return false;
			},
			10,
			2
		);
		$this->assertFalse( Prompt::eligible( $this->user ) );
		$this->assertSame( [ true, 7 ], $seen );
	}

	/** 4: logged in as this user, not disabled. */
	public function test_4_logged_in_and_not_disabled(): void {
		update_user_meta( 7, 'magicauth_disabled', 1 );
		$this->assertFalse( Prompt::eligible( $this->user ), 'disabled' );
		delete_user_meta( 7, 'magicauth_disabled' );
		$this->assertTrue( Prompt::eligible( $this->user ) );

		magicauth_test_login_as( 8 );
		$this->assertFalse( Prompt::eligible( $this->user ), 'another user is signed in' );
		magicauth_test_login_as( 0 );
		$this->assertFalse( Prompt::eligible( $this->user ), 'logged out' );
	}

	/** @return array<string,array{?string}> */
	public static function other_methods(): array {
		return [
			'password'   => [ 'password' ],
			'admin_link' => [ 'admin_link' ],
			'reset'      => [ 'reset' ],
			'passkey'    => [ 'passkey' ],
			'unstamped'  => [ null ],
			'unknown'    => [ 'sso' ],
		];
	}

	/**
	 * 5: only link and code sessions by default.
	 *
	 * @dataProvider other_methods
	 */
	public function test_5_other_sign_ins_never_get_the_prompt( ?string $method ): void {
		Ceremony::sign_in( $this->user, $method );
		$this->assertFalse( Prompt::eligible( $this->user ) );
	}

	/** 5: admin_link and password are never eligible, even when the filter adds them. */
	public function test_5_filter_cannot_add_admin_link_or_password(): void {
		add_filter( 'magicauth_passkey_prompt_methods', static fn() => [ 'link', 'code', 'admin_link', 'password', 'sso' ] );
		foreach ( [ 'admin_link', 'password', 'sso' ] as $method ) {
			Ceremony::sign_in( $this->user, $method );
			$this->assertFalse( Prompt::eligible( $this->user ), $method );
		}
		Ceremony::sign_in( $this->user, 'link' );
		$this->assertTrue( Prompt::eligible( $this->user ) );
	}

	public function test_5_filter_can_narrow_or_widen_within_fresh_methods(): void {
		add_filter( 'magicauth_passkey_prompt_methods', static fn() => [ 'code', 'passkey' ] );
		$this->assertFalse( Prompt::eligible( $this->user ), 'link removed' );
		Ceremony::sign_in( $this->user, 'passkey' );
		$this->assertTrue( Prompt::eligible( $this->user ), 'passkey added' );

		remove_all_filters_for( 'magicauth_passkey_prompt_methods' );
		add_filter( 'magicauth_passkey_prompt_methods', static fn() => 'link' );
		Ceremony::sign_in( $this->user, 'link' );
		$this->assertFalse( Prompt::eligible( $this->user ), 'not an array: nothing' );
	}

	public function test_5_no_core_session_record(): void {
		\WP_Session_Tokens::get_instance( 7 )->destroy_all();
		$this->assertFalse( Prompt::eligible( $this->user ) );
	}

	/** 6: once per session; no row yet counts as not shown, a failed read does not. */
	public function test_6_prompt_done(): void {
		$this->assertNull( self::state() );
		$this->assertTrue( Prompt::eligible( $this->user ), 'no row yet' );
		$this->assertTrue( SessionState::set( 'signals_at', 5 ) );
		$this->assertTrue( Prompt::eligible( $this->user ), 'row with prompt_done 0' );
		$this->assertTrue( SessionState::set( 'prompt_done', 1 ) );
		$this->assertFalse( Prompt::eligible( $this->user ), 'shown in this session' );

		Ceremony::sign_in( $this->user, 'link' );
		$this->assertTrue( Prompt::eligible( $this->user ), 'a new session' );
	}

	public function test_6_state_read_error_is_not_eligible(): void {
		global $wpdb;
		$wpdb->show_errors( true );
		$wpdb->fail_next_query( 'FROM wp_magicauth_passkey_sessions WHERE session_hash' );
		ob_start();
		$eligible = Prompt::eligible( $this->user );
		$this->assertSame( '', ob_get_clean() );
		$this->assertFalse( $eligible );
	}

	/** 7: within 1800 s of the sign-in. */
	public function test_7_window(): void {
		Ceremony::sign_in( $this->user, 'link', Ceremony::NOW - 1800 );
		$this->assertTrue( Prompt::eligible( $this->user ), '1800 s' );
		Ceremony::sign_in( $this->user, 'link', Ceremony::NOW - 1801 );
		$this->assertFalse( Prompt::eligible( $this->user ), '1801 s' );
	}

	/** 8: the shared-device cookie, any value. */
	public function test_8_shared_cookie(): void {
		$_COOKIE['magicauth_pk_shared'] = '1';
		$this->assertFalse( Prompt::eligible( $this->user ) );
		$_COOKIE['magicauth_pk_shared'] = '';
		$this->assertFalse( Prompt::eligible( $this->user ) );
	}

	/** 9: declines < 3 and next_at <= now. */
	public function test_9_cadence(): void {
		$cases = [
			[ [ 'declines' => 2, 'next_at' => Ceremony::NOW ], true ],
			[ [ 'declines' => 2, 'next_at' => Ceremony::NOW + 1 ], false ],
			[ [ 'declines' => 3, 'next_at' => 0 ], false ],
			[ [ 'declines' => 0, 'next_at' => Ceremony::NOW + 7 * self::DAY ], false ],
			[ 'garbage', true ],
			[ [ 'declines' => 'x' ], true ],
		];
		foreach ( $cases as [ $meta, $expected ] ) {
			update_user_meta( 7, 'magicauth_passkey_prompt', $meta );
			$this->assertSame( $expected, Prompt::eligible( $this->user ), (string) wp_json_encode( $meta ) );
		}
	}

	/** 10: below the per-user maximum for the current RP ID; a failed count is not below. */
	public function test_10_count(): void {
		global $wpdb;
		$this->enrol( $this->user );
		$this->assertTrue( Prompt::eligible( $this->user ), '1 of 10' );

		add_filter( 'magicauth_passkey_max_per_user', static fn() => 1 );
		$this->assertFalse( Prompt::eligible( $this->user ), '1 of 1' );

		// A passkey for another RP ID does not count.
		$wpdb->query( $wpdb->prepare( 'UPDATE ' . CredentialStore::table() . ' SET rp_id = %s WHERE user_id = %d', 'old.example', 7 ) );
		$this->assertTrue( Prompt::eligible( $this->user ), '0 for this RP ID' );

		$wpdb->show_errors( true );
		$wpdb->fail_next_query( 'SELECT COUNT(*) FROM wp_magicauth_passkeys' );
		ob_start();
		$eligible = Prompt::eligible( $this->user );
		$this->assertSame( '', ob_get_clean() );
		$this->assertFalse( $eligible, 'count query failed' );
	}

	/** Check order: a failed check 3 stops before the state row and the COUNT query. */
	public function test_check_order_stops_before_the_queries(): void {
		global $wpdb;
		$wpdb->query_log = [];
		$this->assertTrue( Prompt::eligible( $this->user ) );
		$all = implode( "\n", $wpdb->query_log );
		$this->assertStringContainsString( 'COUNT(*) FROM wp_magicauth_passkeys', $all, 'the passing run counts' );
		$this->assertStringContainsString( 'wp_magicauth_passkey_sessions', $all );

		add_filter( 'magicauth_passkey_prompt_eligible', '__return_false' );
		$wpdb->query_log = [];
		$this->assertFalse( Prompt::eligible( $this->user ) );
		$this->assertSame( [], $wpdb->query_log, 'no query after check 3 failed' );

		// Check 9 fails: the state row was read (check 6), the COUNT never ran.
		remove_all_filters_for( 'magicauth_passkey_prompt_eligible' );
		update_user_meta( 7, 'magicauth_passkey_prompt', [ 'declines' => 3, 'next_at' => 0 ] );
		$wpdb->query_log = [];
		$this->assertFalse( Prompt::eligible( $this->user ) );
		$this->assertStringNotContainsString( 'COUNT(*)', implode( "\n", $wpdb->query_log ) );
	}

	/* ------------------------------------------------------------- decide, then commit in the footer */

	public function test_decision_prepares_and_the_footer_commits(): void {
		global $magicauth_test_state;
		Prompt::prepare_front();

		$this->assertSame( 0, self::prompt_done(), 'not written at the decision' );
		$this->assertContains( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private', $magicauth_test_state['headers'] ?? [] );
		$this->assertArrayHasKey( Assets::ACCOUNT_HANDLE, $magicauth_test_state['enqueued_scripts'] ?? [] );
		$this->assertArrayHasKey( Assets::CORE_HANDLE, $magicauth_test_state['enqueued_scripts'] ?? [] );
		$this->assertArrayHasKey( Assets::ACCOUNT_STYLE, $magicauth_test_state['enqueued_styles'] ?? [] );
		$config = self::config();
		$this->assertTrue( $config['prompt']['show'] );
		$this->assertSame( 'Create a passkey', $config['i18n']['P4'] );
		$this->assertSame( 'magicauth_passkey_prompt', $config['actions']['promptChoice'] );

		$html = self::footer();
		$this->assertStringContainsString( 'data-magicauth-pk-prompt', $html );
		$this->assertSame( 1, self::prompt_done(), 'committed after printing' );
		$this->assertSame( '', self::footer(), 'once per request' );

		self::next_request();
		Prompt::prepare_front();
		$this->assertSame( '', self::footer(), 'never again in this session' );
		$this->assertArrayNotHasKey( Assets::ACCOUNT_HANDLE, $magicauth_test_state['enqueued_scripts'] ?? [] );
	}

	public function test_redirect_after_the_decision_consumes_nothing(): void {
		global $magicauth_test_state;
		Prompt::prepare_front();
		$magicauth_test_state['redirect_throws'] = true;
		try {
			wp_redirect( 'https://academy.example.com/lesson/2/' );
			$this->fail( 'redirect' );
		} catch ( RedirectSent $sent ) {
			unset( $sent ); // exit: no footer.
		}
		$this->assertSame( 0, self::prompt_done() );

		self::next_request();
		$magicauth_test_state['redirect_throws'] = false;
		Prompt::prepare_front();
		$this->assertStringContainsString( 'data-magicauth-pk-prompt', self::footer(), 'the next full page still shows it' );
		$this->assertSame( 1, self::prompt_done() );
	}

	public function test_request_without_wp_footer_leaves_it_unconsumed(): void {
		Prompt::prepare_front();
		do_action( 'shutdown' );
		$this->assertSame( 0, self::prompt_done() );
		$this->assertNull( self::state(), 'nothing written at all' );
		self::next_request();
		$this->assertTrue( Prompt::eligible( $this->user ) );
	}

	public function test_no_decision_prints_nothing(): void {
		$this->assertSame( '', self::footer() );
		Ceremony::sign_in( $this->user, 'password' );
		Prompt::prepare_front();
		$this->assertSame( '', self::footer() );
		$this->assertSame( 0, self::prompt_done() );
	}

	public function test_footer_for_another_user_prints_nothing(): void {
		Prompt::prepare_front();
		magicauth_test_login_as( 8 );
		$this->assertSame( '', self::footer() );
	}

	public function test_nothing_for_logged_out_or_module_off_or_wp_admin(): void {
		global $magicauth_test_state;
		magicauth_test_login_as( 0 );
		Prompt::prepare_front();
		$this->assertSame( '', self::footer() );
		$this->assertSame( [], $magicauth_test_state['headers'] ?? [], 'logged out: cacheable' );

		Ceremony::sign_in( $this->user, 'link' );
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => false ] );
		Module::reset_for_tests();
		Prompt::prepare_front();
		$this->assertSame( '', self::footer() );

		Ceremony::enable_module();
		$this->dashboard();
		Prompt::prepare_front();
		$this->assertSame( '', self::footer(), 'prepare_front never runs in wp-admin' );
		$this->assertSame( [], $magicauth_test_state['headers'] ?? [] );
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_decision_defines_donotcachepage(): void {
		Ceremony::site();
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => true ] );
		$user = Ceremony::user( 7 );
		Ceremony::sign_in( $user, 'link' );
		$this->assertFalse( defined( 'DONOTCACHEPAGE' ) );
		Prompt::prepare_front();
		$this->assertTrue( defined( 'DONOTCACHEPAGE' ) && DONOTCACHEPAGE );
	}

	public function test_management_page_gets_no_store_without_a_prompt(): void {
		global $magicauth_test_state;
		self::page( 'Account [magicauth_passkeys]' );
		Prompt::prepare_front();
		$this->assertContains( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private', $magicauth_test_state['headers'] ?? [] );
		$this->assertSame( '', self::footer(), 'no prompt on the management page' );
		$this->assertSame( 0, self::prompt_done() );
	}

	public function test_dashboard_prompt_on_current_screen_and_admin_footer(): void {
		global $magicauth_test_state;
		// A handle and a passkey, so the payload exists and signals: null is the decision's.
		$this->enrol( $this->user );
		$this->assertNotNull( \MagicAuth\Passkeys\Signals::payload( $this->user ) );
		$this->dashboard();
		Prompt::prepare_admin( $magicauth_test_state['screen'] );
		$this->assertArrayHasKey( Assets::ACCOUNT_HANDLE, $magicauth_test_state['enqueued_scripts'] ?? [] );
		$this->assertContains( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private', $magicauth_test_state['headers'] ?? [] );
		$this->assertSame( 0, self::prompt_done() );
		$this->assertTrue( self::config()['prompt']['show'] );
		$this->assertNull( self::config()['signals'], 'the dashboard carries no session signals' );

		$this->assertStringContainsString( 'data-magicauth-pk-prompt', self::footer() );
		$this->assertSame( 1, self::prompt_done() );

		self::next_request();
		$this->dashboard( 'users' );
		Ceremony::sign_in( $this->user, 'code' );
		Prompt::prepare_admin();
		$this->assertSame( '', self::footer(), 'other screens: nothing' );
		$this->assertArrayNotHasKey( 'enqueued_scripts', $magicauth_test_state );
	}

	/* ------------------------------------------------------------- hooks */

	public function test_hooks_registered_only_while_enabled_and_never_nopriv(): void {
		Module::register();
		$this->assertSame( 10, has_action( 'wp_ajax_magicauth_passkey_prompt', [ \MagicAuth\Passkeys\AccountEndpoints::class, 'prompt_choice' ] ) );
		$this->assertFalse( has_action( 'wp_ajax_nopriv_magicauth_passkey_prompt' ), 'nopriv dismiss not registered' );
		$this->assertSame( PHP_INT_MAX, has_action( 'template_redirect', [ Prompt::class, 'prepare_front' ] ) );
		$this->assertSame( 20, has_action( 'wp_footer', [ Prompt::class, 'render_footer' ] ) );
		$this->assertSame( 20, has_action( 'admin_footer', [ Prompt::class, 'render_footer' ] ) );
		$this->assertSame( 10, has_action( 'current_screen', [ Prompt::class, 'prepare_admin' ] ) );
		$this->assertFalse( has_action( 'template_redirect', [ \MagicAuth\Passkeys\ManageShortcode::class, 'prepare_front' ] ), 'folded into Prompt' );
	}

	/* ------------------------------------------------------------- cadence through the endpoint */

	public function test_later_30_then_90_days_then_stop(): void {
		$this->assertSame( 200, self::choose( 'later' )['status'] );
		$this->assertSame( [ 'declines' => 1, 'next_at' => Ceremony::NOW + 30 * self::DAY ], self::cadence() );

		$this->assertSame( 200, self::choose( 'later' )['status'] );
		$this->assertSame( [ 'declines' => 2, 'next_at' => Ceremony::NOW + 90 * self::DAY ], self::cadence() );

		// After next_at the prompt comes back for the third time.
		\MagicAuth\Passkeys\Clock::set_for_tests( Ceremony::NOW + 91 * self::DAY );
		Ceremony::sign_in( $this->user, 'link' );
		$this->assertTrue( Prompt::eligible( $this->user ) );

		$this->assertSame( 200, self::choose( 'later' )['status'] );
		$this->assertSame( 3, self::cadence()['declines'] );
		\MagicAuth\Passkeys\Clock::set_for_tests( Ceremony::NOW + 3650 * self::DAY );
		Ceremony::sign_in( $this->user, 'link' );
		$this->assertFalse( Prompt::eligible( $this->user ), 'stopped for this account' );
	}

	public function test_dismiss_adds_7_days_without_a_decline(): void {
		$this->assertSame( 200, self::choose( 'dismiss' )['status'] );
		$this->assertSame( [ 'declines' => 0, 'next_at' => Ceremony::NOW + 7 * self::DAY ], self::cadence() );

		// Never shortens a later wait.
		update_user_meta( 7, 'magicauth_passkey_prompt', [ 'declines' => 1, 'next_at' => Ceremony::NOW + 30 * self::DAY ] );
		self::choose( 'dismiss' );
		$this->assertSame( [ 'declines' => 1, 'next_at' => Ceremony::NOW + 30 * self::DAY ], self::cadence() );

		\MagicAuth\Passkeys\Clock::set_for_tests( Ceremony::NOW + 30 * self::DAY );
		Ceremony::sign_in( $this->user, 'link' );
		$this->assertTrue( Prompt::eligible( $this->user ) );
	}

	public function test_failed_adds_30_days_without_a_decline(): void {
		$this->assertSame( 200, self::choose( 'failed' )['status'] );
		$this->assertSame( [ 'declines' => 0, 'next_at' => Ceremony::NOW + 30 * self::DAY ], self::cadence() );
	}

	public function test_three_failed_then_later_still_allows_the_prompt_after_next_at(): void {
		for ( $i = 0; $i < 3; $i++ ) {
			self::choose( 'failed' );
		}
		$this->assertSame( [ 'declines' => 0, 'next_at' => Ceremony::NOW + 30 * self::DAY ], self::cadence() );
		self::choose( 'later' );
		$this->assertSame( [ 'declines' => 1, 'next_at' => Ceremony::NOW + 30 * self::DAY ], self::cadence() );

		\MagicAuth\Passkeys\Clock::set_for_tests( Ceremony::NOW + 30 * self::DAY );
		Ceremony::sign_in( $this->user, 'code' );
		$this->assertTrue( Prompt::eligible( $this->user ) );
	}

	public function test_cadence_is_per_account(): void {
		self::choose( 'later' );
		Ceremony::sign_in( Ceremony::user( 8 ), 'link' );
		$this->assertSame( [ 'declines' => 0, 'next_at' => 0 ], Prompt::cadence( 8 ) );
		$this->assertTrue( Prompt::eligible( get_userdata( 8 ) ) );
	}

	public function test_registration_resets_the_cadence(): void {
		update_user_meta( 7, 'magicauth_passkey_prompt', [ 'declines' => 2, 'next_at' => Ceremony::NOW + 90 * self::DAY ] );
		$auth = new SoftAuthenticator( 'ES256' );
		Ceremony::account_post( [] );
		$options = Ceremony::call( 'register_options' );
		$this->assertSame( 200, $options['status'] );
		Ceremony::account_post( [ 'credential' => Ceremony::encode( $auth->register( $options['data']['publicKey'], Ceremony::ORIGIN ) ) ] );
		$this->assertSame( 200, Ceremony::call( 'register' )['status'] );
		$this->assertSame( [ 'declines' => 0, 'next_at' => 0 ], self::cadence() );
	}

	/* ------------------------------------------------------------- shared device */

	public function test_device_sets_the_shared_cookie_and_leaves_the_account_alone(): void {
		global $magicauth_test_state;
		$this->assertSame( 200, self::choose( 'device' )['status'] );
		$this->assertSame( '', get_user_meta( 7, 'magicauth_passkey_prompt', true ) );
		$cookies = $magicauth_test_state['cookies'] ?? [];
		$this->assertCount( 1, $cookies );
		$this->assertSame(
			[
				'name'     => 'magicauth_pk_shared',
				'value'    => '1',
				'max_age'  => 31536000,
				'expires'  => Ceremony::NOW + 31536000,
				'path'     => '/',
				'domain'   => '',
				'secure'   => true,
				'httponly' => true,
				'samesite' => 'Lax',
			],
			$cookies[0]
		);

		// http://localhost (S8d allows it): no Secure attribute.
		$magicauth_test_state['is_ssl'] = false;
		Prompt::set_shared_cookie();
		$this->assertFalse( $magicauth_test_state['cookies'][1]['secure'], 'Secure only on https' );
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_device_cookie_honours_cookie_domain(): void {
		global $magicauth_test_state;
		define( 'COOKIE_DOMAIN', '.example.com' );
		Prompt::set_shared_cookie();
		$this->assertSame( '.example.com', $magicauth_test_state['cookies'][0]['domain'] );
	}

	public function test_shared_cookie_suppresses_the_prompt_for_a_second_user(): void {
		self::choose( 'device' );
		$_COOKIE['magicauth_pk_shared'] = '1'; // The browser sends it back.
		$second                         = get_userdata( 8 );
		$this->assertInstanceOf( WP_User::class, $second );
		Ceremony::sign_in( $second, 'link' );
		$_COOKIE['magicauth_pk_shared'] = '1';
		$this->assertFalse( Prompt::eligible( $second ) );
		Prompt::prepare_front();
		$this->assertSame( '', self::footer(), 'no markup for a shared device' );
	}

	/* ------------------------------------------------------------- account key, template, strings */

	public function test_account_key_is_the_first_16_hex_of_sha256_of_the_handle(): void {
		$this->enrol( $this->user );
		$handle = (string) CredentialStore::user_handle( 7, false );
		$this->assertSame( substr( hash( 'sha256', $handle ), 0, 16 ), Assets::account_key( $this->user ) );
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{16}$/', Assets::account_key( $this->user ) );
		$this->assertSame( '', Assets::account_key( get_userdata( 8 ) ), 'no handle, no key' );

		Prompt::prepare_front();
		$this->assertSame( Assets::account_key( $this->user ), self::config()['account']['key'] );
		$this->assertStringNotContainsString( $handle, (string) wp_json_encode( self::config()['account'] ) );
	}

	public function test_template_markup(): void {
		Prompt::prepare_front();
		$html = self::footer();

		$this->assertSame( 1, preg_match( '/<dialog [^>]*data-magicauth-pk-prompt[^>]*>/', $html, $m ) );
		$this->assertStringContainsString( 'aria-labelledby="magicauth-pk-title"', $m[0] );
		$this->assertStringContainsString( 'aria-describedby="magicauth-pk-desc"', $m[0] );
		$this->assertStringNotContainsString( ' open', $m[0], 'closed: JS calls showModal()' );
		$this->assertStringContainsString( '>Sign in faster next time</h2>', $html, 'P1 without passkeys' );
		$this->assertStringContainsString( 'Passkey created. Next time, choose &quot;Sign in with a passkey&quot;.', $html, 'P8 names L1' );
		$this->assertStringContainsString( 'aria-label="Close"', $html );

		// One form: the step-up code form, with R7 its only submit button; no method=dialog.
		$this->assertSame( 1, substr_count( $html, '<form' ) );
		$this->assertStringNotContainsString( 'method="dialog"', $html );
		$this->assertSame( 1, preg_match( '/<form [^>]*data-magicauth-pk-reauth-form[^>]*>/', $html ) );
		preg_match_all( '/<button\b[^>]*>/', $html, $buttons );
		$submit = array_values( array_filter( $buttons[0], static fn( $b ) => false === strpos( $b, 'type="button"' ) ) );
		$this->assertCount( 1, $submit );
		$this->assertStringContainsString( 'type="submit"', $submit[0] );
		$this->assertStringContainsString( 'data-magicauth-pk-reauth-confirm', $submit[0] );

		// Views: only the offer is visible; the live regions are never hidden.
		foreach ( [ 'reauth', 'success', 'error' ] as $view ) {
			$this->assertSame( 1, preg_match( '/data-magicauth-pk-view="' . $view . '" hidden/', $html ), $view );
		}
		$this->assertSame( 1, preg_match( '/data-magicauth-pk-view="offer">/', $html ) );
		$this->assertSame( 2, preg_match_all( '/<button [^>]*data-magicauth-pk-create/', $html ), 'P4 and P18' );
		$this->assertSame( 1, preg_match( '/<p class="magicauth-pk-sr-only" data-magicauth-pk-status role="status"><\/p>/', $html ) );
		$this->assertSame( 1, preg_match( '/<p class="magicauth-pk-sr-only" data-magicauth-pk-alert role="alert"><\/p>/', $html ) );
		$this->assertStringNotContainsString( 'Manage passkeys', $html, 'no manage URL for a learner without a page' );
	}

	public function test_template_heading_and_manage_link_for_a_user_with_passkeys(): void {
		global $magicauth_test_state;
		$this->enrol( $this->user );
		$magicauth_test_state['posts'][42] = [
			'status' => 'publish',
			'type'   => 'page',
		];
		update_option(
			'magicauth_settings',
			[
				'passkeys_enabled'        => true,
				'passkeys_manage_page_id' => 42,
			]
		);
		Module::reset_for_tests();
		Prompt::prepare_front();
		$html = self::footer();
		$this->assertStringContainsString( '>Add a passkey for this device</h2>', $html, 'P1b' );
		$this->assertSame( 1, preg_match( '/<a class="magicauth-pk-link" href="([^"]+)">Manage passkeys<\/a>/', $html, $m ) );
		$this->assertSame( get_permalink( 42 ), html_entity_decode( $m[1] ) );
	}

	/** P1b and prompt.hasPasskeys both count the current RP ID only (check 10). */
	public function test_heading_and_config_agree_on_the_current_rp_id(): void {
		global $wpdb;
		$this->enrol( $this->user );
		Prompt::prepare_front();
		$this->assertTrue( self::config()['prompt']['hasPasskeys'] );
		$this->assertStringContainsString( '>Add a passkey for this device</h2>', self::footer(), 'P1b' );

		self::next_request();
		Ceremony::sign_in( $this->user, 'link', Ceremony::NOW - 60 );
		$wpdb->query( $wpdb->prepare( 'UPDATE ' . CredentialStore::table() . ' SET rp_id = %s WHERE user_id = %d', 'old.example', 7 ) );
		Prompt::prepare_front();
		$config = self::config();
		$this->assertCount( 1, $config['passkeys'], 'the list keeps every RP ID' );
		$this->assertFalse( $config['prompt']['hasPasskeys'] );
		$this->assertStringContainsString( '>Sign in faster next time</h2>', self::footer(), 'P1' );
	}

	public function test_prompt_strings_filter_known_keys_only_and_escaped(): void {
		$seen = null;
		add_filter(
			'magicauth_passkey_prompt_strings',
			static function ( $strings, $user ) use ( &$seen ) {
				$seen               = $user->ID;
				$strings['P1']      = '<b>Faster</b> "next" time';
				$strings['P8']      = 'Choose %1$s or %s, not %2$s';
				$strings['P99']     = 'extra';
				$strings['P2']      = [ 'not a string' ];
				return $strings;
			},
			10,
			2
		);
		$strings = Prompt::strings( $this->user );
		$this->assertSame( 7, $seen );
		$this->assertArrayNotHasKey( 'P99', $strings );
		$this->assertStringStartsWith( 'Create a passkey on this device.', $strings['P2'] );
		$this->assertSame( 'Choose Sign in with a passkey or Sign in with a passkey, not %2$s', $strings['P8'], 'no sprintf: nothing throws' );

		Prompt::prepare_front();
		$html = self::footer();
		$this->assertStringContainsString( '&lt;b&gt;Faster&lt;/b&gt; &quot;next&quot; time', $html );
		$this->assertStringNotContainsString( '<b>Faster', $html );
	}

	public function test_theme_can_override_the_prompt_template(): void {
		global $magicauth_test_state;
		$dir = sys_get_temp_dir() . '/magicauth-theme-' . bin2hex( random_bytes( 4 ) );
		mkdir( $dir . '/magicauth', 0777, true );
		file_put_contents( $dir . '/magicauth/passkey-prompt.php', '<?php echo "<dialog data-magicauth-pk-prompt>theme</dialog>";' );
		$magicauth_test_state['stylesheet_directory'] = $dir;
		$magicauth_test_state['template_directory']   = $dir;
		try {
			Prompt::prepare_front();
			$this->assertSame( '<dialog data-magicauth-pk-prompt>theme</dialog>', self::footer() );
			$this->assertSame( 1, self::prompt_done() );
		} finally {
			unlink( $dir . '/magicauth/passkey-prompt.php' );
			rmdir( $dir . '/magicauth' );
			rmdir( $dir );
		}
	}

	/* ------------------------------------------------------------- 2.6 row 7: never logged out */

	public function test_logged_out_template_and_hooks_offer_nothing(): void {
		magicauth_test_login_as( 0 );
		$this->assertFalse( Prompt::eligible( $this->user ) );
		Prompt::prepare_front();
		$this->assertSame( '', self::footer() );
		Prompt::prepare_admin();
		$this->assertSame( '', self::footer() );
	}

	/* ------------------------------------------------------------- helpers */

	/** @return array<string,mixed> The account config added before the account script. */
	private static function config(): array {
		global $magicauth_test_state;
		$inline = $magicauth_test_state['inline_scripts'][ Assets::ACCOUNT_HANDLE ] ?? [];
		self::assertCount( 1, $inline, 'config added once' );
		self::assertSame( 'before', $inline[0][1] );
		self::assertSame( 1, preg_match( '/^window\.magicauthPasskeysConfig = (.*);$/s', $inline[0][0], $m ) );
		return (array) json_decode( $m[1], true );
	}
}

/** Removes every callback of a hook (the harness has no remove_all_filters()). */
function remove_all_filters_for( string $hook ): void {
	global $magicauth_test_state;
	unset( $magicauth_test_state['filters'][ $hook ] );
}
