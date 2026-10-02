<?php
/**
 * T-SIG (SPEC 8.7, 8.11, invariant 7, build steps 11 and 14):
 * Signals::payload() as the responses and configs carry it; the details
 * marker on profile_update; the session-time signals decided by
 * Prompt::prepare_front() and committed by render_footer(), and the
 * signals-only page view that loads the core script alone.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Passkeys\Assets;
use MagicAuth\Passkeys\Base64Url;
use MagicAuth\Passkeys\CredentialStore;
use MagicAuth\Passkeys\ManageShortcode;
use MagicAuth\Passkeys\Module;
use MagicAuth\Passkeys\Prompt;
use MagicAuth\Passkeys\SessionState;
use MagicAuth\Passkeys\Signals;
use MagicAuth\Tests\Support\Ceremony;
use MagicAuth\Tests\Support\SoftAuthenticator;
use PHPUnit\Framework\TestCase;
use WP_User;

final class SignalsTest extends TestCase {

	private WP_User $user;

	protected function setUp(): void {
		Ceremony::site();
		$this->user = Ceremony::user( 7 );
	}

	protected function tearDown(): void {
		global $post;
		$post    = null;
		$_COOKIE = [];
		magicauth_test_reset_state();
	}

	private function enrolled(): SoftAuthenticator {
		$auth = new SoftAuthenticator();
		Ceremony::enrol( $auth, $this->user );
		return $auth;
	}

	public function test_payload_is_complete(): void {
		$first  = $this->enrolled();
		$second = $this->enrolled();

		$this->assertSame(
			[
				'rpId'        => Ceremony::RP,
				'userId'      => CredentialStore::user_handle( 7, false ),
				'allAccepted' => [ Base64Url::encode( $first->credentialId() ), Base64Url::encode( $second->credentialId() ) ],
				'name'        => 'learner7@example.test',
				'displayName' => 'Learner 7',
			],
			Signals::payload( $this->user )
		);
	}

	public function test_only_this_rp_id_and_this_user(): void {
		global $wpdb;
		$here      = $this->enrolled();
		$elsewhere = $this->enrolled();
		$wpdb->query( $wpdb->prepare( 'UPDATE ' . CredentialStore::table() . ' SET rp_id = %s WHERE credential_hash = %s', 'old.example', hash( 'sha256', $elsewhere->credentialId() ) ) );
		$other = Ceremony::user( 8 );
		Ceremony::enrol( new SoftAuthenticator(), $other );

		$this->assertSame( [ Base64Url::encode( $here->credentialId() ) ], Signals::payload( $this->user )['allAccepted'] ?? null );
	}

	/** 16b: a former holder's row of a reused user ID is not in the list. */
	public function test_reused_id_row_is_absent(): void {
		global $wpdb;
		$kept   = $this->enrolled();
		$former = $this->enrolled();
		$wpdb->query( $wpdb->prepare( 'UPDATE ' . CredentialStore::table() . ' SET user_registered = %s WHERE credential_hash = %s', '2025-01-01 10:00:00', hash( 'sha256', $former->credentialId() ) ) );

		$this->assertSame( [ Base64Url::encode( $kept->credentialId() ) ], Signals::payload( $this->user )['allAccepted'] ?? null );
	}

	public function test_empty_list_after_revoke_all_is_sent(): void {
		$this->enrolled();
		CredentialStore::delete_all_for_user( 7 );
		$payload = Signals::payload( $this->user );
		$this->assertNotNull( $payload );
		$this->assertSame( [], $payload['allAccepted'] );
	}

	public function test_query_error_gives_no_payload(): void {
		global $wpdb;
		$this->enrolled();
		$wpdb->show_errors( true );
		$wpdb->fail_next_query( 'SELECT * FROM wp_magicauth_passkeys WHERE user_id' );
		ob_start();
		$payload = Signals::payload( $this->user );
		$out     = (string) ob_get_clean();
		$wpdb->show_errors( false );
		$this->assertNull( $payload );
		$this->assertSame( '', $out );
	}

	public function test_no_handle_gives_no_payload(): void {
		$this->assertNull( Signals::payload( $this->user ) );
	}

	public function test_display_name_equal_to_the_email_is_empty(): void {
		$this->enrolled();
		$this->user->display_name = 'LEARNER7@example.test';
		$this->assertSame( '', Signals::payload( $this->user )['displayName'] ?? null );
	}

	/** B-9: HyperDB/LudicrousDB send reads to the primary before the list is read. */
	public function test_send_reads_to_masters_is_called_when_available(): void {
		global $wpdb;
		$this->enrolled();
		$real  = $wpdb;
		$proxy = new class( $real ) {
			/** @var object */
			private $inner;

			/** @var array<int,string> */
			public array $calls = [];

			public function __construct( object $inner ) {
				$this->inner = $inner;
			}

			public function send_reads_to_masters(): void {
				$this->calls[] = 'send_reads_to_masters';
			}

			/** @param array<int,mixed> $args */
			public function __call( string $name, array $args ) {
				$this->calls[] = $name;
				return $this->inner->$name( ...$args );
			}

			/** @return mixed */
			public function __get( string $name ) {
				return $this->inner->$name;
			}

			/** @param mixed $value */
			public function __set( string $name, $value ): void {
				$this->inner->$name = $value;
			}
		};
		$wpdb = $proxy; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		try {
			$payload = Signals::payload( $this->user );
		} finally {
			$wpdb = $real; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		}
		$this->assertNotNull( $payload );
		$this->assertCount( 1, $payload['allAccepted'] );
		$first_read = array_search( 'get_results', $proxy->calls, true );
		$this->assertSame( 0, array_search( 'send_reads_to_masters', $proxy->calls, true ) );
		$this->assertIsInt( $first_read );
	}

	/* ------------------------------------------------------------- details marker (8.7) */

	public function test_details_marker_on_display_name_change_only_with_a_handle(): void {
		Module::setup();
		wp_update_user( [ 'ID' => 7, 'display_name' => 'No Handle Yet' ] );
		$this->assertSame( '', get_user_meta( 7, Signals::DETAILS_META, true ), 'no handle: nothing to update' );

		$this->enrolled();
		\MagicAuth\Passkeys\Clock::set_for_tests( \MagicAuth\Tests\Support\Ceremony::NOW + 5 );
		wp_update_user( [ 'ID' => 7, 'display_name' => 'Learner Seven' ] );
		$this->assertSame( \MagicAuth\Tests\Support\Ceremony::NOW + 5, get_user_meta( 7, Signals::DETAILS_META, true ) );
		$this->assertSame( 'Learner Seven', Signals::payload( get_userdata( 7 ) )['displayName'] ?? null );
	}

	public function test_unchanged_profile_sets_no_marker(): void {
		Module::setup();
		$this->enrolled();
		wp_update_user( [ 'ID' => 7, 'display_name' => 'Learner 7', 'user_email' => 'learner7@example.test' ] );
		$this->assertSame( '', get_user_meta( 7, Signals::DETAILS_META, true ) );
	}

	public function test_unrevoked_email_change_sets_the_marker_and_the_next_payload_names_the_new_email(): void {
		Module::setup();
		$this->enrolled();
		add_filter( 'magicauth_passkey_revoke_on_email_change', '__return_false' );
		wp_update_user( [ 'ID' => 7, 'user_email' => 'new7@example.test' ] );

		$this->assertSame( \MagicAuth\Tests\Support\Ceremony::NOW, get_user_meta( 7, Signals::DETAILS_META, true ) );
		$payload = Signals::payload( get_userdata( 7 ) );
		$this->assertSame( 'new7@example.test', $payload['name'] ?? null );
		$this->assertCount( 1, $payload['allAccepted'] ?? [], 'the passkey was kept' );
	}

	public function test_email_change_with_rule_m_sets_no_marker(): void {
		Module::setup();
		$this->enrolled();
		wp_update_user( [ 'ID' => 7, 'user_email' => 'new7@example.test', 'display_name' => 'Renamed Too' ] );
		$this->assertSame( '', get_user_meta( 7, Signals::DETAILS_META, true ), 'every passkey is gone: nothing to update' );
		$this->assertSame( [], Signals::payload( get_userdata( 7 ) )['allAccepted'] ?? null );
	}

	public function test_case_only_email_change_marks_the_details(): void {
		Module::setup();
		$this->enrolled();
		wp_update_user( [ 'ID' => 7, 'user_email' => 'Learner7@Example.test' ] );
		$this->assertNotNull( CredentialStore::for_user( get_userdata( 7 ) )[0] ?? null, 'rule M did not run' );
		$this->assertSame( \MagicAuth\Tests\Support\Ceremony::NOW, get_user_meta( 7, Signals::DETAILS_META, true ), 'user.name changed' );
	}

	/* ------------------------------------------------------------- session-time signals (8.7, 8.11) */

	/** Signed in with a password (never the prompt), the module on, a plain page. */
	private function signed_in( string $method = 'password' ): void {
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => true ] );
		Module::reset_for_tests();
		\MagicAuth\Tests\Support\Ceremony::sign_in( $this->user, $method );
	}

	private static function footer(): string {
		ob_start();
		Prompt::render_footer();
		return (string) ob_get_clean();
	}

	private static function next_request(): void {
		global $magicauth_test_state;
		Prompt::reset_for_tests();
		Assets::reset_for_tests();
		unset( $magicauth_test_state['enqueued_scripts'], $magicauth_test_state['enqueued_styles'], $magicauth_test_state['inline_scripts'] );
		$magicauth_test_state['headers'] = [];
	}

	private static function signals_at(): int {
		$row = SessionState::get();
		return null !== $row ? (int) $row->signals_at : -1;
	}

	public function test_signals_only_view_enqueues_core_js_only(): void {
		global $magicauth_test_state;
		$this->enrolled();
		$this->signed_in();

		Prompt::prepare_front();

		$this->assertSame( [ Assets::CORE_HANDLE ], array_keys( $magicauth_test_state['enqueued_scripts'] ?? [] ) );
		$this->assertSame( [ 'in_footer' => true, 'strategy' => 'defer' ], $magicauth_test_state['enqueued_scripts'][ Assets::CORE_HANDLE ][3] );
		$this->assertArrayNotHasKey( 'enqueued_styles', $magicauth_test_state, 'no stylesheet' );
		$this->assertContains( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private', $magicauth_test_state['headers'] ?? [] );
		$inline = $magicauth_test_state['inline_scripts'][ Assets::CORE_HANDLE ] ?? [];
		$this->assertCount( 1, $inline );
		$this->assertSame( 'before', $inline[0][1], 'an after script would cost the defer strategy' );
		$this->assertSame( 1, preg_match( '/^window\.magicauthPasskeysConfig = (\{.*?\});\(function\(c\)/s', $inline[0][0], $m ) );
		$config = (array) json_decode( $m[1], true );
		$this->assertSame( [ 'ajaxUrl', 'account', 'signals' ], array_keys( $config ), 'reduced config, no nonce' );
		$this->assertSame( Assets::account_key( $this->user ), $config['account']['key'] );
		$this->assertSame( Signals::payload( $this->user ), $config['signals'] );
		$this->assertStringNotContainsString( '</', $inline[0][0] );

		$this->assertSame( 0, max( 0, self::signals_at() ), 'not committed at the decision' );
		$this->assertSame( '', self::footer(), 'nothing printed' );
		$this->assertSame( \MagicAuth\Tests\Support\Ceremony::NOW, self::signals_at(), 'committed in the footer' );

		self::next_request();
		Prompt::prepare_front();
		$this->assertArrayNotHasKey( 'enqueued_scripts', $magicauth_test_state, 'once per session' );
		$this->assertSame( [], $magicauth_test_state['headers'], 'nothing due: the page stays cacheable' );
	}

	/**
	 * 8.11: a shortcode the early detection missed (theme template, pattern)
	 * still gets the account script and stylesheet after a signals-only
	 * decision, with the full config; the signals go once, by the inline call.
	 */
	public function test_late_shortcode_after_signals_only_enqueues_the_account_assets(): void {
		global $magicauth_test_state;
		$this->enrolled();
		$this->signed_in();
		Prompt::prepare_front();
		$this->assertSame( [ Assets::CORE_HANDLE ], array_keys( $magicauth_test_state['enqueued_scripts'] ?? [] ) );

		$html = ManageShortcode::render();
		$this->assertStringContainsString( 'data-magicauth-pk-manage', $html );
		$scripts = $magicauth_test_state['enqueued_scripts'] ?? [];
		$this->assertArrayHasKey( Assets::ACCOUNT_HANDLE, $scripts );
		$this->assertSame( [ Assets::CORE_HANDLE ], $scripts[ Assets::ACCOUNT_HANDLE ][1] );
		$this->assertSame( [ 'in_footer' => true, 'strategy' => 'defer' ], $scripts[ Assets::ACCOUNT_HANDLE ][3] );
		$this->assertArrayHasKey( Assets::ACCOUNT_STYLE, $magicauth_test_state['enqueued_styles'] ?? [] );
		$config = self::account_config();
		$this->assertSame(
			[ 'ajaxUrl', 'rpId', 'nonce', 'manageUrl', 'account', 'prompt', 'signals', 'passkeys', 'reauth', 'actions', 'i18n', 'render' ],
			array_keys( $config )
		);
		$this->assertSame( wp_create_nonce( 'magicauth_passkeys' ), $config['nonce'] );
		$this->assertCount( 1, $config['passkeys'] );
		$this->assertFalse( $config['prompt']['show'] );
		$this->assertNull( $config['signals'], 'the inline call already sends them' );
		$this->assertCount( 1, $magicauth_test_state['inline_scripts'][ Assets::CORE_HANDLE ], 'one signals call' );

		ManageShortcode::render();
		$this->assertCount( 1, $magicauth_test_state['inline_scripts'][ Assets::ACCOUNT_HANDLE ], 'once per request' );
		$this->assertSame( '', self::footer() );
		$this->assertSame( \MagicAuth\Tests\Support\Ceremony::NOW, self::signals_at(), 'committed in the footer' );
	}

	public function test_signals_again_after_a_details_change(): void {
		global $magicauth_test_state;
		$this->enrolled();
		$this->signed_in();
		Prompt::prepare_front();
		self::footer();

		\MagicAuth\Passkeys\Clock::set_for_tests( \MagicAuth\Tests\Support\Ceremony::NOW + 60 );
		Module::setup();
		wp_update_user( [ 'ID' => 7, 'display_name' => 'Learner Seven' ] );
		self::next_request();
		Prompt::prepare_front();
		$this->assertSame( [ Assets::CORE_HANDLE ], array_keys( $magicauth_test_state['enqueued_scripts'] ?? [] ) );
		self::footer();
		$this->assertSame( \MagicAuth\Tests\Support\Ceremony::NOW + 60, self::signals_at() );

		self::next_request();
		Prompt::prepare_front();
		$this->assertArrayNotHasKey( 'enqueued_scripts', $magicauth_test_state, 'details_at is not after signals_at any more' );
	}

	public function test_no_signals_without_a_handle_logged_out_or_off_html(): void {
		global $magicauth_test_state;
		$this->signed_in();
		Prompt::prepare_front();
		$this->assertArrayNotHasKey( 'enqueued_scripts', $magicauth_test_state, 'no handle' );

		$this->enrolled();
		self::next_request();
		$magicauth_test_state['request']['is_feed'] = true;
		Prompt::prepare_front();
		$this->assertArrayNotHasKey( 'enqueued_scripts', $magicauth_test_state, 'a feed' );
		unset( $magicauth_test_state['request'] );

		self::next_request();
		magicauth_test_login_as( 0 );
		Prompt::prepare_front();
		$this->assertArrayNotHasKey( 'enqueued_scripts', $magicauth_test_state, 'logged out' );
		$this->assertSame( '', self::footer() );
	}

	public function test_unreadable_list_sends_nothing_and_commits_nothing(): void {
		global $wpdb, $magicauth_test_state;
		$this->enrolled();
		$this->signed_in();
		$wpdb->fail_next_query( 'SELECT * FROM wp_magicauth_passkeys WHERE user_id' );
		Prompt::prepare_front();
		$this->assertArrayNotHasKey( 'enqueued_scripts', $magicauth_test_state );
		self::footer();
		$this->assertSame( -1, self::signals_at(), 'no row written: the next page tries again' );

		self::next_request();
		Prompt::prepare_front();
		$this->assertArrayHasKey( Assets::CORE_HANDLE, $magicauth_test_state['enqueued_scripts'] ?? [] );
	}

	public function test_state_read_error_is_not_due(): void {
		global $wpdb, $magicauth_test_state;
		$this->enrolled();
		$this->signed_in();
		$wpdb->fail_next_query( 'FROM wp_magicauth_passkey_sessions WHERE session_hash' );
		Prompt::prepare_front();
		$this->assertArrayNotHasKey( 'enqueued_scripts', $magicauth_test_state );
	}

	public function test_prompt_page_carries_signals_only_when_due(): void {
		$this->enrolled();
		$this->signed_in( 'link' );
		Prompt::prepare_front();
		$config = self::account_config();
		$this->assertTrue( $config['prompt']['show'] );
		$this->assertSame( Signals::payload( $this->user ), $config['signals'], 'first page view: due' );
		self::footer();
		$this->assertSame( \MagicAuth\Tests\Support\Ceremony::NOW, self::signals_at() );
		$this->assertSame( 1, (int) SessionState::get()->prompt_done );

		// A new link session whose signals were already sent (row stamped) still gets the prompt, without signals.
		\MagicAuth\Tests\Support\Ceremony::sign_in( $this->user, 'link' );
		$this->assertTrue( SessionState::set( 'signals_at', \MagicAuth\Tests\Support\Ceremony::NOW ) );
		self::next_request();
		Prompt::prepare_front();
		$config = self::account_config();
		$this->assertTrue( $config['prompt']['show'] );
		$this->assertNull( $config['signals'] );
		self::footer();
	}

	public function test_management_page_with_signals_due_commits_after_the_footer(): void {
		global $post, $magicauth_test_state;
		$this->enrolled();
		$this->signed_in();
		$post                            = new \WP_Post( '[magicauth_passkeys]' );
		$magicauth_test_state['queried'] = [
			'id'   => 50,
			'type' => 'page',
			'post' => $post,
		];
		Prompt::prepare_front();
		$this->assertArrayNotHasKey( 'enqueued_scripts', $magicauth_test_state, 'the management assets come on wp_enqueue_scripts' );
		Assets::enqueue_front();
		$this->assertNotNull( self::account_config()['signals'] );
		$this->assertSame( '', self::footer() );
		$this->assertSame( \MagicAuth\Tests\Support\Ceremony::NOW, self::signals_at() );
	}

	/** The inline signals call itself, in node: both signals in order, the empty-list cleanup. */
	public function test_inline_signals_call_runs_in_node(): void {
		$node = trim( (string) shell_exec( 'command -v node 2>/dev/null' ) );
		if ( '' === $node ) {
			$this->markTestSkipped( 'node is not installed' );
		}
		global $magicauth_test_state;
		$this->enrolled();
		$this->signed_in();
		Prompt::prepare_front();
		$inline = (string) ( $magicauth_test_state['inline_scripts'][ Assets::CORE_HANDLE ][0][0] ?? '' );
		$script = __DIR__ . '/js/account-script.js';
		$file   = tempnam( sys_get_temp_dir(), 'magicauth-inline-' );
		$this->assertNotFalse( $file );
		file_put_contents( $file, $inline );
		try {
			$out = (string) shell_exec( escapeshellarg( $node ) . ' ' . escapeshellarg( $script ) . ' ' . escapeshellarg( MAGICAUTH_DIR ) . ' inline_signals ' . escapeshellarg( $file ) . ' 2>&1' );
		} finally {
			unlink( $file );
		}
		$this->assertSame( "ok\n", $out );
	}

	/** @return array<string,mixed> */
	private static function account_config(): array {
		global $magicauth_test_state;
		$inline = $magicauth_test_state['inline_scripts'][ Assets::ACCOUNT_HANDLE ] ?? [];
		self::assertCount( 1, $inline );
		self::assertSame( 1, preg_match( '/^window\.magicauthPasskeysConfig = (.*);$/s', $inline[0][0], $m ) );
		return (array) json_decode( $m[1], true );
	}
}
