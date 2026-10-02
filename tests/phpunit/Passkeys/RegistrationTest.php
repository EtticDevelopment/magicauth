<?php
/**
 * T-REG at the endpoint level (SPEC 6.4, 6.5, 7.3, 14.1, build step 11):
 * magicauth_passkey_register_options and magicauth_passkey_register through
 * AccountEndpoints with SoftAuthenticator credentials, real sessions, real
 * challenge rows and MySQL changed-rows semantics.
 *
 * The verifier's per-check negatives (9b to 31) are covered one by one in
 * RegistrationVerifierTest; here every gate of the two endpoints, the
 * response bodies (unknown_credential present only when flagged), the
 * throttle buckets, the orphan flag matrix through the endpoint, R-14 (email,
 * cadence, rule E, action) and the response shape.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Auth\Throttle;
use MagicAuth\Passkeys\AccountEndpoints;
use MagicAuth\Passkeys\Base64Url;
use MagicAuth\Passkeys\ChallengeStore;
use MagicAuth\Passkeys\Clock;
use MagicAuth\Passkeys\CredentialStore;
use MagicAuth\Passkeys\Freshness;
use MagicAuth\Passkeys\Module;
use MagicAuth\Passkeys\SessionState;
use MagicAuth\Tests\Support\Cbor;
use MagicAuth\Tests\Support\Ceremony;
use MagicAuth\Tests\Support\SoftAuthenticator;
use PHPUnit\Framework\TestCase;
use WP_User;

final class RegistrationTest extends TestCase {

	private WP_User $user;

	/** @var array<string,mixed> */
	private array $server = [];

	protected function setUp(): void {
		$this->server = $_SERVER;
		Ceremony::site();
		Ceremony::enable_module();
		$this->user = Ceremony::user( 7 );
		Ceremony::sign_in( $this->user );
		$_COOKIE = array_intersect_key( $_COOKIE, [ Freshness::COOKIE => true ] );
	}

	protected function tearDown(): void {
		global $wpdb;
		$_SERVER  = $this->server;
		$_POST    = [];
		$_REQUEST = [];
		$_COOKIE  = [];
		$wpdb->show_errors( false );
		magicauth_test_reset_state();
	}

	/* ------------------------------------------------------------- helpers */

	/**
	 * @param array<string,mixed> $fields
	 * @return array{status:?int,success:bool,data:array<string,mixed>,body:string}
	 */
	private static function post( string $handler, array $fields = [] ): array {
		global $wpdb;
		Ceremony::account_post( $fields );
		$wpdb->show_errors( true );
		try {
			return Ceremony::call( $handler );
		} finally {
			$wpdb->show_errors( false );
		}
	}

	/** @return array<string,mixed> publicKey of a 200 register_options. */
	private function options(): array {
		$response = self::post( 'register_options' );
		$this->assertSame( 200, $response['status'], (string) wp_json_encode( $response['data'] ) );
		$this->assertTrue( $response['success'] );
		return $response['data']['publicKey'];
	}

	/**
	 * Fresh options, then register with the authenticator's response.
	 *
	 * @param array<string,mixed> $o      SoftAuthenticator overrides.
	 * @param array<string,mixed> $fields Extra POST fields.
	 * @return array{status:?int,success:bool,data:array<string,mixed>,body:string}
	 */
	private function register( SoftAuthenticator $auth, array $o = [], array $fields = [] ): array {
		$credential = Ceremony::encode( $auth->register( $this->options(), Ceremony::ORIGIN, $o ) );
		return self::post( 'register', [ 'credential' => $credential ] + $fields );
	}

	/** @param array{status:?int,success:bool,data:array<string,mixed>,body:string} $response */
	private function assert_failed( array $response, string $code, int $status, bool $flag = false, string $message = '' ): void {
		$this->assertSame( $status, $response['status'], $message . ' ' . $response['body'] );
		$this->assertFalse( $response['success'], $message );
		$this->assertSame( $code, $response['data']['code'] ?? null, $message );
		$this->assertIsString( $response['data']['message'] ?? null );
		$this->assertNotSame( '', $response['data']['message'] );
		if ( $flag ) {
			$this->assertTrue( $response['data']['unknown_credential'] ?? null, $message . ': flagged' );
		} else {
			$this->assertArrayNotHasKey( 'unknown_credential', $response['data'], $message . ': no flag key' );
		}
		$this->assertIsArray( json_decode( $response['body'], true ), 'valid JSON body' );
	}

	private static function bucket( string $bucket, int $uid = 7 ): int {
		return (int) get_transient( 'magicauth_throttle_' . $bucket . '_u' . $uid );
	}

	private static function enrolled( WP_User $user, array $opts = [] ): SoftAuthenticator {
		$auth = new SoftAuthenticator( 'ES256', $opts );
		Ceremony::enrol( $auth, $user );
		return $auth;
	}

	private static function challenge_rows(): int {
		global $wpdb;
		return (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . ChallengeStore::table() );
	}

	/* ------------------------------------------------------------------ 1-6: gates */

	/** 1: only wp_ajax_ hooks, never nopriv (2.6 rows 10, 11). */
	public function test_1_nopriv_actions_are_not_registered(): void {
		do_action( 'init' );
		Module::register();
		foreach ( [ 'register_options', 'register', 'reauth_email', 'reauth_code', 'reauth_options', 'reauth_passkey' ] as $handler ) {
			$this->assertSame( 10, has_action( 'wp_ajax_magicauth_passkey_' . $handler, [ AccountEndpoints::class, $handler ] ), $handler );
			$this->assertFalse( has_action( 'wp_ajax_nopriv_magicauth_passkey_' . $handler ), $handler );
		}
	}

	/** @return array<string,array{string}> */
	public static function handlers(): array {
		return [
			'register_options' => [ 'register_options' ],
			'register'         => [ 'register' ],
		];
	}

	/** @dataProvider handlers */
	public function test_2_not_logged_in( string $handler ): void {
		magicauth_test_login_as( 0 );
		$this->assert_failed( self::post( $handler ), 'not_logged_in', 403 );
	}

	/** @dataProvider handlers */
	public function test_3_bad_nonce( string $handler ): void {
		Ceremony::account_post( [], 'magicauth-passkeys-admin' );
		$this->assert_failed( Ceremony::call( $handler ), 'bad_nonce', 403, false, 'other action' );

		Ceremony::account_post();
		$_REQUEST['_ajax_nonce'] = '';
		$this->assert_failed( Ceremony::call( $handler ), 'bad_nonce', 403, false, 'empty' );
	}

	/** @return array<string,array{string,?string}> */
	public static function bad_origins(): array {
		return [
			'register_options, missing'   => [ 'register_options', null ],
			'register_options, foreign'   => [ 'register_options', 'https://evil.example' ],
			'register_options, null'      => [ 'register_options', 'null' ],
			'register_options, subdomain' => [ 'register_options', 'https://x.academy.example.com' ],
			'register, missing'           => [ 'register', null ],
			'register, foreign'           => [ 'register', 'https://evil.example' ],
			'register, http'              => [ 'register', 'http://academy.example.com' ],
		];
	}

	/** @dataProvider bad_origins */
	public function test_4_bad_or_missing_origin( string $handler, ?string $origin ): void {
		Ceremony::account_post();
		unset( $_SERVER['HTTP_ORIGIN'] );
		if ( null !== $origin ) {
			$_SERVER['HTTP_ORIGIN'] = $origin;
		}
		$this->assert_failed( Ceremony::call( $handler ), 'bad_origin', 403 );
	}

	/** @dataProvider handlers */
	public function test_get_is_405( string $handler ): void {
		Ceremony::account_post();
		$_SERVER['REQUEST_METHOD'] = 'GET';
		$this->assert_failed( Ceremony::call( $handler ), 'bad_request', 405 );
	}

	/** @dataProvider handlers */
	public function test_5_module_off( string $handler ): void {
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => false ] );
		Module::reset_for_tests();
		$this->assert_failed( self::post( $handler ), 'unavailable', 404 );
	}

	/** @dataProvider handlers */
	public function test_5_unavailable_site( string $handler ): void {
		update_option( 'magicauth_db_version', 1 );
		Module::reset_for_tests();
		$this->assert_failed( self::post( $handler ), 'unavailable', 404 );
	}

	/** @dataProvider handlers */
	public function test_6_disabled_user( string $handler ): void {
		update_user_meta( 7, 'magicauth_disabled', 1 );
		$this->assert_failed( self::post( $handler ), 'disabled_user', 403 );
		$this->assertSame( 0, self::challenge_rows() );
	}

	/** Rule D after the options: the register call is refused and stores nothing. */
	public function test_6_disabled_between_options_and_register(): void {
		$credential = Ceremony::encode( ( new SoftAuthenticator() )->register( $this->options(), Ceremony::ORIGIN ) );
		update_user_meta( 7, 'magicauth_disabled', 1 );
		$this->assert_failed( self::post( 'register', [ 'credential' => $credential ] ), 'disabled_user', 403 );
		$this->assertSame( 0, Ceremony::count_rows() );
	}

	/* ------------------------------------------------------------------ 7, 8: freshness */

	public function test_7_stale_session_gets_reauth_required_with_email_code(): void {
		Ceremony::sign_in( $this->user, 'link', Clock::now() - 601 );
		$response = self::post( 'register_options' );
		$this->assert_failed( $response, 'reauth_required', 403 );
		$this->assertSame( [ 'email_code' ], $response['data']['methods'] );
		$this->assertSame( 0, self::challenge_rows(), 'no challenge for a stale session' );
	}

	public function test_7_passkey_listed_only_with_a_usable_passkey(): void {
		$auth = self::enrolled( $this->user, [ 'be' => false, 'bs' => false ] );
		Ceremony::sign_in( $this->user, 'link', Clock::now() - 601 );
		$this->assertSame( [ 'email_code', 'passkey' ], self::post( 'register_options' )['data']['methods'] );

		$row = CredentialStore::find_by_raw_id( $auth->credentialId() );
		$this->assertIsObject( $row );
		CredentialStore::block( (int) $row->id );
		$this->assertSame( [ 'email_code' ], self::post( 'register_options' )['data']['methods'], 'blocked passkeys do not count' );
	}

	public function test_7_passkey_for_another_rp_id_is_not_usable(): void {
		global $wpdb;
		$auth = self::enrolled( $this->user );
		$wpdb->query( $wpdb->prepare( 'UPDATE ' . CredentialStore::table() . ' SET rp_id = %s', 'old.example' ) );
		Ceremony::sign_in( $this->user, 'link', Clock::now() - 601 );
		$this->assertSame( [ 'email_code' ], self::post( 'register_options' )['data']['methods'] );
		unset( $auth );
	}

	public function test_7_email_code_absent_after_an_in_session_email_change(): void {
		$auth_at = Clock::now() - 601;
		Ceremony::sign_in( $this->user, 'link', $auth_at );

		update_user_meta( 7, 'magicauth_email_changed_at', $auth_at );
		$this->assertSame( [], self::post( 'register_options' )['data']['methods'], 'change at the stamp' );

		update_user_meta( 7, 'magicauth_email_changed_at', $auth_at + 30 );
		$this->assertSame( [], self::post( 'register_options' )['data']['methods'], 'change after the stamp' );

		update_user_meta( 7, 'magicauth_email_changed_at', $auth_at - 1 );
		$this->assertSame( [ 'email_code' ], self::post( 'register_options' )['data']['methods'], 'change before the session' );
	}

	/** 7b: stale calls count only passkey_stale_user; the 61st is throttled. */
	public function test_7b_stale_calls_count_only_the_stale_bucket(): void {
		Ceremony::sign_in( $this->user, 'link', Clock::now() - 601 );
		for ( $i = 1; $i <= 60; $i++ ) {
			$this->assertSame( 'reauth_required', self::post( 'register_options' )['data']['code'] );
		}
		$this->assertSame( 60, self::bucket( Throttle::ACTION_PASSKEY_STALE_USER ) );
		$this->assertSame( 0, self::bucket( Throttle::ACTION_PASSKEY_REG_USER ) );
		$this->assert_failed( self::post( 'register_options' ), 'throttled', 429 );

		// The owner's fresh session still has its whole registration quota.
		Ceremony::sign_in( $this->user );
		$this->options();
		$this->assertSame( 1, self::bucket( Throttle::ACTION_PASSKEY_REG_USER ) );
	}

	/** @return array<string,array{?string,bool,bool}> */
	public static function never_fresh(): array {
		return [
			'8 unstamped (switched) session'  => [ null, true, true ],
			'8b password session'             => [ 'password', true, true ],
			'8c admin_link session'           => [ 'admin_link', true, true ],
			'8d link session without cookie'  => [ 'link', true, false ],
			'link session without fresh hash' => [ 'link', false, true ],
		];
	}

	/** @dataProvider never_fresh */
	public function test_8_sessions_that_are_never_fresh( ?string $method, bool $fresh, bool $cookie ): void {
		Ceremony::sign_in( $this->user, $method, Clock::now() - 1, $fresh, $cookie );
		if ( null !== $method && ! $fresh ) {
			$_COOKIE[ Freshness::COOKIE ] = str_repeat( 'a', 64 );
		}
		$response = self::post( 'register_options' );
		$this->assert_failed( $response, 'reauth_required', 403 );
		$this->assertSame( [ 'email_code' ], $response['data']['methods'] );
	}

	public function test_copied_cookies_from_another_browser_are_not_fresh(): void {
		$_COOKIE[ Freshness::COOKIE ] = str_repeat( 'b', 64 );
		$this->assert_failed( self::post( 'register_options' ), 'reauth_required', 403 );
	}

	/* ------------------------------------------------------------------ options */

	public function test_options_shape_and_challenge_row(): void {
		global $wpdb;
		$public_key = $this->options();

		$this->assertSame( [ 'id' => Ceremony::RP, 'name' => Ceremony::RP ], $public_key['rp'] );
		$handle = CredentialStore::user_handle( 7, false );
		$this->assertSame( $handle, $public_key['user']['id'] );
		$this->assertSame( 'learner7@example.test', $public_key['user']['name'] );
		$this->assertSame( 'Learner 7', $public_key['user']['displayName'] );
		$this->assertSame( [ -7, -8, -257 ], array_column( $public_key['pubKeyCredParams'], 'alg' ) );
		$this->assertSame( 300000, $public_key['timeout'] );
		$this->assertSame( [], $public_key['excludeCredentials'] );
		$this->assertSame( 'required', $public_key['authenticatorSelection']['userVerification'] );
		$this->assertSame( 'none', $public_key['attestation'] );

		$row = $wpdb->get_row( 'SELECT * FROM ' . ChallengeStore::table(), ARRAY_A );
		$this->assertSame( 'register', $row['ceremony'] );
		$this->assertSame( '7', (string) $row['user_id'] );
		$this->assertSame( Freshness::session_hash(), $row['session_hash'] );
		$this->assertSame( $handle, $row['user_handle'] );
		$this->assertSame( '-7,-8,-257', $row['algs'] );
		$this->assertSame( gmdate( 'Y-m-d H:i:s', Ceremony::NOW + 420 ), $row['expires_at'] );
		$this->assertSame( 1, self::bucket( Throttle::ACTION_PASSKEY_REG_USER ) );
	}

	public function test_options_responses_are_no_store(): void {
		global $magicauth_test_state;
		$this->options();
		$this->assertContains( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private', $magicauth_test_state['headers'] );
	}

	public function test_exclude_credentials_list_existing_ids_including_blocked_with_transports(): void {
		$first  = self::enrolled( $this->user, [ 'transports' => [ 'usb' ], 'be' => false, 'bs' => false ] );
		$second = self::enrolled( $this->user, [ 'transports' => [] ] );
		$row    = CredentialStore::find_by_raw_id( $first->credentialId() );
		$this->assertIsObject( $row );
		CredentialStore::block( (int) $row->id );

		$exclude = $this->options()['excludeCredentials'];

		$this->assertSame(
			[
				[
					'type'       => 'public-key',
					'id'         => Base64Url::encode( $first->credentialId() ),
					'transports' => [ 'usb' ],
				],
				[
					'type' => 'public-key',
					'id'   => Base64Url::encode( $second->credentialId() ),
				],
			],
			$exclude
		);
	}

	public function test_registration_quota_is_20_per_hour(): void {
		for ( $i = 1; $i <= 20; $i++ ) {
			$this->options();
		}
		$this->assert_failed( self::post( 'register_options' ), 'throttled', 429 );
		$this->assertSame( 20, self::challenge_rows() );
	}

	public function test_options_db_errors_are_retry(): void {
		global $wpdb;
		$wpdb->fail_next_query( 'SELECT * FROM wp_magicauth_passkeys WHERE user_id' );
		$this->assert_failed( self::post( 'register_options' ), 'retry', 503 );

		$wpdb->fail_next_query( 'INSERT INTO wp_magicauth_passkey_challenges' );
		$this->assert_failed( self::post( 'register_options' ), 'retry', 503 );
	}

	/* ------------------------------------------------------------------ happy */

	/** @return array<string,array{string}> */
	public static function algs(): array {
		return [
			'ES256' => [ 'ES256' ],
			'RS256' => [ 'RS256' ],
			'EdDSA' => [ 'EdDSA' ],
		];
	}

	/** @dataProvider algs */
	public function test_full_registration( string $alg ): void {
		global $magicauth_test_state;
		$added = [];
		add_action(
			'magicauth_passkey_added',
			static function ( $uid, $id ) use ( &$added ) {
				$added[] = [ $uid, $id ];
			},
			10,
			2
		);
		$auth = new SoftAuthenticator( $alg );

		$response = $this->register( $auth );

		$this->assertSame( 200, $response['status'], $response['body'] );
		$this->assertTrue( $response['success'] );
		$this->assertSame( 1, Ceremony::count_rows() );
		$item = $response['data']['passkey'];
		$this->assertSame( 'Passkey', $item['name'] );
		$this->assertSame( Base64Url::encode( $auth->credentialId() ), $item['credential_id'] );
		$this->assertStringStartsWith( 'Passkey ending in ', $item['label'] );
		$this->assertTrue( $item['usable_here'] );
		$this->assertTrue( $item['is_new'] );
		$this->assertSame( [ $item ], $response['data']['passkeys'] );

		$signal = $response['data']['signal'];
		$this->assertSame( Ceremony::RP, $signal['rpId'] );
		$this->assertSame( CredentialStore::user_handle( 7, false ), $signal['userId'] );
		$this->assertSame( [ Base64Url::encode( $auth->credentialId() ) ], $signal['allAccepted'] );
		$this->assertSame( 'learner7@example.test', $signal['name'] );
		$this->assertSame( 'Learner 7', $signal['displayName'] );

		// R-14: the added email once, after the response; cadence reset; action.
		$this->assertSame( 1, $magicauth_test_state['after_response_calls'] ?? 0 );
		$this->assertCount( 1, $magicauth_test_state['mail'] ?? [] );
		$this->assertSame( 'learner7@example.test', $magicauth_test_state['mail'][0]['to'] );
		$this->assertStringContainsString( 'A passkey was added', $magicauth_test_state['mail'][0]['subject'] );
		$this->assertSame( [ 'declines' => 0, 'next_at' => 0 ], get_user_meta( 7, 'magicauth_passkey_prompt', true ) );
		$this->assertSame( [ [ 7, $item['id'] ] ], $added );
		$this->assertSame( 0, self::bucket( Throttle::ACTION_PASSKEY_REGFAIL_USER ) );
		$this->assertSame( [], array_column( $magicauth_test_state['auth_cookies'] ?? [], 'user_id' ), 'no auth cookie' );
	}

	public function test_cadence_reset_replaces_an_earlier_decline(): void {
		update_user_meta(
			7,
			'magicauth_passkey_prompt',
			[
				'declines' => 2,
				'next_at'  => Ceremony::NOW + 90 * DAY_IN_SECONDS,
			]
		);
		$this->assertSame( 200, $this->register( new SoftAuthenticator() )['status'] );
		$this->assertSame( [ 'declines' => 0, 'next_at' => 0 ], get_user_meta( 7, 'magicauth_passkey_prompt', true ) );
	}

	/** @return array<string,array{bool,bool}> */
	public static function backup_flags(): array {
		return [
			'synced'             => [ true, true ],
			'eligible, unsynced' => [ true, false ],
			'device-bound'       => [ false, false ],
		];
	}

	/** @dataProvider backup_flags */
	public function test_backup_flags_are_stored( bool $be, bool $bs ): void {
		$item = $this->register( new SoftAuthenticator( 'ES256', [ 'be' => $be, 'bs' => $bs ] ) )['data']['passkey'];
		$this->assertSame( $bs, $item['synced'] );
		$this->assertSame( $be, $item['sync_possible'] );
		$this->assertSame( ! $be, $item['device_bound'] );
	}

	public function test_passkey_signin_session_can_add_without_step_up(): void {
		Ceremony::sign_in( $this->user, 'passkey' );
		$this->assertSame( 200, $this->register( new SoftAuthenticator() )['status'] );
	}

	/** 3.3: the register call does not re-check the window; the challenge carries freshness. */
	public function test_register_after_the_window_with_a_live_challenge_succeeds(): void {
		$options = $this->options();
		Clock::set_for_tests( Ceremony::NOW + 419 );
		$credential = Ceremony::encode( ( new SoftAuthenticator() )->register( $options, Ceremony::ORIGIN ) );
		$this->assertSame( 200, self::post( 'register', [ 'credential' => $credential ] )['status'] );
	}

	/* ------------------------------------------------------------------ rule E initialisation (R-14) */

	public function test_rule_e_initialises_from_a_link_session(): void {
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => true, 'passkeys_email_reverify_days' => 180 ] );
		$this->register( new SoftAuthenticator() );
		$this->assertSame( Ceremony::NOW, get_user_meta( 7, 'magicauth_email_verified_at', true ) );
	}

	public function test_rule_e_off_writes_nothing(): void {
		$this->register( new SoftAuthenticator() );
		$this->assertSame( '', get_user_meta( 7, 'magicauth_email_verified_at', true ) );
	}

	public function test_rule_e_keeps_an_existing_value(): void {
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => true, 'passkeys_email_reverify_days' => 180 ] );
		update_user_meta( 7, 'magicauth_email_verified_at', 1234 );
		$this->register( new SoftAuthenticator() );
		$this->assertSame( 1234, get_user_meta( 7, 'magicauth_email_verified_at', true ) );
	}

	/** @return array<string,array{string}> */
	public static function not_mailbox_sessions(): array {
		return [
			'reset'   => [ 'reset' ],
			'passkey' => [ 'passkey' ],
		];
	}

	/** @dataProvider not_mailbox_sessions */
	public function test_rule_e_not_initialised_from_other_fresh_sessions( string $method ): void {
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => true, 'passkeys_email_reverify_days' => 180 ] );
		Ceremony::sign_in( $this->user, $method );
		$this->assertSame( 200, $this->register( new SoftAuthenticator() )['status'] );
		$this->assertSame( '', get_user_meta( 7, 'magicauth_email_verified_at', true ) );
	}

	public function test_rule_e_initialised_after_an_email_code_step_up_only(): void {
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => true, 'passkeys_email_reverify_days' => 180 ] );

		// A passkey step-up from a password session: not a mailbox proof.
		Ceremony::sign_in( $this->user, 'password' );
		$this->assertTrue( SessionState::stamp_reauth( 'passkey' ) );
		$_COOKIE[ Freshness::COOKIE ] = self::last_fresh_cookie();
		$this->assertSame( 200, $this->register( new SoftAuthenticator() )['status'] );
		$this->assertSame( '', get_user_meta( 7, 'magicauth_email_verified_at', true ) );

		// An email-code step-up stamp is (the code endpoint also writes it; here only the stamp).
		Ceremony::sign_in( $this->user, 'password' );
		$this->assertTrue( SessionState::stamp_reauth( 'email_code' ) );
		$_COOKIE[ Freshness::COOKIE ] = self::last_fresh_cookie();
		$this->assertSame( 200, $this->register( new SoftAuthenticator() )['status'] );
		$this->assertSame( Ceremony::NOW, get_user_meta( 7, 'magicauth_email_verified_at', true ) );
	}

	private static function last_fresh_cookie(): string {
		global $magicauth_test_state;
		$cookies = array_values(
			array_filter(
				$magicauth_test_state['cookies'] ?? [],
				static function ( array $c ): bool {
					return Freshness::COOKIE === $c['name'];
				}
			)
		);
		return (string) end( $cookies )['value'];
	}

	/* ------------------------------------------------------------------ 9, 9b: challenge */

	public function test_9_unknown_challenge_is_flagged(): void {
		$options              = $this->options();
		$options['challenge'] = Base64Url::encode( random_bytes( 32 ) );
		$credential           = Ceremony::encode( ( new SoftAuthenticator() )->register( $options, Ceremony::ORIGIN ) );
		$this->assert_failed( self::post( 'register', [ 'credential' => $credential ] ), 'registration_failed', 400, true );
	}

	public function test_9_expired_challenge_is_flagged(): void {
		$options = $this->options();
		Clock::set_for_tests( Ceremony::NOW + 420 );
		$credential = Ceremony::encode( ( new SoftAuthenticator() )->register( $options, Ceremony::ORIGIN ) );
		$this->assert_failed( self::post( 'register', [ 'credential' => $credential ] ), 'registration_failed', 400, true );
	}

	public function test_9_challenge_of_another_user_is_flagged_and_burnt(): void {
		$other = Ceremony::user( 8 );
		Ceremony::sign_in( $other );
		$options    = $this->options();
		$credential = Ceremony::encode( ( new SoftAuthenticator() )->register( $options, Ceremony::ORIGIN ) );

		Ceremony::sign_in( $this->user );
		$this->assert_failed( self::post( 'register', [ 'credential' => $credential ] ), 'registration_failed', 400, true );

		Ceremony::sign_in( $other );
		$this->assert_failed( self::post( 'register', [ 'credential' => $credential ] ), 'registration_failed', 400, false, 'burnt: replay, no flag' );
		$this->assertSame( 0, Ceremony::count_rows() );
	}

	public function test_9_challenge_of_another_session_is_flagged(): void {
		$options    = $this->options();
		$credential = Ceremony::encode( ( new SoftAuthenticator() )->register( $options, Ceremony::ORIGIN ) );
		Ceremony::sign_in( $this->user );
		$this->assert_failed( self::post( 'register', [ 'credential' => $credential ] ), 'registration_failed', 400, true );
	}

	public function test_9_signin_challenge_is_flagged(): void {
		$options              = $this->options();
		$signin               = Ceremony::signin_options();
		$options['challenge'] = $signin['challenge'];
		$credential           = Ceremony::encode( ( new SoftAuthenticator() )->register( $options, Ceremony::ORIGIN ) );
		$this->assert_failed( self::post( 'register', [ 'credential' => $credential ] ), 'registration_failed', 400, true );
	}

	/** 9b: rule M deleted the row: flagged (missing). */
	public function test_9b_email_change_deleted_the_challenge(): void {
		$options = $this->options();
		Clock::set_for_tests( Ceremony::NOW + 60 );
		update_user_meta( 7, 'magicauth_email_changed_at', Ceremony::NOW + 60 );
		ChallengeStore::delete_for_user( 7 );
		Clock::set_for_tests( Ceremony::NOW + 120 );

		$credential = Ceremony::encode( ( new SoftAuthenticator() )->register( $options, Ceremony::ORIGIN ) );
		$this->assert_failed( self::post( 'register', [ 'credential' => $credential ] ), 'registration_failed', 400, true );
	}

	/** 9b: the row escaped the deletion (race): rejected at R-11, flagged. */
	public function test_9b_email_change_with_the_challenge_left_in_place(): void {
		$options = $this->options();
		update_user_meta( 7, 'magicauth_email_changed_at', Ceremony::NOW + 60 );
		Clock::set_for_tests( Ceremony::NOW + 120 );

		$credential = Ceremony::encode( ( new SoftAuthenticator() )->register( $options, Ceremony::ORIGIN ) );
		$this->assert_failed( self::post( 'register', [ 'credential' => $credential ] ), 'registration_failed', 400, true );
		$this->assertSame( 0, Ceremony::count_rows() );
	}

	/* ------------------------------------------------------------------ 10-23: request and ceremony */

	public function test_10_body_cap(): void {
		$credential = Ceremony::encode( ( new SoftAuthenticator() )->register( $this->options(), Ceremony::ORIGIN ) );
		Ceremony::account_post( [ 'credential' => $credential ] );
		$_SERVER['CONTENT_LENGTH'] = '65537';
		$this->assert_failed( Ceremony::call( 'register' ), 'registration_failed', 400 );
		$this->assertSame( 0, Ceremony::count_rows() );
	}

	public function test_10_credential_field_cap_and_shape(): void {
		$this->options();
		$this->assert_failed( self::post( 'register', [ 'credential' => str_repeat( 'a', 24577 ) ] ), 'registration_failed', 400, false, 'over 24576' );
		$this->assert_failed( self::post( 'register' ), 'registration_failed', 400, false, 'absent' );
		$this->assert_failed( self::post( 'register', [ 'credential' => [ 'x' ] ] ), 'registration_failed', 400, false, 'array' );
	}

	public function test_slashed_post_values_are_unslashed(): void {
		$credential = Ceremony::encode( ( new SoftAuthenticator() )->register( $this->options(), Ceremony::ORIGIN ) );
		$response   = self::post(
			'register',
			[
				'credential' => addslashes( $credential ),
				'name'       => addslashes( 'Laptop "work"' ),
			]
		);
		$this->assertSame( 200, $response['status'], $response['body'] );
		$this->assertSame( 'Laptop "work"', $response['data']['passkey']['name'] );
	}

	/** @return array<string,array{array<string,mixed>}> */
	public static function before_r2(): array {
		return [
			'11 non-canonical b64url' => [ [ 'id' => 'AB', 'rawId' => 'AB' ] ],
			'12 id != rawId'          => [ [ 'id' => 'AAAAAAAAAAAAAAAAAAAAAA' ] ],
			'13 type'                 => [ [ 'type' => 'password' ] ],
		];
	}

	/**
	 * Failures before R-2 have no trusted ID: never flagged.
	 *
	 * @dataProvider before_r2
	 * @param array<string,mixed> $mutation
	 */
	public function test_failures_before_r2_are_not_flagged( array $mutation ): void {
		$credential = array_merge( ( new SoftAuthenticator() )->register( $this->options(), Ceremony::ORIGIN ), $mutation );
		$this->assert_failed( self::post( 'register', [ 'credential' => Ceremony::encode( $credential ) ] ), 'registration_failed', 400 );
	}

	/** @return array<string,array{array<string,mixed>}> */
	public static function flagged_failures(): array {
		return [
			'14 crossOrigin true'      => [ [ 'crossOrigin' => true ] ],
			'14 foreign origin'        => [ [ 'origin' => 'https://evil.example' ] ],
			'15 fido-u2f'              => [ [ 'fmt' => 'fido-u2f', 'attStmt' => [ 'sig' => Cbor::bytes( 'x' ), 'x5c' => [ Cbor::bytes( 'c' ) ] ] ] ],
			'15c bad self attestation' => [ [ 'fmt' => 'packed', 'attStmt' => [ 'alg' => -7, 'sig' => Cbor::bytes( random_bytes( 70 ) ) ] ] ],
			'16 rpIdHash example.com'   => [ [ 'rpId' => 'example.com' ] ],
			'17 UV=0'                  => [ [ 'flags' => SoftAuthenticator::FLAG_UP | SoftAuthenticator::FLAG_AT ] ],
			'20 alg -35'               => [ [ 'cose' => [ 3 => -35 ] ] ],
			'23 credProps.rk false'    => [ [ 'credProps_rk' => false ] ],
		];
	}

	/**
	 * 14 to 23 through the endpoint: every failure after R-2 is flagged.
	 *
	 * @dataProvider flagged_failures
	 * @param array<string,mixed> $o
	 */
	public function test_failures_after_r2_are_flagged( array $o ): void {
		$this->assert_failed( $this->register( new SoftAuthenticator(), $o ), 'registration_failed', 400, true );
		$this->assertSame( 0, Ceremony::count_rows() );
		$this->assertSame( 1, self::bucket( Throttle::ACTION_PASSKEY_REGFAIL_USER ), 'counted in passkey_regfail_user' );
	}

	public function test_15b_packed_self_attestation_is_stored(): void {
		$this->assertSame( 200, $this->register( new SoftAuthenticator( 'EdDSA' ), [ 'self_attest' => true ] )['status'] );
		$this->assertSame( 1, Ceremony::count_rows() );
	}

	/* ------------------------------------------------------------------ 24, 25 */

	public function test_24_duplicate_credential_is_never_flagged(): void {
		$auth = new SoftAuthenticator();
		$this->assertSame( 200, $this->register( $auth )['status'] );
		$this->assert_failed( $this->register( $auth ), 'registration_failed', 400, false, 'same user' );

		$other = Ceremony::user( 8 );
		Ceremony::sign_in( $other );
		$this->assert_failed( $this->register( $auth ), 'registration_failed', 400, false, 'other user' );
		$this->assertSame( 1, Ceremony::count_rows() );
	}

	/** @return array<string,array{string}> */
	public static function store_errors(): array {
		return [
			'duplicate SELECT' => [ 'SELECT * FROM wp_magicauth_passkeys WHERE credential_hash' ],
			'INSERT'           => [ 'INSERT INTO wp_magicauth_passkeys' ],
		];
	}

	/**
	 * 24b: no flag, 503, not counted as a registration failure.
	 *
	 * @dataProvider store_errors
	 */
	public function test_24b_store_errors_are_retry( string $pattern ): void {
		global $wpdb;
		$credential = Ceremony::encode( ( new SoftAuthenticator() )->register( $this->options(), Ceremony::ORIGIN ) );
		$wpdb->fail_next_query( $pattern );
		$this->assert_failed( self::post( 'register', [ 'credential' => $credential ] ), 'retry', 503 );
		$this->assertSame( 0, self::bucket( Throttle::ACTION_PASSKEY_REGFAIL_USER ) );
	}

	public function test_25_limit_at_options(): void {
		for ( $i = 0; $i < 10; $i++ ) {
			self::enrolled( $this->user );
		}
		$response = self::post( 'register_options' );
		$this->assert_failed( $response, 'limit_reached', 409 );
		$this->assertSame( 'You have 10 passkeys, which is the maximum. Remove one before you add another.', $response['data']['message'] );
	}

	public function test_25_limit_message_singular(): void {
		add_filter( 'magicauth_passkey_max_per_user', static fn() => 1 );
		self::enrolled( $this->user );
		$this->assertSame( 'You have 1 passkey, which is the maximum. Remove one before you add another.', self::post( 'register_options' )['data']['message'] );
	}

	public function test_25_limit_reached_inside_register_is_flagged(): void {
		for ( $i = 0; $i < 9; $i++ ) {
			self::enrolled( $this->user );
		}
		$credential = Ceremony::encode( ( new SoftAuthenticator() )->register( $this->options(), Ceremony::ORIGIN ) );
		self::enrolled( $this->user );
		$this->assert_failed( self::post( 'register', [ 'credential' => $credential ] ), 'limit_reached', 409, true );
	}

	/* ------------------------------------------------------------------ 26, 27, 30, 31 */

	public function test_26_transports_filtered_and_capped(): void {
		$auth = new SoftAuthenticator( 'ES256', [ 'transports' => [ 'usb', 'bogus', 'nfc', 'usb', 'ble', 'smart-card', 'hybrid', 'cable', 'internal' ] ] );
		$this->register( $auth );
		$row = CredentialStore::find_by_raw_id( $auth->credentialId() );
		$this->assertIsObject( $row );
		$this->assertSame( 'usb,nfc,ble,smart-card,hybrid', $row->transports );
	}

	public function test_27_names(): void {
		$first = $this->register( new SoftAuthenticator(), [], [ 'name' => '<b>Work</b> laptop' ] );
		$this->assertSame( 'Work laptop', $first['data']['passkey']['name'] );

		$this->assert_failed( $this->register( new SoftAuthenticator(), [], [ 'name' => 'WORK LAPTOP' ] ), 'duplicate_name', 400, true );

		$long = $this->register( new SoftAuthenticator(), [], [ 'name' => str_repeat( 'x', 200 ) ] );
		$this->assertSame( str_repeat( 'x', 64 ), $long['data']['passkey']['name'] );

		$over = $this->register( new SoftAuthenticator(), [], [ 'name' => str_repeat( 'y', 257 ) ] );
		$this->assertSame( 'Passkey', $over['data']['passkey']['name'], 'over 256 bytes is ignored' );
	}

	public function test_30_stored_handle_is_the_one_sent_in_the_options(): void {
		$options = $this->options();
		update_user_meta( 7, CredentialStore::HANDLE_META, Base64Url::encode( random_bytes( 64 ) ) );
		$auth = new SoftAuthenticator();
		$this->assertSame( 200, self::post( 'register', [ 'credential' => Ceremony::encode( $auth->register( $options, Ceremony::ORIGIN ) ) ] )['status'] );
		$row = CredentialStore::find_by_raw_id( $auth->credentialId() );
		$this->assertIsObject( $row );
		$this->assertSame( $options['user']['id'], $row->user_handle );
	}

	public function test_31_platform_hint_and_user_agent(): void {
		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15';
		$ipad                       = $this->register( new SoftAuthenticator(), [], [ 'platform' => 'iPad' ] );
		$this->assertSame( 'Passkey on iPad', $ipad['data']['passkey']['name'] );

		$unknown = $this->register( new SoftAuthenticator(), [], [ 'platform' => 'Amiga' ] );
		$this->assertSame( 'Passkey on Mac', $unknown['data']['passkey']['name'], 'unknown hint ignored, UA used' );
	}

	/* ------------------------------------------------------------------ 29: orphan flag matrix */

	public function test_29_throttled_register_is_flagged_for_an_unknown_credential(): void {
		for ( $i = 0; $i < 10; $i++ ) {
			$this->assert_failed( $this->register( new SoftAuthenticator(), [ 'credProps_rk' => false ] ), 'registration_failed', 400, true );
		}
		$this->assertSame( 10, self::bucket( Throttle::ACTION_PASSKEY_REGFAIL_USER ) );

		$auth     = new SoftAuthenticator();
		$response = $this->register( $auth );
		$this->assert_failed( $response, 'throttled', 429, true );
		$this->assertSame( 0, Ceremony::count_rows(), 'not stored' );
	}

	public function test_29_throttled_register_of_a_stored_credential_is_not_flagged(): void {
		$auth = new SoftAuthenticator();
		$this->assertSame( 200, $this->register( $auth )['status'] );
		set_transient( 'magicauth_throttle_' . Throttle::ACTION_PASSKEY_REGFAIL_USER . '_u7', 10, HOUR_IN_SECONDS );
		$this->assert_failed( $this->register( $auth ), 'throttled', 429 );
	}

	public function test_29_throttled_register_with_a_malformed_credential_is_not_flagged(): void {
		set_transient( 'magicauth_throttle_' . Throttle::ACTION_PASSKEY_REGFAIL_USER . '_u7', 10, HOUR_IN_SECONDS );
		$this->assert_failed( self::post( 'register', [ 'credential' => '{"type":"public-key"}' ] ), 'throttled', 429 );
	}

	public function test_29_throttled_flag_lookup_error_is_retry(): void {
		global $wpdb;
		set_transient( 'magicauth_throttle_' . Throttle::ACTION_PASSKEY_REGFAIL_USER . '_u7', 10, HOUR_IN_SECONDS );
		$credential = Ceremony::encode( ( new SoftAuthenticator() )->register( $this->options(), Ceremony::ORIGIN ) );
		$wpdb->fail_next_query( 'SELECT * FROM wp_magicauth_passkeys WHERE credential_hash' );
		$this->assert_failed( self::post( 'register', [ 'credential' => $credential ] ), 'retry', 503 );
	}

	/** 29b: a replay of a successful POST: no unknown_credential key at all. */
	public function test_29b_replay_after_success_is_not_flagged(): void {
		$credential = Ceremony::encode( ( new SoftAuthenticator() )->register( $this->options(), Ceremony::ORIGIN ) );
		$this->assertSame( 200, self::post( 'register', [ 'credential' => $credential ] )['status'] );
		$this->assert_failed( self::post( 'register', [ 'credential' => $credential ] ), 'registration_failed', 400 );
	}

	/** 29b: the first request is still in flight (challenge consumed, no row yet). */
	public function test_29b_replay_while_the_first_is_in_flight_is_not_flagged(): void {
		$options = $this->options();
		$auth    = new SoftAuthenticator();
		$first   = $auth->register( $options, Ceremony::ORIGIN );
		$reason  = null;
		$this->assertNotNull( ChallengeStore::consume( 'register', (string) Base64Url::decode( $options['challenge'], 32, 32 ), $reason ) );
		$this->assert_failed( self::post( 'register', [ 'credential' => Ceremony::encode( $first ) ] ), 'registration_failed', 400 );
	}

	/**
	 * 29b throttled (7.3 condition 1, invariant 8): the first request is in
	 * flight (challenge consumed, no row yet) and the regfail bucket filled
	 * meanwhile: 429 without the key.
	 */
	public function test_29b_throttled_replay_while_the_first_is_in_flight_is_not_flagged(): void {
		$options = $this->options();
		$first   = ( new SoftAuthenticator() )->register( $options, Ceremony::ORIGIN );
		$reason  = null;
		$this->assertNotNull( ChallengeStore::consume( 'register', (string) Base64Url::decode( $options['challenge'], 32, 32 ), $reason ) );
		set_transient( 'magicauth_throttle_' . Throttle::ACTION_PASSKEY_REGFAIL_USER . '_u7', 10, HOUR_IN_SECONDS );
		$this->assert_failed( self::post( 'register', [ 'credential' => Ceremony::encode( $first ) ] ), 'throttled', 429 );
		$this->assertSame( 0, Ceremony::count_rows(), 'not stored' );
	}

	/**
	 * 29b throttled (r1-endpoints-04): the check consumes the unconsumed
	 * challenge, so a second POST with it gets a plain 429 and no lookup.
	 */
	public function test_29b_throttled_check_consumes_the_challenge(): void {
		global $wpdb;
		$options = $this->options();
		$created = ( new SoftAuthenticator() )->register( $options, Ceremony::ORIGIN );
		set_transient( 'magicauth_throttle_' . Throttle::ACTION_PASSKEY_REGFAIL_USER . '_u7', 10, HOUR_IN_SECONDS );
		$this->assert_failed( self::post( 'register', [ 'credential' => Ceremony::encode( $created ) ] ), 'throttled', 429, true );
		$reason = null;
		$this->assertNull( ChallengeStore::consume( 'register', (string) Base64Url::decode( $options['challenge'], 32, 32 ), $reason ), 'consumed' );

		$wpdb->query_log = [];
		$this->assert_failed( self::post( 'register', [ 'credential' => Ceremony::encode( $created ) ] ), 'throttled', 429 );
		foreach ( $wpdb->query_log as $sql ) {
			$this->assertStringNotContainsString( 'wp_magicauth_passkeys ', (string) $sql . ' ', 'no credential lookup' );
		}
	}

	/**
	 * r1-endpoints-04: once throttled, probing arbitrary credential IDs with
	 * no challenge of this user and session gets a plain 429 and no lookup.
	 */
	public function test_29b_throttled_register_is_no_credential_id_oracle(): void {
		global $wpdb;
		set_transient( 'magicauth_throttle_' . Throttle::ACTION_PASSKEY_REGFAIL_USER . '_u7', 10, HOUR_IN_SECONDS );
		$other = Ceremony::user( 8 );
		$probe = Ceremony::registration( new SoftAuthenticator(), $other );
		for ( $i = 0; $i < 3; $i++ ) {
			$wpdb->query_log = [];
			$this->assert_failed( self::post( 'register', [ 'credential' => $probe ] ), 'throttled', 429 );
			foreach ( $wpdb->query_log as $sql ) {
				$this->assertStringNotContainsString( 'wp_magicauth_passkeys ', (string) $sql . ' ', 'no credential lookup' );
			}
		}
	}

	/** 29b throttled: a query error on the challenge read is 503 retry without the key. */
	public function test_29b_throttled_challenge_read_error_is_retry(): void {
		global $wpdb;
		$credential = Ceremony::encode( ( new SoftAuthenticator() )->register( $this->options(), Ceremony::ORIGIN ) );
		set_transient( 'magicauth_throttle_' . Throttle::ACTION_PASSKEY_REGFAIL_USER . '_u7', 10, HOUR_IN_SECONDS );
		$wpdb->fail_next_query( 'SELECT * FROM wp_magicauth_passkey_challenges' );
		$this->assert_failed( self::post( 'register', [ 'credential' => $credential ] ), 'retry', 503 );
		$this->assertSame( 10, self::bucket( Throttle::ACTION_PASSKEY_REGFAIL_USER ), 'not counted' );
	}

	/** 29b throttled (r1-endpoints-04): a challenge that was never issued gets no flag and no lookup. */
	public function test_29b_throttled_unknown_challenge_is_not_flagged(): void {
		$options              = $this->options();
		$options['challenge'] = Base64Url::encode( random_bytes( 32 ) );
		$credential           = Ceremony::encode( ( new SoftAuthenticator() )->register( $options, Ceremony::ORIGIN ) );
		set_transient( 'magicauth_throttle_' . Throttle::ACTION_PASSKEY_REGFAIL_USER . '_u7', 10, HOUR_IN_SECONDS );
		$this->assert_failed( self::post( 'register', [ 'credential' => $credential ] ), 'throttled', 429 );
	}

	/** @return array<string,array{string,array<string,mixed>}> */
	public static function flag_query_errors(): array {
		return [
			'consume SELECT' => [ 'SELECT * FROM wp_magicauth_passkey_challenges', [] ],
			'consume UPDATE' => [ 'UPDATE wp_magicauth_passkey_challenges', [] ],
			'final SELECT'   => [ 'SELECT * FROM wp_magicauth_passkeys WHERE credential_hash', [ 'credProps_rk' => false ] ],
		];
	}

	/**
	 * 29c: 503 retry, no flag key, nothing counted.
	 *
	 * @dataProvider flag_query_errors
	 * @param array<string,mixed> $o
	 */
	public function test_29c_query_errors_are_retry_without_flag( string $pattern, array $o ): void {
		global $wpdb;
		$credential = Ceremony::encode( ( new SoftAuthenticator() )->register( $this->options(), Ceremony::ORIGIN, $o ) );
		$wpdb->fail_next_query( $pattern );
		$this->assert_failed( self::post( 'register', [ 'credential' => $credential ] ), 'retry', 503 );
		$this->assertSame( 0, self::bucket( Throttle::ACTION_PASSKEY_REGFAIL_USER ) );
	}

	/**
	 * 28: a Throwable from inside the library gives the generic failure,
	 * nothing printed.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_28_library_throwable_gives_the_generic_failure(): void {
		require_once dirname( __DIR__ ) . '/Support/library-throws.php';
		$this->setUp();
		$credential                         = Ceremony::encode( ( new SoftAuthenticator( 'EdDSA' ) )->register( $this->options(), Ceremony::ORIGIN, [ 'self_attest' => true ] ) );
		$GLOBALS['magicauth_library_throw'] = new \TypeError( 'boom <b>' );
		$response                           = self::post( 'register', [ 'credential' => $credential ] );
		unset( $GLOBALS['magicauth_library_throw'] );
		$this->assert_failed( $response, 'registration_failed', 400, true );
		$this->assertStringNotContainsString( 'boom', $response['body'] );
	}
}
