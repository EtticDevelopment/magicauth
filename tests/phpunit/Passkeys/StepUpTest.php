<?php
/**
 * T-REAUTH (SPEC 3.5, 6.7, 7.4 step-up, 14.1, build step 11): the step-up
 * endpoints by email code (reauth_email, reauth_code) and by an existing
 * passkey (reauth_options, reauth_passkey), and step-up both ways ending in a
 * fresh session that can register.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Auth\Throttle;
use MagicAuth\Passkeys\Base64Url;
use MagicAuth\Passkeys\ChallengeStore;
use MagicAuth\Passkeys\Clock;
use MagicAuth\Passkeys\CredentialStore;
use MagicAuth\Passkeys\Freshness;
use MagicAuth\Passkeys\Module;
use MagicAuth\Passkeys\SessionState;
use MagicAuth\Tests\Support\Ceremony;
use MagicAuth\Tests\Support\SoftAuthenticator;
use PHPUnit\Framework\TestCase;
use WP_User;

final class StepUpTest extends TestCase {

	private WP_User $user;

	/** @var array<string,mixed> */
	private array $server = [];

	protected function setUp(): void {
		$this->server = $_SERVER;
		Ceremony::site();
		Ceremony::enable_module();
		$this->user = Ceremony::user( 7 );
		// A stale password session: never fresh from its creation stamp.
		Ceremony::sign_in( $this->user, 'password', Ceremony::NOW - 3600 );
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

	/** @param array{status:?int,success:bool,data:array<string,mixed>,body:string} $response */
	private function assert_failed( array $response, string $code, int $status, bool $flag = false, string $message = '' ): void {
		$this->assertSame( $status, $response['status'], $message . ' ' . $response['body'] );
		$this->assertFalse( $response['success'], $message );
		$this->assertSame( $code, $response['data']['code'] ?? null, $message );
		if ( $flag ) {
			$this->assertTrue( $response['data']['unknown_credential'] ?? null, $message . ': flagged' );
		} else {
			$this->assertArrayNotHasKey( 'unknown_credential', $response['data'], $message . ': no flag key' );
		}
	}

	/** @return array{reauth_id:string,code:string} The code from the sent email. */
	private function send_code(): array {
		global $magicauth_test_state;
		$before   = count( $magicauth_test_state['mail'] ?? [] );
		$response = self::post( 'reauth_email' );
		$this->assertSame( 200, $response['status'], $response['body'] );
		$mails = $magicauth_test_state['mail'] ?? [];
		$this->assertCount( $before + 1, $mails );
		$this->assertSame( 1, preg_match( '/confirm it is you: ([0-9A-Z]{3}-[0-9A-Z]{3})/', (string) end( $mails )['alt_body'], $m ) );
		return [
			'reauth_id' => $response['data']['reauth_id'],
			'code'      => str_replace( '-', '', $m[1] ),
		];
	}

	/** Cookies named $name the endpoints set in this test. */
	private static function cookies( string $name ): array {
		global $magicauth_test_state;
		return array_values(
			array_filter(
				$magicauth_test_state['cookies'] ?? [],
				static function ( array $c ) use ( $name ): bool {
					return $name === $c['name'];
				}
			)
		);
	}

	private static function bucket( string $bucket, int $uid = 7 ): int {
		return (int) get_transient( 'magicauth_throttle_' . $bucket . '_u' . $uid );
	}

	private static function enrolled( WP_User $user, array $opts = [] ): SoftAuthenticator {
		$auth = new SoftAuthenticator( 'ES256', $opts + [ 'transports' => [ 'internal' ] ] );
		Ceremony::enrol( $auth, $user );
		return $auth;
	}

	/** Challenge rows, of one ceremony when given (enrolment leaves a register row). */
	private static function challenge_rows( string $ceremony = '' ): int {
		global $wpdb;
		$where = '' !== $ceremony ? $wpdb->prepare( ' WHERE ceremony = %s', $ceremony ) : '';
		return (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . ChallengeStore::table() . $where );
	}

	/** reauth_options, then reauth_passkey with the authenticator's assertion. */
	private function step_up_with( SoftAuthenticator $auth, array $o = [] ): array {
		$options = self::post( 'reauth_options' );
		$this->assertSame( 200, $options['status'], $options['body'] );
		$credential = Ceremony::encode( $auth->assert( $options['data']['publicKey'], Ceremony::ORIGIN, $o ) );
		return self::post( 'reauth_passkey', [ 'credential' => $credential ] );
	}

	/* ------------------------------------------------------------------ gates */

	/** @return array<string,array{string}> */
	public static function handlers(): array {
		return [
			'reauth_email'   => [ 'reauth_email' ],
			'reauth_code'    => [ 'reauth_code' ],
			'reauth_options' => [ 'reauth_options' ],
			'reauth_passkey' => [ 'reauth_passkey' ],
		];
	}

	/** @dataProvider handlers */
	public function test_session_nonce_origin_module_and_disabled_gates( string $handler ): void {
		magicauth_test_login_as( 0 );
		$this->assert_failed( self::post( $handler ), 'not_logged_in', 403 );
		magicauth_test_login_as( 7 );

		Ceremony::account_post( [], 'other' );
		$this->assert_failed( Ceremony::call( $handler ), 'bad_nonce', 403 );

		Ceremony::account_post();
		$_SERVER['HTTP_ORIGIN'] = 'https://evil.example';
		$this->assert_failed( Ceremony::call( $handler ), 'bad_origin', 403 );

		Ceremony::account_post();
		$_SERVER['REQUEST_METHOD'] = 'GET';
		$this->assert_failed( Ceremony::call( $handler ), 'bad_request', 405 );

		update_user_meta( 7, 'magicauth_disabled', 1 );
		$this->assert_failed( self::post( $handler ), 'disabled_user', 403 );
		delete_user_meta( 7, 'magicauth_disabled' );

		update_option( 'magicauth_settings', [ 'passkeys_enabled' => false ] );
		\MagicAuth\Passkeys\Module::reset_for_tests();
		$this->assert_failed( self::post( $handler ), 'unavailable', 404 );
		$this->assertSame( 0, self::challenge_rows() );
	}

	/** @dataProvider handlers */
	public function test_no_session_token_is_refused( string $handler ): void {
		global $magicauth_test_state;
		$magicauth_test_state['session_token'] = '';
		$this->assert_failed( self::post( $handler ), 'reauth_unavailable', 403 );
		$this->assertSame( 0, self::challenge_rows() );
	}

	/** @dataProvider handlers */
	public function test_destroyed_session_record_is_refused( string $handler ): void {
		\WP_Session_Tokens::get_instance( 7 )->destroy_all();
		$this->assert_failed( self::post( $handler ), 'reauth_unavailable', 403 );
	}

	/** 6.1: jitter exactly once per response of the endpoints that take secret input. */
	public function test_jitter_once_per_response_of_code_and_passkey_only(): void {
		global $magicauth_test_state;
		foreach ( [ 'reauth_code' => 1, 'reauth_passkey' => 1, 'reauth_email' => 0, 'reauth_options' => 0 ] as $handler => $expected ) {
			$magicauth_test_state['jitter_calls'] = 0;
			self::post( $handler );
			$this->assertSame( $expected, $magicauth_test_state['jitter_calls'], $handler );

			$magicauth_test_state['jitter_calls'] = 0;
			magicauth_test_login_as( 0 );
			self::post( $handler );
			$this->assertSame( $expected, $magicauth_test_state['jitter_calls'], $handler . ', gate failure' );
			magicauth_test_login_as( 7 );
		}
	}

	/* ------------------------------------------------------------------ email code */

	public function test_email_code_step_up_makes_the_session_fresh(): void {
		global $magicauth_test_state, $wpdb;
		Ceremony::account_post();
		$this->assertSame( 'reauth_required', Ceremony::call( 'register_options' )['data']['code'], 'stale before' );

		$response = self::post( 'reauth_email' );
		$this->assertSame( 200, $response['status'] );
		$this->assertSame( 22, strlen( $response['data']['reauth_id'] ) );
		$this->assertSame( 600, $response['data']['expires_in'] );
		$this->assertSame( 'l***@example.test', $response['data']['sent_to'] );
		$row = $wpdb->get_row( 'SELECT * FROM ' . ChallengeStore::table(), ARRAY_A );
		$this->assertSame( 'reauth_code', $row['ceremony'] );
		$this->assertSame( Freshness::session_hash(), $row['session_hash'] );
		$this->assertSame( gmdate( 'Y-m-d H:i:s', Ceremony::NOW + 600 ), $row['expires_at'] );
		$this->assertSame( 1, $magicauth_test_state['after_response_calls'] ?? 0, 'email after the response' );
		$this->assertSame( 1, preg_match( '/confirm it is you: ([0-9A-Z]{3}-[0-9A-Z]{3})/', (string) $magicauth_test_state['mail'][0]['alt_body'], $m ) );

		Clock::set_for_tests( Ceremony::NOW + 30 );
		$verified = self::post(
			'reauth_code',
			[
				'reauth_id' => $response['data']['reauth_id'],
				'code'      => strtolower( $m[1] ),
			]
		);

		$this->assertSame( 200, $verified['status'], $verified['body'] );
		$this->assertSame( Ceremony::NOW + 30 + 600, $verified['data']['fresh_until'] );
		$state = SessionState::get();
		$this->assertNotNull( $state );
		$this->assertSame( (string) ( Ceremony::NOW + 30 ), (string) $state->reauth_at );
		$this->assertSame( 'email_code', $state->reauth_method );
		$cookie = self::cookies( Freshness::COOKIE );
		$this->assertCount( 1, $cookie );
		$this->assertSame( hash_hmac( 'sha256', 'magicauth-passkey-fresh|' . $cookie[0]['value'], wp_salt( 'auth' ) ), $state->fresh_hash );
		$this->assertSame( 'Strict', $cookie[0]['samesite'] );
		$this->assertTrue( $cookie[0]['httponly'] );
		$this->assertSame( Ceremony::NOW + 30, get_user_meta( 7, 'magicauth_email_verified_at', true ) );
		$this->assertSame( [], $magicauth_test_state['auth_cookies'] ?? [], 'no auth cookie' );

		// The browser now holds the new cookie: the password session is fresh.
		$_COOKIE[ Freshness::COOKIE ] = $cookie[0]['value'];
		Ceremony::account_post();
		$this->assertSame( 200, Ceremony::call( 'register_options' )['status'] );
	}

	public function test_step_up_cookie_is_needed(): void {
		$sent = $this->send_code();
		self::post( 'reauth_code', $sent );
		$_COOKIE[ Freshness::COOKIE ] = str_repeat( 'c', 64 );
		Ceremony::account_post();
		$this->assertSame( 'reauth_required', Ceremony::call( 'register_options' )['data']['code'], 'copied session cookies without the new fresh cookie' );
	}

	public function test_cooldown_with_plural_message(): void {
		$this->send_code();

		$second = self::post( 'reauth_email' );
		$this->assert_failed( $second, 'cooldown', 429 );
		$this->assertSame( 60, $second['data']['retry_after'] );
		$this->assertSame( 'Please wait 60 seconds before you send another code.', $second['data']['message'] );

		Clock::set_for_tests( Ceremony::NOW + 59 );
		$third = self::post( 'reauth_email' );
		$this->assertSame( 1, $third['data']['retry_after'] );
		$this->assertSame( 'Please wait 1 second before you send another code.', $third['data']['message'] );

		Clock::set_for_tests( Ceremony::NOW + 60 );
		global $magicauth_test_state;
		unset( $magicauth_test_state['transients'][ 'magicauth_throttle_' . Throttle::ACTION_PASSKEY_REAUTH_CD . '_u7' ] );
		$this->assertSame( 200, self::post( 'reauth_email' )['status'] );
	}

	public function test_five_codes_per_hour(): void {
		global $magicauth_test_state;
		for ( $i = 0; $i < 5; $i++ ) {
			$this->assertSame( 200, self::post( 'reauth_email' )['status'] );
			unset( $magicauth_test_state['transients'][ 'magicauth_throttle_' . Throttle::ACTION_PASSKEY_REAUTH_CD . '_u7' ] );
		}
		$this->assert_failed( self::post( 'reauth_email' ), 'throttled', 429 );
		$this->assertCount( 5, $magicauth_test_state['mail'] );
	}

	public function test_wrong_code_five_times_then_locked(): void {
		$sent = $this->send_code();
		$wrong = 'ZZZZZZ' === $sent['code'] ? 'YYYYYY' : 'ZZZZZZ';
		for ( $i = 0; $i < 5; $i++ ) {
			$this->assert_failed( self::post( 'reauth_code', [ 'reauth_id' => $sent['reauth_id'], 'code' => $wrong ] ), 'code_invalid', 400 );
		}
		$this->assert_failed( self::post( 'reauth_code', $sent ), 'code_invalid', 400, false, 'right code after five wrong ones' );
		$this->assertNull( SessionState::get() );
	}

	public function test_expired_code(): void {
		$sent = $this->send_code();
		Clock::set_for_tests( Ceremony::NOW + 600 );
		$this->assert_failed( self::post( 'reauth_code', $sent ), 'code_invalid', 400 );
	}

	public function test_code_is_single_use(): void {
		$sent = $this->send_code();
		$this->assertSame( 200, self::post( 'reauth_code', $sent )['status'] );
		Clock::set_for_tests( Ceremony::NOW + 1 );
		$this->assert_failed( self::post( 'reauth_code', $sent ), 'code_invalid', 400 );
	}

	public function test_code_of_another_session(): void {
		$sent = $this->send_code();
		Ceremony::sign_in( $this->user, 'password', Ceremony::NOW - 3600 );
		$this->assert_failed( self::post( 'reauth_code', $sent ), 'code_invalid', 400 );
	}

	public function test_code_of_another_user(): void {
		$sent  = $this->send_code();
		$other = Ceremony::user( 8 );
		Ceremony::sign_in( $other, 'password', Ceremony::NOW - 3600 );
		$this->assert_failed( self::post( 'reauth_code', $sent ), 'code_invalid', 400 );
	}

	/** @return array<string,array{array<string,mixed>}> */
	public static function malformed_codes(): array {
		return [
			'no fields'          => [ [] ],
			'reauth_id 15 bytes' => [ [ 'reauth_id' => Base64Url::encode( random_bytes( 15 ) ), 'code' => 'ABCDEF' ] ],
			'reauth_id padded'   => [ [ 'reauth_id' => Base64Url::encode( random_bytes( 16 ) ) . '==', 'code' => 'ABCDEF' ] ],
			'code too long'      => [ [ 'reauth_id' => Base64Url::encode( random_bytes( 16 ) ), 'code' => str_repeat( 'A', 17 ) ] ],
			'code array'         => [ [ 'reauth_id' => Base64Url::encode( random_bytes( 16 ) ), 'code' => [ 'A' ] ] ],
		];
	}

	/**
	 * @dataProvider malformed_codes
	 * @param array<string,mixed> $fields
	 */
	public function test_malformed_code_requests( array $fields ): void {
		$this->assert_failed( self::post( 'reauth_code', $fields ), 'code_invalid', 400 );
	}

	public function test_code_attempts_are_throttled_per_hour(): void {
		$sent = $this->send_code();
		for ( $i = 0; $i < 20; $i++ ) {
			self::post( 'reauth_code', [ 'reauth_id' => Base64Url::encode( random_bytes( 16 ) ), 'code' => 'ABCDEF' ] );
		}
		$this->assert_failed( self::post( 'reauth_code', $sent ), 'throttled', 429 );
		$this->assertSame( 21, self::bucket( Throttle::ACTION_PASSKEY_REAUTH_TRY_USER ) );
	}

	public function test_email_change_in_this_session_refuses_email_step_up(): void {
		$sent = $this->send_code();
		update_user_meta( 7, 'magicauth_email_changed_at', Ceremony::NOW - 3600 );

		$this->assert_failed( self::post( 'reauth_email' ), 'reauth_unavailable', 403, false, 'change at the stamp' );
		$this->assert_failed( self::post( 'reauth_code', $sent ), 'reauth_unavailable', 403, false, 'code sent before the change' );

		update_user_meta( 7, 'magicauth_email_changed_at', Ceremony::NOW - 3601 );
		$this->assertNotSame( 'reauth_unavailable', self::post( 'reauth_email' )['data']['code'] ?? '', 'change before the session' );
	}

	/** Review r1-rule-01: rule M lands after the code check and before the stamp. */
	public function test_email_change_racing_the_code_check_leaves_no_fresh_stamp(): void {
		global $wpdb;
		Module::setup(); // profile_update -> rule M.
		$sent = $this->send_code();
		Clock::set_for_tests( Ceremony::NOW + 30 );

		$wpdb->before_next_query(
			'/UPDATE wp_magicauth_passkey_sessions SET reauth_at = [1-9]/',
			static function (): void {
				Clock::set_for_tests( Ceremony::NOW + 20 );
				wp_update_user(
					[
						'ID'         => 7,
						'user_email' => 'successor7@example.test',
					]
				);
				Clock::set_for_tests( Ceremony::NOW + 30 );
			}
		);
		$this->assert_failed( self::post( 'reauth_code', $sent ), 'reauth_unavailable', 403 );
		$this->assertSame( Ceremony::NOW + 20, get_user_meta( 7, 'magicauth_email_changed_at', true ), 'rule M ran' );

		$state = SessionState::get();
		$this->assertNotNull( $state );
		$this->assertSame( '0', (string) $state->reauth_at, 'no step-up stamp survives' );
		$this->assertSame( '', get_user_meta( 7, 'magicauth_email_verified_at', true ), 'no rule E stamp from the old mailbox' );

		foreach ( self::cookies( Freshness::COOKIE ) as $cookie ) {
			$_COOKIE[ Freshness::COOKIE ] = $cookie['value'];
		}
		Ceremony::account_post();
		$this->assertSame( 'reauth_required', Ceremony::call( 'register_options' )['data']['code'] ?? null );
	}

	/**
	 * r2-session-01 (2): rule M lands between verify_step_up's row and
	 * revoked() checks and the stamp of a synced passkey (counter 0, no CAS).
	 * The stamp carries the proof time, so the session is not fresh, and the
	 * re-read answers 403 without a surviving stamp.
	 */
	public function test_email_change_racing_the_passkey_step_up_leaves_no_fresh_stamp(): void {
		global $wpdb;
		Module::setup(); // profile_update -> rule M.
		$auth    = self::enrolled( $this->user, [ 'be' => true, 'bs' => true ] );
		$options = self::post( 'reauth_options' );
		$this->assertSame( 200, $options['status'], $options['body'] );
		$credential = Ceremony::encode( $auth->assert( $options['data']['publicKey'], Ceremony::ORIGIN, [] ) );
		Clock::set_for_tests( Ceremony::NOW + 10 );

		$wpdb->before_next_query(
			'/UPDATE wp_magicauth_passkey_sessions SET reauth_at = [1-9]/',
			static function (): void {
				Clock::set_for_tests( Ceremony::NOW + 20 );
				wp_update_user(
					[
						'ID'         => 7,
						'user_email' => 'successor7@example.test',
					]
				);
				Clock::set_for_tests( Ceremony::NOW + 30 );
			}
		);
		$this->assert_failed( self::post( 'reauth_passkey', [ 'credential' => $credential ] ), 'reauth_unavailable', 403 );
		$this->assertSame( Ceremony::NOW + 20, get_user_meta( 7, 'magicauth_email_changed_at', true ), 'rule M ran' );
		$this->assertSame( 0, Ceremony::count_rows(), 'rule M removed the passkey' );

		$state = SessionState::get();
		$this->assertNotNull( $state );
		$this->assertSame( '0', (string) $state->reauth_at, 'no step-up stamp survives' );

		foreach ( self::cookies( Freshness::COOKIE ) as $cookie ) {
			$_COOKIE[ Freshness::COOKIE ] = $cookie['value'];
		}
		$this->assertFalse( Freshness::is_fresh() );
		Ceremony::account_post();
		$this->assertSame( 'reauth_required', Ceremony::call( 'register_options' )['data']['code'] ?? null );
	}

	/** r2-session-01: the step-up stamp holds the proof time, never the later write time. */
	public function test_passkey_step_up_stamp_is_the_proof_time(): void {
		Clock::set_for_tests( Ceremony::NOW + 10 );
		$this->assertTrue( SessionState::stamp_reauth( 'passkey', Ceremony::NOW + 4 ) );
		$this->assertSame( (string) ( Ceremony::NOW + 4 ), (string) SessionState::get()->reauth_at );
		$this->assertTrue( SessionState::stamp_reauth( 'passkey', Ceremony::NOW + 99 ) );
		$this->assertSame( (string) ( Ceremony::NOW + 10 ), (string) SessionState::get()->reauth_at, 'never later than now' );
	}

	public function test_unstamped_session_uses_its_login_time_for_the_email_change_rule(): void {
		Clock::set_for_tests( Ceremony::NOW );
		Ceremony::sign_in( $this->user, null );
		update_user_meta( 7, 'magicauth_email_changed_at', time() + 1 );
		$this->assert_failed( self::post( 'reauth_email' ), 'reauth_unavailable', 403 );
	}

	/** K4: a database error on the code check is 503 retry, not code_invalid, and nothing is stamped. */
	public function test_code_db_errors_fail_closed(): void {
		global $wpdb;
		$sent = $this->send_code();
		foreach ( [ 'SELECT * FROM wp_magicauth_passkey_challenges', 'UPDATE wp_magicauth_passkey_challenges SET attempts', 'UPDATE wp_magicauth_passkey_challenges SET consumed_at' ] as $pattern ) {
			$wpdb->fail_next_query( $pattern );
			$this->assert_failed( self::post( 'reauth_code', $sent ), 'retry', 503 );
			$this->assertSame( [], self::cookies( Freshness::COOKIE ), $pattern );
			$this->assertSame( '', get_user_meta( 7, 'magicauth_email_verified_at', true ), $pattern );
		}
		$this->assertSame( 200, self::post( 'reauth_code', $sent )['status'], 'the code still works' );

		$wpdb->fail_next_query( 'INSERT INTO wp_magicauth_passkey_challenges' );
		global $magicauth_test_state;
		unset( $magicauth_test_state['transients'][ 'magicauth_throttle_' . Throttle::ACTION_PASSKEY_REAUTH_CD . '_u7' ] );
		$this->assert_failed( self::post( 'reauth_email' ), 'retry', 503 );
	}

	public function test_failed_stamp_is_retry_and_sends_no_cookie(): void {
		global $wpdb;
		$sent = $this->send_code();
		$wpdb->fail_next_query( 'UPDATE wp_magicauth_passkey_sessions' );
		$this->assert_failed( self::post( 'reauth_code', $sent ), 'retry', 503 );
		$this->assertSame( [], self::cookies( Freshness::COOKIE ) );
		$this->assertSame( '', get_user_meta( 7, 'magicauth_email_verified_at', true ) );
	}

	/* ------------------------------------------------------------------ passkey */

	public function test_reauth_options_list_the_usable_passkeys(): void {
		global $wpdb;
		$usable  = self::enrolled( $this->user );
		$blocked = self::enrolled( $this->user, [ 'be' => false, 'bs' => false ] );
		$row     = CredentialStore::find_by_raw_id( $blocked->credentialId() );
		$this->assertIsObject( $row );
		CredentialStore::block( (int) $row->id );

		$response = self::post( 'reauth_options' );

		$this->assertSame( 200, $response['status'], $response['body'] );
		$public_key = $response['data']['publicKey'];
		$this->assertSame(
			[
				[
					'type'       => 'public-key',
					'id'         => Base64Url::encode( $usable->credentialId() ),
					'transports' => [ 'internal' ],
				],
			],
			$public_key['allowCredentials']
		);
		$this->assertSame( Ceremony::RP, $public_key['rpId'] );
		$this->assertSame( 'required', $public_key['userVerification'] );
		$this->assertSame( 300000, $public_key['timeout'] );
		$challenge = $wpdb->get_row( 'SELECT * FROM ' . ChallengeStore::table() . " WHERE ceremony = 'reauth'", ARRAY_A );
		$this->assertSame( gmdate( 'Y-m-d H:i:s', Ceremony::NOW + 420 ), $challenge['expires_at'] );
		$this->assertSame( Freshness::session_hash(), $challenge['session_hash'] );
	}

	public function test_reauth_options_without_a_usable_passkey(): void {
		$this->assert_failed( self::post( 'reauth_options' ), 'no_passkey', 409 );

		$blocked = self::enrolled( $this->user, [ 'be' => false, 'bs' => false ] );
		$row     = CredentialStore::find_by_raw_id( $blocked->credentialId() );
		$this->assertIsObject( $row );
		CredentialStore::block( (int) $row->id );
		$this->assert_failed( self::post( 'reauth_options' ), 'no_passkey', 409, false, 'only a blocked one' );
		$this->assertSame( 0, self::challenge_rows( 'reauth' ) );
	}

	public function test_31st_reauth_options_is_throttled_without_a_challenge_row(): void {
		self::enrolled( $this->user );
		for ( $i = 0; $i < 30; $i++ ) {
			$this->assertSame( 200, self::post( 'reauth_options' )['status'] );
		}
		$this->assert_failed( self::post( 'reauth_options' ), 'throttled', 429 );
		$this->assertSame( 30, self::challenge_rows( 'reauth' ) );
		$this->assertSame( 0, self::bucket( Throttle::ACTION_PASSKEY_REAUTH_TRY_USER ) );
	}

	public function test_reauth_options_db_error_is_retry(): void {
		global $wpdb;
		self::enrolled( $this->user );
		$wpdb->fail_next_query( 'SELECT * FROM wp_magicauth_passkeys WHERE user_id' );
		$this->assert_failed( self::post( 'reauth_options' ), 'retry', 503 );
	}

	/** @return array<string,array{string}> */
	public static function algs(): array {
		return [
			'ES256' => [ 'ES256' ],
			'RS256' => [ 'RS256' ],
			'EdDSA' => [ 'EdDSA' ],
		];
	}

	/** @dataProvider algs */
	public function test_passkey_step_up_makes_the_session_fresh( string $alg ): void {
		global $magicauth_test_state;
		$auth = new SoftAuthenticator( $alg, [ 'be' => false, 'bs' => false, 'sign_count' => 4 ] );
		Ceremony::enrol( $auth, $this->user );

		$response = $this->step_up_with( $auth );

		$this->assertSame( 200, $response['status'], $response['body'] );
		$this->assertSame( Ceremony::NOW + 600, $response['data']['fresh_until'] );
		$state = SessionState::get();
		$this->assertNotNull( $state );
		$this->assertSame( 'passkey', $state->reauth_method );
		$row = CredentialStore::find_by_raw_id( $auth->credentialId() );
		$this->assertIsObject( $row );
		$this->assertSame( '5', (string) $row->sign_count, 'counter recorded' );
		$this->assertSame( gmdate( 'Y-m-d H:i:s', Ceremony::NOW ), $row->last_used_at );
		$this->assertSame( [], $magicauth_test_state['auth_cookies'] ?? [], 'no auth cookie (no A-12)' );
		$this->assertSame( '', get_user_meta( 7, 'magicauth_email_verified_at', true ), 'a passkey does not prove the mailbox' );

		$_COOKIE[ Freshness::COOKIE ] = self::cookies( Freshness::COOKIE )[0]['value'];
		Ceremony::account_post();
		$this->assertSame( 200, Ceremony::call( 'register_options' )['status'] );
	}

	/** 7.6 rule M: deleted credentials make passkey step-up impossible; it is not refused by the email rule. */
	public function test_passkey_step_up_is_not_refused_by_an_email_change(): void {
		$auth = self::enrolled( $this->user );
		update_user_meta( 7, 'magicauth_email_changed_at', Ceremony::NOW - 60 );
		$this->assertSame( 200, $this->step_up_with( $auth )['status'] );
	}

	public function test_null_user_handle_is_accepted(): void {
		$auth = self::enrolled( $this->user );
		$this->assertSame( 200, $this->step_up_with( $auth, [ 'userHandle' => null ] )['status'] );
	}

	public function test_wrong_user_handle_is_rejected(): void {
		$auth = self::enrolled( $this->user );
		$this->assert_failed( $this->step_up_with( $auth, [ 'userHandle' => random_bytes( 64 ) ] ), 'reauth_failed', 400 );
		$this->assertNull( SessionState::get() );
	}

	public function test_other_users_credential_is_rejected(): void {
		self::enrolled( $this->user );
		$other = Ceremony::user( 8 );
		$auth  = self::enrolled( $other );
		$this->assert_failed( $this->step_up_with( $auth ), 'reauth_failed', 400 );
		$this->assertNull( SessionState::get() );
	}

	/** Without a userHandle (allowed in a step-up) only the owner check stops another user's passkey. */
	public function test_other_users_credential_without_a_user_handle_is_rejected(): void {
		self::enrolled( $this->user );
		$other = Ceremony::user( 8 );
		$auth  = self::enrolled( $other );
		$this->assert_failed( $this->step_up_with( $auth, [ 'userHandle' => null ] ), 'reauth_failed', 400 );
		$this->assertNull( SessionState::get() );
	}

	public function test_credential_outside_the_allow_list_is_rejected(): void {
		global $wpdb;
		self::enrolled( $this->user );
		$elsewhere = self::enrolled( $this->user );
		$wpdb->query( $wpdb->prepare( 'UPDATE ' . CredentialStore::table() . ' SET rp_id = %s WHERE credential_hash = %s', 'old.example', hash( 'sha256', $elsewhere->credentialId() ) ) );
		$this->assert_failed( $this->step_up_with( $elsewhere ), 'reauth_failed', 400 );
	}

	public function test_blocked_credential_is_rejected(): void {
		$usable  = self::enrolled( $this->user );
		$blocked = self::enrolled( $this->user, [ 'be' => false, 'bs' => false ] );
		$row     = CredentialStore::find_by_raw_id( $blocked->credentialId() );
		$this->assertIsObject( $row );
		CredentialStore::block( (int) $row->id );
		$this->assert_failed( $this->step_up_with( $blocked, [ 'sign_count' => 1000 ] ), 'reauth_failed', 400 );
		unset( $usable );
	}

	/** A former holder's row (7.6 rule X) is not in the allow list and fails the snapshot check. */
	public function test_user_registered_snapshot_mismatch_is_rejected(): void {
		global $wpdb;
		self::enrolled( $this->user );
		$former = self::enrolled( $this->user );
		$wpdb->query( $wpdb->prepare( 'UPDATE ' . CredentialStore::table() . ' SET user_registered = %s WHERE credential_hash = %s', '2025-01-01 10:00:00', hash( 'sha256', $former->credentialId() ) ) );

		$options = self::post( 'reauth_options' )['data']['publicKey'];
		$this->assertCount( 1, $options['allowCredentials'] );
		$credential = Ceremony::encode( $former->assert( $options, Ceremony::ORIGIN ) );
		$this->assert_failed( self::post( 'reauth_passkey', [ 'credential' => $credential ] ), 'reauth_failed', 400 );
		$this->assertNull( SessionState::get() );
	}

	public function test_counter_regression_blocks_the_device_bound_credential(): void {
		$usable = self::enrolled( $this->user );
		$auth   = self::enrolled( $this->user, [ 'be' => false, 'bs' => false, 'sign_count' => 7 ] );
		$this->assert_failed( $this->step_up_with( $auth, [ 'sign_count' => 3 ] ), 'reauth_failed', 400 );
		$row = CredentialStore::find_by_raw_id( $auth->credentialId() );
		$this->assertIsObject( $row );
		$this->assertNotNull( $row->counter_anomaly_at );
		unset( $usable );

		// The blocked email (10.5) went once (build step 13); a later attempt sends no second one.
		global $magicauth_test_state;
		$this->assert_failed( $this->step_up_with( $auth, [ 'sign_count' => 2000 ] ), 'reauth_failed', 400 );
		$blocked = array_values(
			array_filter(
				$magicauth_test_state['mail'] ?? [],
				static fn( array $m ): bool => false !== strpos( (string) $m['subject'], 'was blocked' )
			)
		);
		$this->assertCount( 1, $blocked );
		$this->assertStringContainsString( 'Passkey ending in ' . strtoupper( substr( (string) $row->credential_hash, -4 ) ), $blocked[0]['alt_body'] );
	}

	public function test_unknown_credential_is_flagged(): void {
		self::enrolled( $this->user );
		$this->assert_failed( $this->step_up_with( new SoftAuthenticator() ), 'reauth_failed', 400, true );
	}

	public function test_bad_signature_is_not_flagged(): void {
		$auth = self::enrolled( $this->user );
		$this->assert_failed( $this->step_up_with( $auth, [ 'signature' => random_bytes( 70 ) ] ), 'reauth_failed', 400 );
	}

	public function test_uv_is_required(): void {
		$auth = self::enrolled( $this->user );
		$this->assert_failed( $this->step_up_with( $auth, [ 'flags' => SoftAuthenticator::FLAG_UP | SoftAuthenticator::FLAG_BE | SoftAuthenticator::FLAG_BS ] ), 'reauth_failed', 400 );
	}

	public function test_challenge_of_another_session_is_rejected(): void {
		$auth    = self::enrolled( $this->user );
		$options = self::post( 'reauth_options' )['data']['publicKey'];
		Ceremony::sign_in( $this->user, 'password', Ceremony::NOW - 3600 );
		$credential = Ceremony::encode( $auth->assert( $options, Ceremony::ORIGIN ) );
		$this->assert_failed( self::post( 'reauth_passkey', [ 'credential' => $credential ] ), 'reauth_failed', 400 );
	}

	public function test_signin_challenge_is_rejected(): void {
		$auth       = self::enrolled( $this->user );
		$credential = Ceremony::encode( $auth->assert( Ceremony::signin_options(), Ceremony::ORIGIN ) );
		$this->assert_failed( self::post( 'reauth_passkey', [ 'credential' => $credential ] ), 'reauth_failed', 400 );
	}

	public function test_challenge_is_single_use(): void {
		$auth    = self::enrolled( $this->user );
		$options = self::post( 'reauth_options' )['data']['publicKey'];
		$credential = Ceremony::encode( $auth->assert( $options, Ceremony::ORIGIN ) );
		$this->assertSame( 200, self::post( 'reauth_passkey', [ 'credential' => $credential ] )['status'] );
		$this->assert_failed( self::post( 'reauth_passkey', [ 'credential' => $credential ] ), 'reauth_failed', 400 );
	}

	public function test_expired_challenge_is_rejected(): void {
		$auth    = self::enrolled( $this->user );
		$options = self::post( 'reauth_options' )['data']['publicKey'];
		Clock::set_for_tests( Ceremony::NOW + 420 );
		$credential = Ceremony::encode( $auth->assert( $options, Ceremony::ORIGIN ) );
		$this->assert_failed( self::post( 'reauth_passkey', [ 'credential' => $credential ] ), 'reauth_failed', 400 );
	}

	/** @return array<string,array{string}> */
	public static function passkey_db_errors(): array {
		return [
			'consume SELECT' => [ 'SELECT * FROM wp_magicauth_passkey_challenges' ],
			'consume UPDATE' => [ 'UPDATE wp_magicauth_passkey_challenges' ],
			'lookup'         => [ 'SELECT * FROM wp_magicauth_passkeys WHERE credential_hash' ],
			'stamp'          => [ 'UPDATE wp_magicauth_passkey_sessions' ],
		];
	}

	/**
	 * Injected DB error: 503 retry without the flag.
	 *
	 * @dataProvider passkey_db_errors
	 */
	public function test_passkey_db_errors_are_retry_without_flag( string $pattern ): void {
		global $wpdb;
		$auth = self::enrolled( $this->user );
		// A stored credential for the stamp case; an unknown one otherwise, so a
		// lookup that failed open would show as the flag.
		$signer     = 'UPDATE wp_magicauth_passkey_sessions' === $pattern ? $auth : new SoftAuthenticator();
		$options    = self::post( 'reauth_options' )['data']['publicKey'];
		$credential = Ceremony::encode( $signer->assert( $options, Ceremony::ORIGIN ) );
		$wpdb->fail_next_query( $pattern );
		$this->assert_failed( self::post( 'reauth_passkey', [ 'credential' => $credential ] ), 'retry', 503 );
		$this->assertSame( [], self::cookies( Freshness::COOKIE ) );
	}

	public function test_passkey_attempts_are_throttled_per_hour(): void {
		$auth = self::enrolled( $this->user );
		for ( $i = 0; $i < 20; $i++ ) {
			self::post( 'reauth_passkey', [ 'credential' => '{}' ] );
		}
		$this->assert_failed( $this->step_up_with( $auth ), 'throttled', 429 );
	}

	public function test_malformed_credentials(): void {
		self::enrolled( $this->user );
		$this->assert_failed( self::post( 'reauth_passkey' ), 'reauth_failed', 400, false, 'absent' );
		$this->assert_failed( self::post( 'reauth_passkey', [ 'credential' => str_repeat( 'a', 24577 ) ] ), 'reauth_failed', 400, false, 'over the cap' );
		Ceremony::account_post( [ 'credential' => '{}' ] );
		$_SERVER['CONTENT_LENGTH'] = '70000';
		$this->assert_failed( Ceremony::call( 'reauth_passkey' ), 'reauth_failed', 400, false, 'body cap' );
	}
}
