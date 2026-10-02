<?php
/**
 * Rule M and the proof time (review r2-session-01): a sign-in is judged by
 * when its proof was checked, not when the session is written. An email
 * change (SPEC 7.6 rule M) that lands between a link, code or passkey
 * completion check and Login::establish() must leave a session that is not
 * fresh and no rule E mailbox proof. The passkey step-up race is in
 * StepUpTest.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Auth\Controller;
use MagicAuth\Auth\Login;
use MagicAuth\Auth\TokenManager;
use MagicAuth\Passkeys\Clock;
use MagicAuth\Passkeys\Freshness;
use MagicAuth\Passkeys\Module;
use MagicAuth\Passkeys\SignInEndpoints;
use MagicAuth\Tests\Stubs\JsonResponseSent;
use MagicAuth\Tests\Stubs\RedirectSent;
use MagicAuth\Tests\Support\Ceremony;
use MagicAuth\Tests\Support\SoftAuthenticator;
use PHPUnit\Framework\TestCase;
use WP_User;

final class ProofTimeRaceTest extends TestCase {

	private WP_User $user;

	/** @var array<string,mixed> */
	private array $server = [];

	protected function setUp(): void {
		$this->server = $_SERVER;
		Ceremony::site();
		Ceremony::enable_module();
		Module::reset_for_tests();
		$this->user             = Ceremony::user( 7 );
		$this->user->user_login = 'learner7';
		Module::setup(); // profile_update -> rule M.
		$_COOKIE                = [];
		$_SERVER['REMOTE_ADDR'] = '203.0.113.10';
	}

	protected function tearDown(): void {
		$_SERVER  = $this->server;
		$_GET     = [];
		$_POST    = [];
		$_REQUEST = [];
		$_COOKIE  = [];
		magicauth_test_reset_state();
	}

	/**
	 * Rule M at NOW + 1 from inside establish(), after the proof was checked
	 * at NOW and before the cookie; the write then happens at NOW + 2.
	 */
	private static function email_change_before_the_cookie(): void {
		$done = false;
		add_action(
			'magicauth_pre_set_auth_cookie',
			static function () use ( &$done ): void {
				if ( $done ) {
					return;
				}
				$done = true;
				Clock::set_for_tests( Ceremony::NOW + 1 );
				wp_update_user(
					[
						'ID'         => 7,
						'user_email' => 'successor7@example.test',
					]
				);
				Clock::set_for_tests( Ceremony::NOW + 2 );
			}
		);
	}

	/** Makes the session establish() created this request's, with its fresh cookie. */
	private static function use_new_session(): void {
		global $magicauth_test_state;
		$cookies = $magicauth_test_state['auth_cookies'] ?? [];
		$magicauth_test_state['session_token'] = (string) end( $cookies )['token'];
		foreach ( $magicauth_test_state['cookies'] ?? [] as $c ) {
			if ( Freshness::COOKIE === ( $c['name'] ?? '' ) && '' !== ( $c['value'] ?? '' ) ) {
				$_COOKIE[ Freshness::COOKIE ] = $c['value'];
			}
		}
	}

	private function assert_signed_in_but_not_fresh( string $method ): void {
		$this->assertSame( 7, get_current_user_id(), 'the sign-in itself still happens' );
		$this->assertSame( Ceremony::NOW + 1, get_user_meta( 7, 'magicauth_email_changed_at', true ), 'rule M ran' );
		self::use_new_session();
		$session = Freshness::session();
		$this->assertIsArray( $session );
		$this->assertSame( $method, $session['magicauth_method'] );
		$this->assertLessThanOrEqual( Ceremony::NOW + 1, $session['magicauth_auth_at'], 'stamped with the proof time' );
		$this->assertArrayHasKey( Freshness::COOKIE, $_COOKIE, 'the fresh cookie was issued' );
		$this->assertFalse( Freshness::is_fresh(), 'a proof made before the email change is not fresh' );
		Ceremony::account_post();
		$this->assertSame( 'reauth_required', Ceremony::call( 'register_options' )['data']['code'] ?? null, 'no passkey can be added' );
	}

	/**
	 * (1) Link: the current-address check passed at NOW, rule M ran in the
	 * jitter gap.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_email_change_racing_a_link_sign_in_gives_no_fresh_session(): void {
		$issued = TokenManager::issue( 7, 'learner7@example.test' );
		$this->assertIsArray( $issued );
		parse_str( (string) wp_parse_url( (string) $issued['link_url'], PHP_URL_QUERY ), $_GET );
		self::email_change_before_the_cookie();

		Controller::maybe_handle_verify_get();

		$this->assertSame( '', get_user_meta( 7, 'magicauth_email_verified_at', true ), 'no rule E proof from the old mailbox' );
		$this->assert_signed_in_but_not_fresh( 'link' );
	}

	/** (1) Code: same race on the code path. */
	public function test_email_change_racing_a_code_sign_in_gives_no_fresh_session(): void {
		$issued = TokenManager::issue( 7, 'learner7@example.test' );
		$this->assertIsArray( $issued );
		set_transient(
			'magicauth_session_race1',
			[
				'email'    => 'learner7@example.test',
				'selector' => (string) $issued['selector'],
				'attempts' => 0,
			],
			1800
		);
		$_COOKIE['magicauth_session'] = 'race1';
		self::email_change_before_the_cookie();

		Controller::handle_code_submit( (string) $issued['code_plaintext'], 'https://example.test/course/', magicauth_hash_ip( '203.0.113.10' ) );
		unset( $_COOKIE['magicauth_session'] );

		$this->assertSame( '', get_user_meta( 7, 'magicauth_email_verified_at', true ), 'no rule E proof from the old mailbox' );
		$this->assert_signed_in_but_not_fresh( 'code' );
	}

	/** (3) Passkey: a completion token issued at NOW, rule M before complete() stamps. */
	public function test_email_change_racing_a_passkey_completion_gives_no_fresh_session(): void {
		global $magicauth_test_state;
		$magicauth_test_state['redirect_throws'] = true;
		$auth                                    = new SoftAuthenticator( 'ES256', [ 'be' => true, 'bs' => true ] );
		Ceremony::enrol( $auth, $this->user );

		self::anonymous_post( [] );
		$options = self::json( 'options' );
		$this->assertSame( 200, $options['status'] );
		self::anonymous_post( [ 'credential' => Ceremony::encode( $auth->assert( $options['data']['publicKey'], Ceremony::ORIGIN, [] ) ) ] );
		$verify = self::json( 'verify' );
		$this->assertSame( 200, $verify['status'] );

		self::email_change_before_the_cookie();
		self::anonymous_post(
			[
				'action'      => 'magicauth_passkey_complete',
				'token'       => (string) $verify['data']['complete'],
				'redirect_to' => '',
				'return_to'   => 'https://academy.example.com/login/',
			]
		);
		ob_start();
		try {
			SignInEndpoints::complete();
			$this->fail( 'complete sent no redirect' );
		} catch ( RedirectSent $sent ) {
			$this->assertStringNotContainsString( 'magicauth_passkey_error', $sent->location );
		} finally {
			ob_end_clean();
		}

		$this->assert_signed_in_but_not_fresh( 'passkey' );
		$this->assertSame( Ceremony::NOW, Freshness::session()['magicauth_auth_at'], 'the completion token issue time' );
	}

	/** Without a race the stamp is still the proof time and the session is fresh. */
	public function test_link_sign_in_without_a_change_is_fresh(): void {
		$this->assertSame( Login::SIGNED_IN, Login::establish( $this->user, 'link', Ceremony::NOW - 1 ) );
		self::use_new_session();
		$this->assertSame( Ceremony::NOW - 1, Freshness::session()['magicauth_auth_at'] );
		$this->assertSame( Ceremony::NOW, get_user_meta( 7, 'magicauth_email_verified_at', true ) );
		$this->assertTrue( Freshness::is_fresh() );
	}

	/** The rule E proof stands only for a proof made after the last email change. */
	public function test_mailbox_proof_is_judged_by_the_proof_time(): void {
		update_user_meta( 7, 'magicauth_email_changed_at', Ceremony::NOW - 10 );
		$this->assertFalse( Login::record_mailbox_proof( 7, Ceremony::NOW - 10 ), 'same second as the change' );
		$this->assertSame( '', get_user_meta( 7, 'magicauth_email_verified_at', true ) );
		$this->assertFalse( Login::record_mailbox_proof( 7, Ceremony::NOW - 20 ), 'before the change' );
		$this->assertSame( '', get_user_meta( 7, 'magicauth_email_verified_at', true ) );
		$this->assertTrue( Login::record_mailbox_proof( 7, Ceremony::NOW - 9 ), 'after the change' );
		$this->assertSame( Ceremony::NOW, get_user_meta( 7, 'magicauth_email_verified_at', true ) );
	}

	/** @param array<string,mixed> $fields */
	private static function anonymous_post( array $fields ): void {
		global $magicauth_test_state;
		magicauth_test_login_as( 0 );
		unset( $magicauth_test_state['session_token'] );
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$_SERVER['HTTP_ORIGIN']    = Ceremony::ORIGIN;
		unset( $_SERVER['HTTP_REFERER'], $_SERVER['CONTENT_LENGTH'], $_SERVER['HTTP_SEC_FETCH_SITE'], $_SERVER['HTTP_SEC_FETCH_MODE'] );
		$_POST    = $fields;
		$_REQUEST = $fields;
		$_COOKIE  = [ SignInEndpoints::BIND_COOKIE => Ceremony::COOKIE ];
		$magicauth_test_state['cookies'] = [];
	}

	/** @return array{status:?int,data:array<string,mixed>} */
	private static function json( string $handler ): array {
		ob_start();
		try {
			call_user_func( [ SignInEndpoints::class, $handler ] );
		} catch ( JsonResponseSent $sent ) {
			ob_end_clean();
			$payload = is_array( $sent->payload ) ? $sent->payload : [];
			return [
				'status' => $sent->status,
				'data'   => is_array( $payload['data'] ?? null ) ? $payload['data'] : [],
			];
		}
		ob_end_clean();
		throw new \RuntimeException( $handler . ' sent no response' );
	}
}
