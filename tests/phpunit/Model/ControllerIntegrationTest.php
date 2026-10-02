<?php
/**
 * Controller integration tests for the throttle enforcement that the
 * security review flagged on 2026-05-02.
 *
 * Exercises handle_email_request directly: pre-pin the IP or email throttle,
 * then assert that the call inserts NO row and sends NO mail. Verifies the
 * fix for the link-request-throttle-discarded-return bug.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Model;

use MagicAuth\Admin\UserProfile;
use MagicAuth\Auth\Controller;
use MagicAuth\Auth\Throttle;
use MagicAuth\Auth\TokenManager;
use MagicAuth\Passkeys\Clock;
use MagicAuth\Tests\Stubs\JsonResponseSent;
use PHPUnit\Framework\TestCase;

final class ControllerIntegrationTest extends TestCase {

	private const USER_ID = 700;
	private const EMAIL   = 'integration@example.test';

	protected function setUp(): void {
		magicauth_test_reset_state();
		magicauth_test_register_user( self::USER_ID, self::EMAIL );
	}

	private function token_count(): int {
		global $wpdb;
		return (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . TokenManager::table() );
	}

	private function mail_count(): int {
		global $magicauth_test_state;
		return count( $magicauth_test_state['mail'] ?? [] );
	}

	public function test_link_request_passes_through_when_under_throttle(): void {
		Controller::handle_email_request( self::EMAIL, 'https://example.test/sign-in', magicauth_hash_ip( '203.0.113.1' ) );

		$this->assertSame( 1, $this->token_count(), 'Token row issued on happy path' );
		$this->assertSame( 1, $this->mail_count(), 'Mail dispatched on happy path' );
	}

	public function test_per_ip_throttle_blocks_issuance_and_mail(): void {
		$ip_hmac = magicauth_hash_ip( '203.0.113.42' );

		// Pin the per-IP link counter to its cap (10 by default). The 11th
		// allow_link_request_ip() call will return false; handle_email_request
		// must short-circuit on that.
		for ( $i = 0; $i < 10; $i++ ) {
			Throttle::allow_link_request_ip( $ip_hmac );
		}

		Controller::handle_email_request( self::EMAIL, 'https://example.test/sign-in', $ip_hmac );

		$this->assertSame( 0, $this->token_count(), 'No token issued when per-IP throttle is over cap' );
		$this->assertSame( 0, $this->mail_count(), 'No mail sent when per-IP throttle is over cap' );
	}

	public function test_per_email_throttle_blocks_issuance_and_mail(): void {
		// v1.3.6: per-email throttle is now a 60s cooldown (was a 3/15min cap).
		// One call sets the cooldown; the next handle_email_request must
		// short-circuit before issuance or mail.
		$email_hmac = magicauth_hash_email( self::EMAIL );
		Throttle::allow_link_request_email( $email_hmac );

		Controller::handle_email_request( self::EMAIL, 'https://example.test/sign-in', magicauth_hash_ip( '203.0.113.7' ) );

		$this->assertSame( 0, $this->token_count(), 'No token issued during the per-email cooldown' );
		$this->assertSame( 0, $this->mail_count(), 'No mail sent during the per-email cooldown' );
	}

	public function test_per_email_cooldown_emits_blocked_envelope_with_secs(): void {
		$email_hmac = magicauth_hash_email( self::EMAIL );
		Throttle::allow_link_request_email( $email_hmac );

		Controller::handle_email_request( self::EMAIL, 'https://example.test/sign-in', magicauth_hash_ip( '203.0.113.71' ) );

		global $magicauth_test_state;
		$last = end( $magicauth_test_state['redirects'] );
		$this->assertIsArray( $last );
		$this->assertStringContainsString(
			'magicauth_blocked=email_cooldown',
			(string) $last['location'],
			'Per-email cooldown short-circuit must surface the blocked reason'
		);
		$this->assertStringContainsString(
			'magicauth_block_secs=',
			(string) $last['location'],
			'Cooldown path must emit remaining seconds for accurate toast copy'
		);
	}

	public function test_per_ip_link_throttle_emits_blocked_ip_link(): void {
		$ip_hmac = magicauth_hash_ip( '203.0.113.72' );
		for ( $i = 0; $i < 10; $i++ ) {
			Throttle::allow_link_request_ip( $ip_hmac );
		}

		Controller::handle_email_request( self::EMAIL, 'https://example.test/sign-in', $ip_hmac );

		global $magicauth_test_state;
		$last = end( $magicauth_test_state['redirects'] );
		$this->assertStringContainsString( 'magicauth_blocked=ip_link', (string) $last['location'] );
	}

	public function test_per_ip_code_throttle_emits_blocked_ip_code(): void {
		$ip_hmac = magicauth_hash_ip( '203.0.113.73' );
		for ( $i = 0; $i < 20; $i++ ) {
			Throttle::allow_code_submit_ip( $ip_hmac );
		}

		Controller::handle_code_submit( 'AAA-AAA', 'https://example.test/sign-in', $ip_hmac );

		global $magicauth_test_state;
		$last = end( $magicauth_test_state['redirects'] );
		$this->assertStringContainsString( 'magicauth_blocked=ip_code', (string) $last['location'] );
	}

	public function test_email_request_redirect_carries_step_code_without_error_flag(): void {
		Controller::handle_email_request( self::EMAIL, 'https://example.test/sign-in', magicauth_hash_ip( '203.0.113.10' ) );

		global $magicauth_test_state;
		$last = end( $magicauth_test_state['redirects'] );
		$this->assertIsArray( $last );
		$this->assertStringContainsString( 'magicauth_step=code', (string) $last['location'] );
		$this->assertStringNotContainsString(
			'magicauth_error=1',
			(string) $last['location'],
			'Happy email-request must NOT set magicauth_error — that flag is only for code-submit retries'
		);
	}

	public function test_code_submit_wrong_code_redirects_with_error_flag(): void {
		// Issue first so a token row + session_email exist for the code submit.
		Controller::handle_email_request( self::EMAIL, 'https://example.test/sign-in', magicauth_hash_ip( '203.0.113.20' ) );

		// Look up the session id we just minted; the helper writes into a
		// transient keyed by the session id, and we don't have direct cookie
		// access in the shim, so prime $_COOKIE manually.
		global $magicauth_test_state;
		foreach ( array_keys( $magicauth_test_state['transients'] ) as $key ) {
			if ( 0 === strpos( $key, 'magicauth_session_' ) ) {
				$_COOKIE['magicauth_session'] = substr( $key, strlen( 'magicauth_session_' ) );
				break;
			}
		}

		// Submit a deliberately wrong code.
		Controller::handle_code_submit( 'AAA-AAA', 'https://example.test/sign-in', magicauth_hash_ip( '203.0.113.21' ) );

		$last = end( $magicauth_test_state['redirects'] );
		$this->assertIsArray( $last );
		$this->assertStringContainsString( 'magicauth_step=code', (string) $last['location'] );
		$this->assertStringContainsString(
			'magicauth_error=1',
			(string) $last['location'],
			'Wrong-code retry must set magicauth_error so the error toast renders'
		);

		unset( $_COOKIE['magicauth_session'] );
	}

	public function test_code_submit_throttled_redirects_with_error_flag(): void {
		// Pre-pin per-IP code-submit throttle (cap = 20).
		$ip_hmac = magicauth_hash_ip( '203.0.113.30' );
		for ( $i = 0; $i < 20; $i++ ) {
			Throttle::allow_code_submit_ip( $ip_hmac );
		}

		Controller::handle_code_submit( 'AAA-AAA', 'https://example.test/sign-in', $ip_hmac );

		global $magicauth_test_state;
		$last = end( $magicauth_test_state['redirects'] );
		$this->assertStringContainsString(
			'magicauth_error=1',
			(string) $last['location'],
			'Throttled code-submit looks identical to wrong-code: same envelope flag'
		);
	}

	public function test_successful_code_submit_clears_session_transient(): void {
		// State A → State B: lays down a session_email transient + cookie value.
		Controller::handle_email_request( self::EMAIL, 'https://example.test/sign-in', magicauth_hash_ip( '203.0.113.40' ) );

		// Pull the session id from the transient table (no cookies in tests).
		global $magicauth_test_state, $wpdb;
		$session_id = '';
		foreach ( array_keys( $magicauth_test_state['transients'] ) as $key ) {
			if ( 0 === strpos( $key, 'magicauth_session_' ) ) {
				$session_id = substr( $key, strlen( 'magicauth_session_' ) );
				break;
			}
		}
		$this->assertNotSame( '', $session_id, 'session was set up by handle_email_request' );
		$_COOKIE['magicauth_session'] = $session_id;

		// Read the issued plaintext code from the row so we can present it.
		$row = $wpdb->get_row( 'SELECT * FROM ' . TokenManager::table() . ' ORDER BY id DESC LIMIT 1' );
		$this->assertNotNull( $row );

		// Drive a code-submit happy path. We don't have the plaintext code
		// locally, so set up a fresh issuance and grab it from the issue() return.
		magicauth_test_reset_state();
		magicauth_test_register_user( self::USER_ID, self::EMAIL );
		$issued = TokenManager::issue( self::USER_ID, self::EMAIL );
		$this->assertIsArray( $issued );
		set_transient(
			'magicauth_session_test',
			[ 'email' => self::EMAIL, 'selector' => (string) $issued['selector'], 'attempts' => 0 ],
			1800
		);
		$_COOKIE['magicauth_session'] = 'test';

		Controller::handle_code_submit( (string) $issued['code_plaintext'], 'https://example.test/sign-in', magicauth_hash_ip( '203.0.113.41' ) );

		$this->assertFalse(
			get_transient( 'magicauth_session_test' ),
			'set_auth_cookie_or_retry must call end_session() so the State-A→B handle does not survive sign-in'
		);
		$this->assertSame(
			self::USER_ID,
			$magicauth_test_state['auth_cookie_set_for'] ?? 0,
			'wp_set_auth_cookie was invoked for the resolved user'
		);

		unset( $_COOKIE['magicauth_session'] );
	}

	public function test_redirect_to_default_setting_honored_when_no_explicit_redirect(): void {
		// 'home' setting → default redirect should be home_url('/'), even though
		// the user can read /wp-admin.
		update_option( 'magicauth_settings', [ 'redirect_to_default' => 'home' ] );

		$issued = TokenManager::issue( self::USER_ID, self::EMAIL );
		$this->assertIsArray( $issued );
		set_transient(
			'magicauth_session_t2',
			[ 'email' => self::EMAIL, 'selector' => (string) $issued['selector'], 'attempts' => 0 ],
			1800
		);
		$_COOKIE['magicauth_session'] = 't2';

		Controller::handle_code_submit( (string) $issued['code_plaintext'], 'https://example.test/sign-in', magicauth_hash_ip( '203.0.113.50' ) );

		global $magicauth_test_state;
		$last = end( $magicauth_test_state['redirects'] );
		$this->assertSame( 'https://example.test/sign-in', (string) $last['location'], 'explicit form redirect_to wins over default' );

		unset( $_COOKIE['magicauth_session'] );

		// Now without an explicit redirect_to: should land on home.
		$issued2 = TokenManager::issue( self::USER_ID, self::EMAIL );
		set_transient(
			'magicauth_session_t3',
			[ 'email' => self::EMAIL, 'selector' => (string) $issued2['selector'], 'attempts' => 0 ],
			1800
		);
		$_COOKIE['magicauth_session'] = 't3';

		Controller::handle_code_submit( (string) $issued2['code_plaintext'], '', magicauth_hash_ip( '203.0.113.51' ) );

		$last = end( $magicauth_test_state['redirects'] );
		$this->assertSame( 'https://example.test/', (string) $last['location'], 'redirect_to_default=home routes here' );

		unset( $_COOKIE['magicauth_session'] );
	}

	public function test_email_request_dispatches_mail_through_after_response_helper(): void {
		// A1 regression: SMTP must be deferred so latency can't leak account existence.
		global $magicauth_test_state;
		$before = (int) ( $magicauth_test_state['after_response_calls'] ?? 0 );

		Controller::handle_email_request( self::EMAIL, 'https://example.test/sign-in', magicauth_hash_ip( '203.0.113.61' ) );

		$this->assertGreaterThan(
			$before,
			(int) ( $magicauth_test_state['after_response_calls'] ?? 0 ),
			'magic-link dispatch must go through magicauth_dispatch_after_response'
		);
	}

	public function test_lostpassword_dispatches_through_after_response_helper(): void {
		// A1 regression: retrieve_password() must NOT run synchronously, or its
		// SMTP latency leaks whether the account exists.
		global $magicauth_test_state;
		$magicauth_test_state['retrieve_password_calls'] = 0;

		$_POST   = [
			'magicauth_nonce'   => wp_create_nonce( 'magicauth_lostpassword' ),
			'magicauth_website' => '',
			'magicauth_ts'      => (string) ( time() - 5 ),
			'user_login'        => self::EMAIL,
			'redirect_to'       => 'https://example.test/sign-in',
		];
		$_SERVER = [
			'HTTP_ORIGIN'  => 'https://example.test',
			'HTTP_REFERER' => 'https://example.test/wp-login.php',
			'REMOTE_ADDR'  => '203.0.113.62',
		];

		$before = (int) ( $magicauth_test_state['after_response_calls'] ?? 0 );

		Controller::handle_lostpassword_post();

		$this->assertGreaterThan(
			$before,
			(int) ( $magicauth_test_state['after_response_calls'] ?? 0 ),
			'handle_lostpassword_post must defer retrieve_password() through magicauth_dispatch_after_response'
		);
		$this->assertSame(
			1,
			(int) ( $magicauth_test_state['retrieve_password_calls'] ?? 0 ),
			'retrieve_password() runs once (inside the deferred callback)'
		);

		$_POST = [];
		$_SERVER = [];
	}

	public function test_invalid_email_does_not_pin_per_email_counter(): void {
		// IP throttle MUST still increment for malformed inputs (DoS defense).
		// Per-email cooldown only triggers after the email validates.
		$ip_hmac    = magicauth_hash_ip( '203.0.113.99' );
		$email_hmac = magicauth_hash_email( 'totally-not-an-email' );

		Controller::handle_email_request( 'totally-not-an-email', 'https://example.test/sign-in', $ip_hmac );

		// IP throttle counter went up.
		$this->assertSame( 1, (int) get_transient( 'magicauth_throttle_link_ip_' . $ip_hmac ) );
		// Per-email cooldown was not set (no real email to attribute it to).
		$this->assertFalse( get_transient( 'magicauth_throttle_link_email_cd_' . $email_hmac ) );

		$this->assertSame( 0, $this->token_count() );
	}

	/* ------------------------------------------------------------------
	 * T-CTRL (SPEC 15 step 3, 4.4): Controller completes every sign-in
	 * through Auth\Login. B2 (no session swap on code, password, reset),
	 * B3 (per-user disable at consume), hook $method arguments.
	 * ---------------------------------------------------------------- */

	private const OTHER_ID    = 701;
	private const OTHER_EMAIL = 'someone-else@example.test';

	/** Issues a token and primes the state-B session; returns the plaintext code and selector. */
	private function prime_code( string $sid ): array {
		$issued = TokenManager::issue( self::USER_ID, self::EMAIL );
		$this->assertIsArray( $issued );
		set_transient(
			'magicauth_session_' . $sid,
			[ 'email' => self::EMAIL, 'selector' => (string) $issued['selector'], 'attempts' => 0 ],
			1800
		);
		$_COOKIE['magicauth_session'] = $sid;
		return [ (string) $issued['code_plaintext'], (string) $issued['selector'] ];
	}

	/** @return array{consumed_at:?string,use_count:int} */
	private function row_state( string $selector ): array {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT consumed_at, use_count FROM ' . TokenManager::table() . ' WHERE selector = %s', $selector ) );
		$this->assertNotNull( $row );
		return [
			'consumed_at' => null === $row->consumed_at ? null : (string) $row->consumed_at,
			'use_count'   => (int) $row->use_count,
		];
	}

	private function last_location(): string {
		global $magicauth_test_state;
		$last = end( $magicauth_test_state['redirects'] );
		$this->assertIsArray( $last );
		return (string) $last['location'];
	}

	private function auth_cookie_count(): int {
		global $magicauth_test_state;
		return count( $magicauth_test_state['auth_cookies'] ?? [] );
	}

	/** @return array<int,array<string,mixed>> */
	private function sessions(): array {
		global $magicauth_test_state;
		return array_values( $magicauth_test_state['sessions'][ self::USER_ID ] ?? [] );
	}

	public function test_code_post_signed_in_as_another_account_does_not_consume(): void {
		magicauth_test_register_user( self::OTHER_ID, self::OTHER_EMAIL );
		[ $code, $selector ] = $this->prime_code( 'ctrl1' );
		magicauth_test_login_as( self::OTHER_ID );

		Controller::handle_code_submit( $code, 'https://example.test/sign-in', magicauth_hash_ip( '203.0.113.80' ) );

		$this->assertSame( [ 'consumed_at' => null, 'use_count' => 0 ], $this->row_state( $selector ), 'row untouched, still usable by its owner' );
		$this->assertSame( 0, $this->auth_cookie_count() );
		$this->assertSame( self::OTHER_ID, get_current_user_id(), 'no session swap (B2)' );
		$location = $this->last_location();
		$this->assertStringContainsString( 'magicauth_step=code', $location );
		$this->assertStringContainsString( 'magicauth_error=1', $location, 'same envelope as a wrong code' );
		$this->assertStringContainsString( 'magicauth_sid=ctrl1', $location );

		unset( $_COOKIE['magicauth_session'] );
	}

	public function test_code_post_signed_in_as_the_same_account_redirects_without_new_cookie(): void {
		[ $code, $selector ] = $this->prime_code( 'ctrl2' );
		magicauth_test_login_as( self::USER_ID );
		global $magicauth_test_state;
		$magicauth_test_state['users'][ self::USER_ID ]->user_email = strtoupper( self::EMAIL ); // Case-insensitive match.

		Controller::handle_code_submit( $code, 'https://example.test/course/', magicauth_hash_ip( '203.0.113.81' ) );

		$this->assertNotNull( $this->row_state( $selector )['consumed_at'] );
		$this->assertSame( 0, $this->auth_cookie_count(), 'ALREADY: no second session' );
		$this->assertSame( 'https://example.test/course/', $this->last_location() );

		unset( $_COOKIE['magicauth_session'] );
	}

	public function test_code_post_for_a_disabled_user_signs_nobody_in(): void {
		[ $code ] = $this->prime_code( 'ctrl3' );
		update_user_meta( self::USER_ID, 'magicauth_disabled', '1' ); // Disabled after the code was sent (B3).

		Controller::handle_code_submit( $code, 'https://example.test/sign-in', magicauth_hash_ip( '203.0.113.82' ) );

		$this->assertSame( 0, $this->auth_cookie_count() );
		$this->assertFalse( is_user_logged_in() );
		$this->assertStringContainsString( 'magicauth_error=1', $this->last_location(), 'same envelope as a wrong code' );

		unset( $_COOKIE['magicauth_session'] );
	}

	public function test_code_sign_in_stamps_the_session_and_passes_code_to_hooks(): void {
		Clock::set_for_tests( 1790000000 );
		$calls = [];
		add_action(
			'magicauth_pre_set_auth_cookie',
			static function ( ...$args ) use ( &$calls ): void {
				$calls['pre'][] = $args;
			},
			10,
			3
		);
		add_filter(
			'magicauth_redirect_to',
			static function ( ...$args ) use ( &$calls ) {
				$calls['redirect'][] = array_slice( $args, 2 );
				return $args[0];
			},
			10,
			4
		);
		add_action(
			'magicauth_login_completed',
			static function ( ...$args ) use ( &$calls ): void {
				$calls['completed'][] = $args;
			},
			10,
			2
		);
		[ $code ] = $this->prime_code( 'ctrl4' );

		Controller::handle_code_submit( $code, 'https://example.test/course/', magicauth_hash_ip( '203.0.113.83' ) );

		$this->assertSame( [ [ self::USER_ID, 'shortcode', 'code' ] ], $calls['pre'] ?? null );
		$this->assertSame( [ [ 'shortcode', 'code' ] ], $calls['redirect'] ?? null );
		$this->assertSame( [ [ self::USER_ID, 'code' ] ], $calls['completed'] ?? null );
		$sessions = $this->sessions();
		$this->assertCount( 1, $sessions );
		$this->assertSame( 'code', $sessions[0]['magicauth_method'] );
		$this->assertSame( 1790000000, $sessions[0]['magicauth_auth_at'] );
		$this->assertArrayNotHasKey( 'magicauth_fresh_hash', $sessions[0] );
		$this->assertSame( 1790000000, get_user_meta( self::USER_ID, 'magicauth_email_verified_at', true ) );
		global $magicauth_test_state;
		$this->assertSame( [], $magicauth_test_state['cookies'] ?? [], 'no magicauth_pk_fresh with the module off' );
		$this->assertSame( 'https://example.test/course/', $this->last_location() );

		unset( $_COOKIE['magicauth_session'] );
	}

	public function test_code_sign_in_cookie_failure_redirects_to_retry_once(): void {
		global $magicauth_test_state;
		$magicauth_test_state['auth_cookie_throws'] = new \RuntimeException( 'headers already sent' );
		[ $code ] = $this->prime_code( 'ctrl5' );

		Controller::handle_code_submit( $code, 'https://example.test/sign-in', magicauth_hash_ip( '203.0.113.84' ) );

		$this->assertCount( 1, $magicauth_test_state['redirects'], 'no second redirect after the retry' );
		$this->assertSame( 'https://example.test/sign-in?magicauth_retry=1', $this->last_location() );
		$this->assertFalse( is_user_logged_in() );

		unset( $_COOKIE['magicauth_session'] );
	}

	public function test_refused_code_sign_in_honours_the_allow_login_filter(): void {
		add_filter(
			'magicauth_allow_login',
			static function ( $allowed, $user, $method ) {
				return 'code' === $method ? false : $allowed;
			},
			10,
			3
		);
		[ $code ] = $this->prime_code( 'ctrl6' );

		Controller::handle_code_submit( $code, 'https://example.test/sign-in', magicauth_hash_ip( '203.0.113.85' ) );

		$this->assertSame( 0, $this->auth_cookie_count() );
		$this->assertStringContainsString( 'magicauth_error=1', $this->last_location() );

		unset( $_COOKIE['magicauth_session'] );
	}

	/** Valid password-form POST and server for handle_password_post / handle_resetpass_post. */
	private function prime_form_post( string $action, array $fields ): void {
		$_POST   = array_merge(
			[
				'magicauth_nonce'   => wp_create_nonce( $action ),
				'magicauth_website' => '',
				'magicauth_ts'      => (string) ( time() - 5 ),
				'redirect_to'       => 'https://example.test/course/',
			],
			$fields
		);
		$_SERVER = [
			'HTTP_ORIGIN' => 'https://example.test',
			'REMOTE_ADDR' => '203.0.113.90',
		];
	}

	public function test_password_post_signed_in_as_another_account_is_refused(): void {
		global $magicauth_test_state;
		magicauth_test_register_user( self::OTHER_ID, self::OTHER_EMAIL );
		$magicauth_test_state['passwords']['learner'] = [ 'correct horse', self::USER_ID ];
		magicauth_test_login_as( self::OTHER_ID );
		$this->prime_form_post( 'magicauth_password', [ 'log' => 'learner', 'pwd' => 'correct horse' ] );

		Controller::handle_password_post();

		$this->assertSame( 0, $this->auth_cookie_count() );
		$this->assertSame( self::OTHER_ID, get_current_user_id(), 'no session swap (B2)' );
		$location = $this->last_location();
		$this->assertStringContainsString( 'magicauth_step=password', $location );
		$this->assertStringContainsString( 'magicauth_error=1', $location );

		$_POST   = [];
		$_SERVER = [];
	}

	public function test_password_post_signs_in_with_method_password(): void {
		global $magicauth_test_state;
		$magicauth_test_state['passwords']['learner'] = [ 'correct horse', self::USER_ID ];
		update_user_meta( self::USER_ID, 'magicauth_disabled', '1' ); // Does not block passwords.
		$this->prime_form_post( 'magicauth_password', [ 'log' => 'learner', 'pwd' => 'correct horse' ] );

		Controller::handle_password_post();

		$this->assertSame( 1, $this->auth_cookie_count() );
		$this->assertSame( 'password', $this->sessions()[0]['magicauth_method'] );
		$this->assertSame( '', get_user_meta( self::USER_ID, 'magicauth_email_verified_at', true ) );
		$this->assertSame( 'https://example.test/course/', $this->last_location() );

		$_POST   = [];
		$_SERVER = [];
	}

	public function test_resetpass_post_signed_in_as_another_account_is_refused(): void {
		global $magicauth_test_state;
		magicauth_test_register_user( self::OTHER_ID, self::OTHER_EMAIL );
		$magicauth_test_state['reset_keys']['learner'] = [ 'k3y', self::USER_ID ];
		magicauth_test_login_as( self::OTHER_ID );
		$this->prime_form_post( 'magicauth_resetpass', [ 'key' => 'k3y', 'login' => 'learner', 'pass1' => 'n3w-pass', 'pass2' => 'n3w-pass' ] );

		Controller::handle_resetpass_post();

		$this->assertSame( 0, $this->auth_cookie_count() );
		$this->assertSame( self::OTHER_ID, get_current_user_id() );
		$this->assertStringContainsString( 'magicauth_error=1', $this->last_location() );
		$this->assertSame( [], $magicauth_test_state['password_resets'] ?? [], 'r1-regress-02: a refused reset leaves the password unchanged' );

		$_POST   = [];
		$_SERVER = [];
	}

	/** r1-regress-02: the same user signed in gets a fresh cookie, as in 1.0.5, not ALREADY. */
	public function test_resetpass_post_by_the_signed_in_user_issues_a_fresh_cookie(): void {
		global $magicauth_test_state;
		$magicauth_test_state['reset_keys']['learner'] = [ 'k3y', self::USER_ID ];
		magicauth_test_login_as( self::USER_ID );
		$this->prime_form_post( 'magicauth_resetpass', [ 'key' => 'k3y', 'login' => 'learner', 'pass1' => 'n3w-pass', 'pass2' => 'n3w-pass' ] );

		Controller::handle_resetpass_post();

		$this->assertSame( [ self::USER_ID ], $magicauth_test_state['password_resets'] ?? [] );
		$this->assertSame( 1, $this->auth_cookie_count(), 'reset_password voided the old cookie, so a new one is set' );
		$this->assertSame( self::USER_ID, $magicauth_test_state['auth_cookie_set_for'] ?? null );
		$this->assertSame( 'reset', $this->sessions()[0]['magicauth_method'] );
		$this->assertSame( self::USER_ID, get_current_user_id() );
		$this->assertSame( 'https://example.test/course/', $this->last_location() );

		$_POST   = [];
		$_SERVER = [];
	}

	/** r1-regress-02: a sign-in the allow_login filter refuses changes nothing. */
	public function test_resetpass_post_refused_by_filter_leaves_the_password_unchanged(): void {
		global $magicauth_test_state;
		add_filter(
			'magicauth_allow_login',
			static function ( $allowed, $user, $method ) {
				return 'reset' === $method ? false : $allowed;
			},
			10,
			3
		);
		$magicauth_test_state['reset_keys']['learner'] = [ 'k3y', self::USER_ID ];
		$this->prime_form_post( 'magicauth_resetpass', [ 'key' => 'k3y', 'login' => 'learner', 'pass1' => 'n3w-pass', 'pass2' => 'n3w-pass' ] );

		Controller::handle_resetpass_post();

		$this->assertSame( [], $magicauth_test_state['password_resets'] ?? [] );
		$this->assertSame( 0, $this->auth_cookie_count() );
		$this->assertStringContainsString( 'magicauth_error=1', $this->last_location() );

		$_POST   = [];
		$_SERVER = [];
	}

	public function test_resetpass_post_signs_in_with_method_reset(): void {
		global $magicauth_test_state;
		$magicauth_test_state['reset_keys']['learner'] = [ 'k3y', self::USER_ID ];
		$this->prime_form_post( 'magicauth_resetpass', [ 'key' => 'k3y', 'login' => 'learner', 'pass1' => 'n3w-pass', 'pass2' => 'n3w-pass' ] );

		Controller::handle_resetpass_post();

		$this->assertSame( [ self::USER_ID ], $magicauth_test_state['password_resets'] ?? [] );
		$this->assertSame( 'reset', $this->sessions()[0]['magicauth_method'] );
		$this->assertSame( 'https://example.test/course/', $this->last_location() );

		$_POST   = [];
		$_SERVER = [];
	}

	/**
	 * Link click, logged out. Separate process: the handler sends headers,
	 * which PHP refuses once PHPUnit has printed.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_link_click_signs_in_with_method_link(): void {
		Clock::set_for_tests( 1790000000 );
		$issued = TokenManager::issue( self::USER_ID, self::EMAIL, 'https://example.test/course/' );
		$this->assertIsArray( $issued );
		parse_str( (string) wp_parse_url( (string) $issued['link_url'], PHP_URL_QUERY ), $_GET );

		Controller::maybe_handle_verify_get();

		$sessions = $this->sessions();
		$this->assertCount( 1, $sessions );
		$this->assertSame( 'link', $sessions[0]['magicauth_method'] );
		$this->assertSame( 1790000000, get_user_meta( self::USER_ID, 'magicauth_email_verified_at', true ) );
		$this->assertSame( 'https://example.test/course/', $this->last_location() );
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_link_click_for_a_disabled_user_is_an_invalid_link(): void {
		$issued = TokenManager::issue( self::USER_ID, self::EMAIL );
		$this->assertIsArray( $issued );
		update_user_meta( self::USER_ID, 'magicauth_disabled', '1' ); // Disabled after the link was sent (B3).
		parse_str( (string) wp_parse_url( (string) $issued['link_url'], PHP_URL_QUERY ), $_GET );

		Controller::maybe_handle_verify_get();

		$this->assertSame( 0, $this->auth_cookie_count() );
		$this->assertFalse( is_user_logged_in() );
		$this->assertStringContainsString( 'magicauth_link_invalid=1', $this->last_location() );
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_link_click_cookie_failure_redirects_to_retry_once(): void {
		global $magicauth_test_state;
		$issued = TokenManager::issue( self::USER_ID, self::EMAIL );
		$this->assertIsArray( $issued );
		parse_str( (string) wp_parse_url( (string) $issued['link_url'], PHP_URL_QUERY ), $_GET );
		$_SERVER['HTTP_HOST']                       = 'example.test';
		$_SERVER['REQUEST_URI']                     = '/?magicauth=verify';
		$magicauth_test_state['auth_cookie_throws'] = new \RuntimeException( 'headers already sent' );

		Controller::maybe_handle_verify_get();

		$this->assertCount( 1, $magicauth_test_state['redirects'] );
		$this->assertSame( 'http://example.test/?magicauth=verify&magicauth_retry=1', $this->last_location() );
	}

	/* ------------------------------------------------------------------
	 * T-CTRL issued_by (SPEC 15 step 8, 4.4, 5.8): a token an administrator
	 * created ("Create magic-link") signs in as admin_link, by link and by
	 * code; the public flow and "Send link" store 0.
	 * ---------------------------------------------------------------- */

	private const ADMIN_ID = 900;

	private function issued_by_of( string $selector ): string {
		global $wpdb;
		return (string) $wpdb->get_var( $wpdb->prepare( 'SELECT issued_by FROM ' . TokenManager::table() . ' WHERE selector = %s', $selector ) );
	}

	public function test_public_issue_stores_issued_by_0(): void {
		$issued = TokenManager::issue( self::USER_ID, self::EMAIL );
		$this->assertIsArray( $issued );
		$this->assertSame( '0', $this->issued_by_of( (string) $issued['selector'] ) );

		Controller::handle_email_request( self::EMAIL, 'https://example.test/sign-in', magicauth_hash_ip( '203.0.113.90' ) );
		global $wpdb;
		$this->assertSame( [ '0', '0' ], array_map( 'strval', $wpdb->get_col( 'SELECT issued_by FROM ' . TokenManager::table() ) ) );
	}

	public function test_code_from_an_admin_created_token_signs_in_as_admin_link(): void {
		Clock::set_for_tests( 1790000000 );
		$methods = [];
		add_filter(
			'magicauth_redirect_to',
			static function ( $target, $user, $context, $method ) use ( &$methods ) {
				$methods[] = $method;
				return $target;
			},
			10,
			4
		);
		$issued = TokenManager::issue( self::USER_ID, self::EMAIL, '', self::ADMIN_ID );
		$this->assertIsArray( $issued );
		$this->assertSame( (string) self::ADMIN_ID, $this->issued_by_of( (string) $issued['selector'] ) );
		set_transient( 'magicauth_session_adm1', [ 'email' => self::EMAIL, 'selector' => (string) $issued['selector'], 'attempts' => 0 ], 1800 );

		Controller::handle_code_submit( (string) $issued['code_plaintext'], 'https://example.test/course/', magicauth_hash_ip( '203.0.113.91' ), 'adm1' );

		$sessions = $this->sessions();
		$this->assertCount( 1, $sessions );
		$this->assertSame( 'admin_link', $sessions[0]['magicauth_method'], 'never an email sign-in' );
		$this->assertSame( '', get_user_meta( self::USER_ID, 'magicauth_email_verified_at', true ), 'does not prove the mailbox' );
		$this->assertSame( [ 'admin_link' ], $methods );
		$this->assertSame( 'https://example.test/course/', $this->last_location() );
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_link_from_an_admin_created_token_signs_in_as_admin_link(): void {
		$issued = TokenManager::issue( self::USER_ID, self::EMAIL, '', self::ADMIN_ID );
		$this->assertIsArray( $issued );
		parse_str( (string) wp_parse_url( (string) $issued['link_url'], PHP_URL_QUERY ), $_GET );

		Controller::maybe_handle_verify_get();

		$sessions = $this->sessions();
		$this->assertCount( 1, $sessions );
		$this->assertSame( 'admin_link', $sessions[0]['magicauth_method'] );
		$this->assertSame( '', get_user_meta( self::USER_ID, 'magicauth_email_verified_at', true ) );
	}

	/**
	 * Calls a UserProfile AJAX handler as ADMIN_ID for USER_ID; returns the JSON payload.
	 *
	 * @return array<string,mixed>
	 */
	private function profile_ajax( string $handler ): array {
		magicauth_test_register_user( self::ADMIN_ID, 'admin@example.test', [ 'administrator' ] );
		magicauth_test_login_as( self::ADMIN_ID );
		// B17 (open, SPEC Appendix D): the 1.0.5 rank helper refuses administrators
		// on other roles, so the test widens it through its filter as a site would.
		add_filter(
			'magicauth_current_user_can_control_user',
			static function ( $can ) {
				return $can || current_user_can( 'manage_options' );
			}
		);
		$_POST    = [
			'user_id'     => (string) self::USER_ID,
			'_ajax_nonce' => wp_create_nonce( 'magicauth-user-profile' ),
		];
		$_REQUEST = $_POST;
		try {
			UserProfile::$handler();
			$this->fail( 'no JSON response' );
		} catch ( JsonResponseSent $e ) {
			$payload = $e->payload;
		} finally {
			$_POST    = [];
			$_REQUEST = [];
		}
		$this->assertIsArray( $payload );
		$this->assertTrue( $payload['success'] ?? false );
		return $payload;
	}

	public function test_admin_create_link_stores_the_actor_and_send_link_stores_0(): void {
		global $wpdb;
		$this->profile_ajax( 'ajax_create_link' );
		$this->assertSame( [ (string) self::ADMIN_ID ], array_map( 'strval', $wpdb->get_col( 'SELECT issued_by FROM ' . TokenManager::table() ) ), 'the link and code are shown to the administrator' );

		$this->profile_ajax( 'ajax_send_link' );
		$this->assertSame( [ '0' ], array_map( 'strval', $wpdb->get_col( 'SELECT issued_by FROM ' . TokenManager::table() . ' WHERE consumed_at IS NULL' ) ), 'the token reaches only the mailbox' );
	}
}
