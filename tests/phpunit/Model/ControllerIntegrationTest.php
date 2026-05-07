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

use MagicAuth\Auth\Controller;
use MagicAuth\Auth\Throttle;
use MagicAuth\Auth\TokenManager;
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
			'magicauth_nonce'   => 'test-nonce',
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
}
