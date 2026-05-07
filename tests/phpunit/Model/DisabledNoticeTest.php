<?php
/**
 * "Your account is restricted from magic-link sign-in" notice.
 *
 * Backend-only flow: TokenManager surfaces a distinct error code, Controller
 * dispatches a one-shot notification (24h-throttled), Mailer renders templates
 * containing zero clickable URLs.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Model;

use MagicAuth\Auth\Controller;
use MagicAuth\Auth\Throttle;
use MagicAuth\Auth\TokenManager;
use MagicAuth\Email\Mailer;
use PHPUnit\Framework\TestCase;
use WP_Error;

final class DisabledNoticeTest extends TestCase {

	private const USER_ID = 222;
	private const EMAIL   = 'disabled@example.test';

	protected function setUp(): void {
		magicauth_test_reset_state();
		magicauth_test_register_user( self::USER_ID, self::EMAIL );
		Throttle::reset_all();
	}

	public function test_token_manager_returns_distinct_error_code_for_disabled_user(): void {
		update_user_meta( self::USER_ID, 'magicauth_disabled', 1 );

		$result = TokenManager::issue( self::USER_ID, self::EMAIL );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'magicauth_user_disabled', $result->get_error_code() );
	}

	public function test_throttle_allows_first_then_blocks_within_window(): void {
		$hmac = magicauth_hash_email( self::EMAIL );

		$this->assertTrue( Throttle::allow_disabled_notice( $hmac ) );
		$this->assertFalse( Throttle::allow_disabled_notice( $hmac ) );
		$this->assertFalse( Throttle::allow_disabled_notice( $hmac ) );
	}

	public function test_throttle_uses_independent_keys_per_email(): void {
		$hmac_a = magicauth_hash_email( 'a@example.test' );
		$hmac_b = magicauth_hash_email( 'b@example.test' );

		$this->assertTrue( Throttle::allow_disabled_notice( $hmac_a ) );
		$this->assertTrue( Throttle::allow_disabled_notice( $hmac_b ) );
		$this->assertFalse( Throttle::allow_disabled_notice( $hmac_a ) );
		$this->assertFalse( Throttle::allow_disabled_notice( $hmac_b ) );
	}

	public function test_mailer_send_disabled_notice_dispatches_wp_mail(): void {
		$result = Mailer::send_disabled_notice( self::USER_ID );
		$this->assertTrue( $result );

		global $magicauth_test_state;
		$this->assertNotEmpty( $magicauth_test_state['mail'] );
		$this->assertSame( self::EMAIL, $magicauth_test_state['mail'][0]['to'] );
	}

	public function test_mailer_subject_uses_company_name(): void {
		update_option( 'magicauth_settings', [ 'company_name' => 'Acme Co' ] );

		Mailer::send_disabled_notice( self::USER_ID );

		global $magicauth_test_state;
		$this->assertSame( 'About your sign-in request for Acme Co', $magicauth_test_state['mail'][0]['subject'] );
	}

	public function test_mailer_body_contains_no_clickable_urls(): void {
		Mailer::send_disabled_notice( self::USER_ID );

		global $magicauth_test_state;
		$body = (string) $magicauth_test_state['mail'][0]['message'];

		$this->assertStringNotContainsString( '<a ', $body, 'Disabled-notice must not contain anchor tags' );
		$this->assertStringNotContainsString( 'href=', $body, 'Disabled-notice must not contain href attributes' );
		$this->assertStringNotContainsString( 'http://', $body );
		$this->assertStringNotContainsString( 'https://', $body );
	}

	public function test_mailer_body_includes_password_line_when_password_login_on(): void {
		update_option( 'magicauth_settings', [ 'allow_password_login' => true ] );

		Mailer::send_disabled_notice( self::USER_ID );

		global $magicauth_test_state;
		$body = (string) $magicauth_test_state['mail'][0]['message'];
		$this->assertStringContainsString( 'sign in with your password', $body );
	}

	public function test_mailer_body_omits_password_line_when_password_login_off(): void {
		update_option( 'magicauth_settings', [ 'allow_password_login' => false ] );

		Mailer::send_disabled_notice( self::USER_ID );

		global $magicauth_test_state;
		$body = (string) $magicauth_test_state['mail'][0]['message'];
		$this->assertStringNotContainsString( 'sign in with your password', $body );
		$this->assertStringContainsString( 'questions about your account access', $body );
	}

	public function test_controller_dispatches_notice_once_then_skips_in_window(): void {
		update_user_meta( self::USER_ID, 'magicauth_disabled', 1 );

		Controller::handle_email_request( self::EMAIL, '/login', 'ip-hmac-1' );
		Controller::handle_email_request( self::EMAIL, '/login', 'ip-hmac-2' );
		Controller::handle_email_request( self::EMAIL, '/login', 'ip-hmac-3' );

		global $magicauth_test_state;
		$notice_subject = 'About your sign-in request for Test Site';
		$notices        = array_filter(
			$magicauth_test_state['mail'] ?? [],
			static fn ( $m ) => ( $m['subject'] ?? '' ) === $notice_subject
		);
		$this->assertCount( 1, $notices, 'Only one notice email should be dispatched within the 24h window' );
	}

	public function test_controller_does_not_dispatch_notice_for_active_user(): void {
		// User exists but is NOT disabled — happy path issues a magic link, not a notice.
		Controller::handle_email_request( self::EMAIL, '/login', 'ip-hmac-1' );

		global $magicauth_test_state;
		foreach ( $magicauth_test_state['mail'] ?? [] as $mail ) {
			$this->assertStringNotContainsString( 'About your sign-in request', (string) $mail['subject'] );
		}
	}

	public function test_controller_does_not_dispatch_notice_for_unknown_email(): void {
		Controller::handle_email_request( 'nobody@example.test', '/login', 'ip-hmac-1' );

		global $magicauth_test_state;
		$this->assertEmpty( $magicauth_test_state['mail'] ?? [], 'No mail should be sent for an unknown email' );
	}
}
