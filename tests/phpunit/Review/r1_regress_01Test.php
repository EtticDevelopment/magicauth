<?php
/**
 * r1-regress-01: Login::establish() writes magicauth_email_verified_at and
 * fires magicauth_login_completed only after do_action( 'wp_login' ). A
 * wp_login interstitial that exits (Two Factor: clear cookies, print form,
 * exit; SPEC 1328) stops the request there, so a link/code sign-in that
 * proved the mailbox never records it and rule E keeps refusing passkeys.
 *
 * PHPUnit cannot survive a real exit, so the interstitial is modelled by a
 * wp_login callback that throws: in both cases no line after wp_login runs.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Review;

use MagicAuth\Auth\Login;
use MagicAuth\Passkeys\Clock;
use PHPUnit\Framework\TestCase;
use WP_User;

final class r1_regress_01Test extends TestCase {

	private const NOW = 1790000000;

	private const USER_ID = 930;

	private WP_User $user;

	protected function setUp(): void {
		magicauth_test_reset_state();
		$this->user             = magicauth_test_register_user( self::USER_ID, 'twofa@example.test' );
		$this->user->user_login = 'twofa';
		Clock::set_for_tests( self::NOW );
		$_COOKIE = [];
	}

	protected function tearDown(): void {
		$_COOKIE = [];
		magicauth_test_reset_state();
	}

	/** Stand-in for a wp_login callback that renders a form and exits. */
	private static function add_exiting_interstitial(): void {
		add_action(
			'wp_login',
			static function (): void {
				throw new \RuntimeException( 'interstitial exit' );
			},
			10,
			2
		);
	}

	/** @return array<string,array{0:string}> */
	public static function mailbox_methods(): array {
		return [
			'link' => [ 'link' ],
			'code' => [ 'code' ],
		];
	}

	/** @dataProvider mailbox_methods */
	public function test_mailbox_proof_is_recorded_even_when_wp_login_exits( string $method ): void {
		self::add_exiting_interstitial();

		Login::establish( $this->user, $method );

		$this->assertSame(
			self::NOW,
			(int) get_user_meta( self::USER_ID, 'magicauth_email_verified_at', true ),
			'the auth cookie was already sent, so the mailbox proof must be recorded before wp_login can exit'
		);
	}

	public function test_rule_e_lets_a_passkey_in_after_an_interrupted_email_sign_in(): void {
		update_option( 'magicauth_settings', array_merge( (array) get_option( 'magicauth_settings', [] ), [ 'passkeys_email_reverify_days' => 30 ] ) );
		update_user_meta( self::USER_ID, 'magicauth_email_verified_at', self::NOW - 31 * DAY_IN_SECONDS );
		$this->assertSame(
			'magicauth_reverify_required',
			Login::preflight( $this->user, 'passkey' )->get_error_code(),
			'precondition: setting is read and the old proof is stale'
		);

		// The user follows L8: signs in by email link, the 2FA interstitial exits.
		self::add_exiting_interstitial();
		Login::establish( $this->user, 'link' );
		wp_set_current_user( 0 );

		$this->assertTrue(
			Login::preflight( $this->user, 'passkey' ),
			'after a fresh email sign-in the passkey must be usable again'
		);
	}
}
