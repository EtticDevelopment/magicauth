<?php
/**
 * r2-regress-01: with the passkey module off, magicauth_current_user_can_control_user()
 * must behave as in 1.0.5 (d8c8d7d). The K2 change (role keys dropped plus a
 * manage_options requirement) is not one of the sanctioned module-off changes
 * (B2/B3/B5/B6, SPEC G6) and SPEC Appendix D leaves B17 open pending a rank-model
 * decision. Expected values below are the 1.0.5 results with core-accurate allcaps.
 * Proof test of review r2-regress-01, moved from tests/phpunit/Review/.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Model;

use MagicAuth\Admin\UserProfile;
use MagicAuth\Passkeys\Module;
use PHPUnit\Framework\TestCase;

final class ModuleOffControlUserTest extends TestCase {

	protected function setUp(): void {
		magicauth_test_reset_state();
	}

	protected function tearDown(): void {
		magicauth_test_reset_state();
	}

	public function test_module_off_administrator_on_subscriber_matches_1_0_5(): void {
		$sub = magicauth_test_register_user( 910, 'r2r1-sub@example.test', [ 'subscriber' ] );
		magicauth_test_register_user( 911, 'r2r1-adm@example.test', [ 'administrator' ] );
		magicauth_test_login_as( 911 );

		$this->assertFalse( Module::enabled(), 'precondition: module off' );
		$this->assertTrue( current_user_can( 'edit_user', 910 ), 'precondition: edit_user passes' );

		$this->assertFalse(
			magicauth_current_user_can_control_user( 910 ),
			'module off: 1.0.5 refused an administrator on a subscriber (B17 unchanged until decided)'
		);

		ob_start();
		UserProfile::render_fields( $sub );
		$html = (string) ob_get_clean();

		$this->assertStringNotContainsString(
			'Create magic-link',
			$html,
			'module off: 1.0.5 did not offer an administrator a sign-in link for a subscriber'
		);
	}

	public function test_module_off_edit_users_peer_without_manage_options_matches_1_0_5(): void {
		$peer  = magicauth_test_register_user( 920, 'r2r1-peer@example.test', [ 'editor' ] );
		$actor = magicauth_test_register_user( 921, 'r2r1-actor@example.test', [ 'editor' ] );
		$peer->add_cap( 'edit_users' );
		$actor->add_cap( 'edit_users' );
		magicauth_test_login_as( 921 );

		$this->assertFalse( Module::enabled(), 'precondition: module off' );
		$this->assertTrue( current_user_can( 'edit_user', 920 ), 'precondition: edit_user passes' );
		$this->assertFalse( current_user_can( 'manage_options' ), 'precondition: no manage_options' );

		$this->assertTrue(
			magicauth_current_user_can_control_user( 920 ),
			'module off: 1.0.5 let an edit_users holder control a same-caps peer'
		);
	}
}
