<?php
/**
 * K2 (B17), reverted by r2-regress-01: core WP_User::get_role_caps() merges
 * $caps, which holds the role names, into $allcaps, so the allcaps superset
 * rank check refuses administrators on every other role. That is 1.0.5
 * behaviour and stays until the rank model is decided (SPEC Appendix D).
 * These tests pin the 1.0.5 results, including the group-leader (B13) case
 * that today is blocked only by B17, so a later B17 fix has to face it.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Review;

use MagicAuth\Admin\UserProfile;
use PHPUnit\Framework\TestCase;

final class K2Test extends TestCase {

	protected function setUp(): void {
		magicauth_test_reset_state();
	}

	protected function tearDown(): void {
		magicauth_test_reset_state();
	}

	public function test_core_allcaps_shape_holds_role_names(): void {
		$sub = magicauth_test_register_user( 310, 'k2-sub@example.test', [ 'subscriber' ] );
		$adm = magicauth_test_register_user( 311, 'k2-adm@example.test', [ 'administrator' ] );

		$this->assertArrayHasKey( 'subscriber', $sub->allcaps );
		$this->assertArrayNotHasKey( 'subscriber', $adm->allcaps );
	}

	public function test_b17_administrator_is_refused_on_subscriber_and_editor(): void {
		magicauth_test_register_user( 320, 'k2-sub2@example.test', [ 'subscriber' ] );
		magicauth_test_register_user( 330, 'k2-ed@example.test', [ 'editor' ] );
		magicauth_test_register_user( 321, 'k2-adm2@example.test', [ 'administrator' ] );
		magicauth_test_login_as( 321 );

		$this->assertFalse( magicauth_current_user_can_control_user( 320 ), 'B17 open: 1.0.5 result' );
		$this->assertFalse( magicauth_current_user_can_control_user( 330 ), 'B17 open: 1.0.5 result' );
		$this->assertTrue( magicauth_current_user_can_control_user( 321 ), 'self stays allowed' );
	}

	public function test_b17_profile_fields_stay_hidden_for_admin_viewing_subscriber(): void {
		$sub = magicauth_test_register_user( 340, 'k2-sub3@example.test', [ 'subscriber' ] );
		magicauth_test_register_user( 341, 'k2-adm4@example.test', [ 'administrator' ] );
		magicauth_test_login_as( 341 );

		ob_start();
		UserProfile::render_fields( $sub );
		$html = (string) ob_get_clean();

		$this->assertStringNotContainsString( 'Create magic-link', $html, 'B17 open: 1.0.5 rendered no MagicAuth tools here' );
	}

	public function test_edit_users_holder_still_cannot_control_administrator(): void {
		magicauth_test_register_user( 350, 'k2-adm5@example.test', [ 'administrator' ] );
		$leader = magicauth_test_register_user( 351, 'k2-lead@example.test', [ 'editor' ] );
		$leader->add_cap( 'edit_users' );
		magicauth_test_login_as( 351 );

		$this->assertFalse( magicauth_current_user_can_control_user( 350 ) );
	}

	/**
	 * B13: a group leader (edit_users, no manage_options) is kept off a
	 * student only by the role-name key (B17). A B17 fix must keep this false.
	 */
	public function test_edit_users_holder_cannot_control_a_subscriber(): void {
		magicauth_test_register_user( 360, 'k2-sub4@example.test', [ 'subscriber' ] );
		$leader = magicauth_test_register_user( 361, 'k2-lead2@example.test', [ 'editor' ] );
		$leader->add_cap( 'edit_users' );
		magicauth_test_login_as( 361 );

		$this->assertTrue( current_user_can( 'edit_user', 360 ), 'precondition: edit_user passes' );
		$this->assertFalse( magicauth_current_user_can_control_user( 360 ) );
	}
}
