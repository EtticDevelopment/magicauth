<?php
/**
 * Capability gate: magicauth_current_user_can_control_user.
 *
 * The reference plugin had a bug where this function ignored its $user_id
 * argument, letting editors with `edit_users` issue admin login links. Our
 * helper combines edit_user($target) with a same-or-higher-role rank check.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Model;

use PHPUnit\Framework\TestCase;

final class CapabilityTest extends TestCase {

	protected function setUp(): void {
		magicauth_test_reset_state();
	}

	public function test_editor_cannot_control_administrator(): void {
		$editor_id = 100;
		$admin_id  = 200;
		magicauth_test_register_user( $editor_id, 'editor@example.test', [ 'editor' ] );
		magicauth_test_register_user( $admin_id, 'admin@example.test', [ 'administrator' ] );

		magicauth_test_login_as( $editor_id );

		$this->assertFalse(
			magicauth_current_user_can_control_user( $admin_id ),
			'Editor must NOT be able to control an administrator (rank gate)'
		);
	}

	public function test_administrator_can_control_editor(): void {
		$editor_id = 101;
		$admin_id  = 201;
		magicauth_test_register_user( $editor_id, 'editor2@example.test', [ 'editor' ] );
		magicauth_test_register_user( $admin_id, 'admin2@example.test', [ 'administrator' ] );

		magicauth_test_login_as( $admin_id );

		$this->assertTrue( magicauth_current_user_can_control_user( $editor_id ) );
	}

	public function test_administrator_can_control_self(): void {
		$admin_id = 202;
		magicauth_test_register_user( $admin_id, 'admin3@example.test', [ 'administrator' ] );
		magicauth_test_login_as( $admin_id );

		$this->assertTrue( magicauth_current_user_can_control_user( $admin_id ) );
	}

	public function test_anonymous_cannot_control_anyone(): void {
		$target_id = 203;
		magicauth_test_register_user( $target_id, 't@example.test', [ 'subscriber' ] );

		// No login.
		$this->assertFalse( magicauth_current_user_can_control_user( $target_id ) );
	}

	public function test_administrator_cannot_control_user_zero(): void {
		$admin_id = 204;
		magicauth_test_register_user( $admin_id, 'admin4@example.test', [ 'administrator' ] );
		magicauth_test_login_as( $admin_id );

		$this->assertFalse( magicauth_current_user_can_control_user( 0 ) );
		$this->assertFalse( magicauth_current_user_can_control_user( -5 ) );
	}

	public function test_filter_can_override(): void {
		$editor_id = 105;
		$admin_id  = 205;
		magicauth_test_register_user( $editor_id, 'editor3@example.test', [ 'editor' ] );
		magicauth_test_register_user( $admin_id, 'admin5@example.test', [ 'administrator' ] );
		magicauth_test_login_as( $editor_id );

		$this->assertFalse( magicauth_current_user_can_control_user( $admin_id ) );

		add_filter(
			'magicauth_current_user_can_control_user',
			static function ( $can, $target_id ) {
				unset( $can, $target_id );
				return true;
			},
			10,
			2
		);

		$this->assertTrue(
			magicauth_current_user_can_control_user( $admin_id ),
			'Filter can override (e.g. for site owners with custom role hierarchies)'
		);
	}

	public function test_two_admins_can_control_each_other(): void {
		// Same-role rank — equal capability sets — passes the proper-superset gate.
		magicauth_test_register_user( 301, 'a1@example.test', [ 'administrator' ] );
		magicauth_test_register_user( 302, 'a2@example.test', [ 'administrator' ] );

		magicauth_test_login_as( 301 );
		$this->assertTrue( magicauth_current_user_can_control_user( 302 ) );
	}
}
