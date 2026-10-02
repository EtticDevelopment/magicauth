<?php
/**
 * The E2E fixture mu-plugin (tests/e2e/wp/mu-plugins/magicauth-e2e.php, SPEC 14.2)
 * opens logged-out admin-ajax actions that write user meta, settings and sessions.
 * It must be inert anywhere MAGICAUTH_E2E is not defined, and it never ships: the
 * release allowlist leaves tests/ out (BuildReleaseTest), and .distignore lists it.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use PHPUnit\Framework\TestCase;

final class E2eFixtureTest extends TestCase {

	private const FIXTURE = __DIR__ . '/../../e2e/wp/mu-plugins/magicauth-e2e.php';

	/** Hooks the fixture registers when it is active. */
	private const HOOKS = [
		'wp_ajax_nopriv_magicauth_e2e_set',
		'wp_ajax_nopriv_magicauth_e2e_get',
		'wp_ajax_nopriv_magicauth_e2e_mail',
		'wp_ajax_magicauth_e2e_set',
		'pre_wp_mail',
		'magicauth_current_user_can_control_user',
		'magicauth_passkey_options_ip_max',
		'magicauth_force_frontend_assets',
		'wp_login',
		'template_include',
	];

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_inert_without_the_constant(): void {
		$this->assertFalse( defined( 'MAGICAUTH_E2E' ) );
		require self::FIXTURE;
		foreach ( self::HOOKS as $hook ) {
			$this->assertFalse( has_filter( $hook ), "{$hook} not registered" );
		}
		$this->assertFalse( defined( 'MAGICAUTH_E2E_FLAGS' ), 'stopped before its first statement' );
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_registers_its_hooks_only_under_the_constant(): void {
		define( 'MAGICAUTH_E2E', true );
		require self::FIXTURE;
		foreach ( self::HOOKS as $hook ) {
			$this->assertNotFalse( has_filter( $hook ), "{$hook} registered" );
		}
	}

	public function test_the_release_and_dist_lists_leave_tests_out(): void {
		$script = (string) file_get_contents( __DIR__ . '/../../../tools/build-release.sh' );
		$this->assertSame( 1, preg_match( '/^allowlist=\(([^)]*)\)$/m', $script, $m ) );
		$this->assertNotContains( 'tests', preg_split( '/\s+/', trim( $m[1] ) ) );
		$dist = (string) file_get_contents( __DIR__ . '/../../../.distignore' );
		$this->assertMatchesRegularExpression( '/^tests\/$/m', $dist );
	}
}
