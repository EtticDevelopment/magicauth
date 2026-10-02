<?php
/**
 * Review r1-data-03: uninstall.php runs in one blog context only. On a
 * (subdomain) multisite where MagicAuth ran on another site, that site's
 * {$prefix}magicauth_passkeys table, credential rows included (personal data,
 * SPEC 12.1 "removed on uninstall"), survives the uninstall.
 *
 * The multisite stub here: is_multisite() true, get_sites() lists blogs 1
 * and 2, and switch_to_blog()/restore_current_blog() swap $wpdb->prefix the
 * way core does. Run in a separate process so the global functions and the
 * WP_UNINSTALL_PLUGIN constant never leak into other tests.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use PHPUnit\Framework\TestCase;

final class UninstallMultisiteTest extends TestCase {

	private const TABLES = [
		'magicauth_requests',
		'magicauth_passkeys',
		'magicauth_passkey_challenges',
		'magicauth_passkey_sessions',
	];

	protected function setUp(): void {
		global $wpdb;
		magicauth_test_reset_state();
		$wpdb->install_magicauth_schema();
		$wpdb->install_magicauth_passkeys_schema();
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_multisite_uninstall_drops_every_sites_passkey_tables(): void {
		global $wpdb, $magicauth_test_state;

		// Blog 2's tables, created under its prefix, with one credential row.
		$wpdb->prefix = 'wp_2_';
		$wpdb->install_magicauth_schema();
		$wpdb->install_magicauth_passkeys_schema();
		$wpdb->query( "INSERT INTO wp_2_magicauth_passkeys (user_id, rp_id, credential_id, credential_hash, user_handle, public_key, alg, created_at) VALUES (5, 'site2.example.com', 'cid', 'chash', 'uh', 'pk', -7, '2026-10-01 00:00:00')" );
		$wpdb->prefix = 'wp_';
		$this->assertTrue( $wpdb->table_exists( 'wp_2_magicauth_passkeys' ), 'seeded' );
		$this->assertSame( '1', (string) $wpdb->get_var( 'SELECT COUNT(*) FROM wp_2_magicauth_passkeys' ) );

		$magicauth_test_state['multisite']         = true;
		$magicauth_test_state['subdomain_install'] = true;
		$magicauth_test_state['sites']             = [
			[ 'blog_id' => 1, 'domain' => 'example.com', 'path' => '/' ],
			[ 'blog_id' => 2, 'domain' => 'site2.example.com', 'path' => '/' ],
		];
		if ( ! function_exists( 'switch_to_blog' ) ) {
			eval(
				'function switch_to_blog( $id, $deprecated = null ) {
					global $wpdb, $magicauth_review_blog_stack;
					$id = is_object( $id ) ? (int) $id->blog_id : (int) $id;
					$magicauth_review_blog_stack[] = $wpdb->prefix;
					$wpdb->prefix = 1 === $id ? "wp_" : "wp_{$id}_";
					return true;
				}
				function restore_current_blog() {
					global $wpdb, $magicauth_review_blog_stack;
					if ( empty( $magicauth_review_blog_stack ) ) { return false; }
					$wpdb->prefix = array_pop( $magicauth_review_blog_stack );
					return true;
				}
				function get_current_blog_id() { return 1; }'
			);
		}

		define( 'WP_UNINSTALL_PLUGIN', 'magicauth/magicauth.php' );
		require MAGICAUTH_DIR . 'uninstall.php';

		$this->assertSame( 'wp_', $wpdb->prefix, 'blog context restored after the loop' );
		foreach ( self::TABLES as $name ) {
			$this->assertFalse( $wpdb->table_exists( 'wp_' . $name ), "wp_{$name} dropped (main site)" );
		}
		foreach ( self::TABLES as $name ) {
			$this->assertFalse( $wpdb->table_exists( 'wp_2_' . $name ), "wp_2_{$name} dropped (blog 2): credential rows must not survive uninstall" );
		}
	}
}
