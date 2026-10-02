<?php
/**
 * Review r1-data-04: network user deletion (wpmu_delete_user()) never fires
 * delete_user, so on_wpmu_delete_user() must delete the per-site rows
 * (credentials, challenges, session state, requests) on the current site and
 * on every site the user belongs to, then the network-wide meta.
 *
 * Multisite stub as in UninstallMultisiteTest: switch_to_blog() and
 * restore_current_blog() swap $wpdb->prefix, get_blogs_of_user() lists blogs
 * 1 and 2 for user 5. Separate process, so the global functions never leak.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Auth\TokenManager;
use MagicAuth\Passkeys\Base64Url;
use MagicAuth\Passkeys\ChallengeStore;
use MagicAuth\Passkeys\Clock;
use MagicAuth\Passkeys\CredentialStore;
use MagicAuth\Passkeys\SessionState;
use PHPUnit\Framework\TestCase;

final class NetworkUserDeletionTest extends TestCase {

	private const PREFIXES = [ 'wp_', 'wp_2_', 'wp_3_' ];

	private const SESSION = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

	private static function seed( int $user_id ): void {
		global $wpdb;
		$id = CredentialStore::insert(
			[
				'user_id'         => $user_id,
				'rp_id'           => 'academy.example.com',
				'credential_id'   => Base64Url::encode( random_bytes( 16 ) ),
				'user_handle'     => Base64Url::encode( random_bytes( 64 ) ),
				'public_key'      => "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
				'alg'             => -7,
				'user_registered' => '2026-09-30 08:00:00',
			]
		);
		if ( ! is_int( $id ) ) {
			throw new \RuntimeException( 'seed failed' );
		}
		ChallengeStore::issue( 'register', $user_id, self::SESSION, '', '-7', 420 );
		$wpdb->insert(
			SessionState::table(),
			[
				'session_hash' => hash( 'sha256', $wpdb->prefix . $user_id ),
				'user_id'      => $user_id,
				'expires_at'   => '2030-01-01 00:00:00',
			]
		);
		if ( ! is_array( TokenManager::issue( $user_id, "u{$user_id}@example.test" ) ) ) {
			throw new \RuntimeException( 'token seed failed' );
		}
	}

	/** @return array<int,int> Rows of the user per table under the current prefix. */
	private static function rows_of( int $user_id ): array {
		global $wpdb;
		$out = [];
		foreach ( [ CredentialStore::table(), ChallengeStore::table(), SessionState::table(), TokenManager::table() ] as $table ) {
			$out[] = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE user_id = %d", $user_id ) );
		}
		return $out;
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_network_deletion_removes_rows_on_every_site_of_the_user(): void {
		global $wpdb, $magicauth_test_state;
		magicauth_test_reset_state();
		Clock::set_for_tests( 1790000000 );

		foreach ( self::PREFIXES as $prefix ) {
			$wpdb->prefix = $prefix;
			$wpdb->install_magicauth_schema();
			$wpdb->install_magicauth_passkeys_schema();
			self::seed( 5 );
			self::seed( 6 );
		}
		$wpdb->prefix = 'wp_';
		update_user_meta( 5, CredentialStore::HANDLE_META, '1' );

		$magicauth_test_state['multisite'] = true;
		if ( ! function_exists( 'switch_to_blog' ) ) {
			eval(
				'function switch_to_blog( $id, $deprecated = null ) {
					global $wpdb, $magicauth_review_blog_stack;
					$id = (int) $id;
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
				function get_current_blog_id() { return 1; }
				function get_blogs_of_user( $id, $all = false ) {
					if ( 5 !== (int) $id ) { return []; }
					return [
						1 => (object) [ "userblog_id" => 1 ],
						2 => (object) [ "userblog_id" => 2 ],
					];
				}'
			);
		}

		CredentialStore::on_wpmu_delete_user( 5 );

		$this->assertSame( 'wp_', $wpdb->prefix, 'blog context restored' );
		$this->assertSame( [], get_user_meta( 5, CredentialStore::HANDLE_META ), 'network-wide meta removed' );
		foreach ( [ 'wp_', 'wp_2_' ] as $prefix ) {
			$wpdb->prefix = $prefix;
			$this->assertSame( [ 0, 0, 0, 0 ], self::rows_of( 5 ), "{$prefix}: rows of the deleted user removed" );
			$this->assertSame( [ 1, 1, 1, 1 ], self::rows_of( 6 ), "{$prefix}: other users untouched" );
		}
		// Blog 3: the user is no member, so its rows are left to that site's daily sweep.
		$wpdb->prefix = 'wp_3_';
		$this->assertSame( [ 1, 1, 1, 1 ], self::rows_of( 5 ) );
		$wpdb->prefix = 'wp_';
	}
}
