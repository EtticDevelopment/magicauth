<?php
/**
 * Guard for the real-database suite (SPEC 14.1, CI job real-database): the
 * group realdb ran against the server the job asked for, not silently on
 * SQLite, and that server reports changed rows (no CLIENT_FOUND_ROWS).
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use PHPUnit\Framework\TestCase;

/**
 * @group realdb
 */
final class RealDatabaseTest extends TestCase {

	protected function setUp(): void {
		magicauth_test_reset_state();
	}

	protected function tearDown(): void {
		magicauth_test_reset_state();
	}

	public function test_the_requested_driver_and_server_are_in_use(): void {
		global $wpdb;
		$version = $wpdb->server_version();
		if ( 'mysql' !== getenv( 'MAGICAUTH_TEST_DB' ) ) {
			$this->assertSame( 'sqlite', $wpdb->driver );
			$this->assertStringStartsWith( 'SQLite ', $version );
			return;
		}
		$this->assertSame( 'mysql', $wpdb->driver );
		$expect = (string) getenv( 'MAGICAUTH_TEST_DB_EXPECT' );
		$this->assertNotSame( '', $expect, 'the CI job names the server it started' );
		$this->assertStringContainsString( $expect, $version );
	}

	/** An UPDATE that changes nothing reports 0, natively on MySQL and through the emulation on SQLite. */
	public function test_update_reports_changed_rows_not_matched_rows(): void {
		global $wpdb;
		$wpdb->mysql_changed_rows = true;
		$table                    = $wpdb->prefix . 'magicauth_passkey_challenges';
		$wpdb->insert(
			$table,
			[
				'lookup_hash' => str_repeat( 'a', 64 ),
				'ceremony'    => 'signin',
				'created_at'  => '2026-10-01 00:00:00',
				'expires_at'  => '2026-10-01 00:10:00',
			]
		);
		$set = "UPDATE {$table} SET consumed_at = '2026-10-01 00:01:00' WHERE consumed_at IS NULL";
		$this->assertSame( 1, $wpdb->query( $set ) );
		$this->assertSame( 0, $wpdb->query( $set ), 'moved out of the WHERE' );
		$this->assertSame( 0, $wpdb->query( "UPDATE {$table} SET ceremony = 'signin'" ), 'same value: not changed' );
		$this->assertSame( 1, $wpdb->query( "UPDATE {$table} SET ceremony = 'complete'" ) );
	}
}
