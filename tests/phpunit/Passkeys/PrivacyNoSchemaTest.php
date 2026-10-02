<?php
/**
 * Review r1-data-06: in the schema-failure state (magicauth_db_version below
 * 2, passkey tables never created) the passkey exporter and eraser must not
 * fail: no passkey rows can exist, and a WP_Error would abort every personal
 * data request of the site. The user meta is still exported and erased. On
 * an existing schema a missing table stays a WP_Error (D-32).
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Passkeys\Privacy;
use MagicAuth\Tests\Support\Ceremony;
use PHPUnit\Framework\TestCase;
use WP_Error;

final class PrivacyNoSchemaTest extends TestCase {

	private const TABLES = [ 'wp_magicauth_passkeys', 'wp_magicauth_passkey_challenges', 'wp_magicauth_passkey_sessions' ];

	protected function setUp(): void {
		global $wpdb;
		Ceremony::site();
		Ceremony::user( 7 );
		update_user_meta( 7, 'magicauth_email_changed_at', '1790000000' );
		foreach ( self::TABLES as $table ) {
			$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
		}
	}

	protected function tearDown(): void {
		global $wpdb;
		$wpdb->prefix = 'wp_';
		$wpdb->install_magicauth_passkeys_schema();
		$wpdb->show_errors( false );
		magicauth_test_reset_state();
	}

	public function test_export_and_erase_work_without_the_passkey_tables(): void {
		update_option( 'magicauth_db_version', 1 );
		$email = (string) get_userdata( 7 )->user_email;

		$export = Privacy::export( $email );
		$this->assertIsArray( $export, 'no WP_Error: it would abort every export of the site' );
		$this->assertTrue( $export['done'] );
		$this->assertSame( [ 'magicauth-passkey-settings' ], array_column( $export['data'], 'item_id' ), 'the meta is still exported' );

		$erase = Privacy::erase( $email );
		$this->assertIsArray( $erase, 'no WP_Error: it would abort every erasure of the site' );
		$this->assertTrue( $erase['done'] );
		$this->assertTrue( $erase['items_removed'] );
		$this->assertSame( [], get_user_meta( 7, 'magicauth_email_changed_at' ), 'the meta is still erased' );
	}

	public function test_a_missing_table_on_an_existing_schema_stays_an_error(): void {
		update_option( 'magicauth_db_version', 2 );
		$email = (string) get_userdata( 7 )->user_email;

		$this->assertInstanceOf( WP_Error::class, Privacy::export( $email ) );
		$this->assertInstanceOf( WP_Error::class, Privacy::erase( $email ) );
	}
}
