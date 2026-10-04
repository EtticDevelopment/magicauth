<?php
/**
 * T-CRED (SPEC 5.1, 5.3, 5.4, 7.4 A-4, 7.6, 14.1): credential rows, tri-state
 * lookups, user_registered snapshot on per-user reads, counter CAS, the
 * race-safe user handle, orphan sweep, delete_user cleanup. Runs with MySQL
 * changed-rows semantics; part of the real-database suite (group realdb).
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Auth\TokenManager;
use MagicAuth\Installer;
use MagicAuth\Passkeys\Base64Url;
use MagicAuth\Passkeys\ChallengeStore;
use MagicAuth\Passkeys\Clock;
use MagicAuth\Passkeys\CredentialStore;
use MagicAuth\Passkeys\SessionState;
use PHPUnit\Framework\TestCase;
use WP_Error;
use WP_User;

/**
 * @group realdb
 */
final class CredentialStoreTest extends TestCase {

	private const NOW = 1790000000;

	private const RP = 'academy.example.com';

	private const REGISTERED = '2026-09-30 08:00:00';

	private const SESSION = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

	protected function setUp(): void {
		global $wpdb;
		magicauth_test_reset_state();
		$wpdb->mysql_changed_rows = true;
		Clock::set_for_tests( self::NOW );
	}

	protected function tearDown(): void {
		magicauth_test_reset_state();
	}

	private static function user( int $id, string $registered = self::REGISTERED ): WP_User {
		$user                  = magicauth_test_register_user( $id, "u{$id}@example.test" );
		$user->user_registered = $registered;
		return $user;
	}

	/** @return array<string,mixed> */
	private static function record( int $user_id, string $raw_id = '', array $over = [] ): array {
		return array_merge(
			[
				'user_id'         => $user_id,
				'rp_id'           => self::RP,
				'credential_id'   => Base64Url::encode( '' !== $raw_id ? $raw_id : random_bytes( 16 ) ),
				'user_handle'     => Base64Url::encode( random_bytes( 64 ) ),
				'public_key'      => "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
				'alg'             => -7,
				'sign_count'      => 0,
				'backup_eligible' => true,
				'backup_state'    => true,
				'transports'      => 'internal,hybrid',
				'aaguid'          => '00000000-0000-0000-0000-000000000000',
				'name'            => 'Passkey',
				'user_registered' => self::REGISTERED,
			],
			$over
		);
	}

	private static function insert( int $user_id, string $raw_id = '', array $over = [] ): int {
		$id = CredentialStore::insert( self::record( $user_id, $raw_id, $over ) );
		if ( ! is_int( $id ) ) {
			throw new \RuntimeException( 'insert failed: ' . $id->get_error_code() );
		}
		return $id;
	}

	private static function count_rows( string $table = '' ): int {
		global $wpdb;
		return (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . ( '' !== $table ? $table : CredentialStore::table() ) );
	}

	/** @return array<string,mixed>|null */
	private static function row( int $id ): ?array {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . CredentialStore::table() . ' WHERE id = %d', $id ), ARRAY_A );
		return is_array( $row ) ? $row : null;
	}

	/* ------------------------------------------------------------------ insert */

	public function test_insert_stores_the_record_with_its_hash(): void {
		$raw = random_bytes( 20 );
		$id  = self::insert( 5, $raw );

		$row = self::row( $id );
		$this->assertNotNull( $row );
		$this->assertSame( hash( 'sha256', $raw ), $row['credential_hash'], 'unkeyed sha256 of the raw ID' );
		$this->assertSame( Base64Url::encode( $raw ), $row['credential_id'] );
		$this->assertSame( '5', (string) $row['user_id'] );
		$this->assertSame( '-7', (string) $row['alg'] );
		$this->assertSame( '1', (string) $row['backup_eligible'] );
		$this->assertSame( 'internal,hybrid', $row['transports'] );
		$this->assertSame( self::REGISTERED, $row['user_registered'] );
		$this->assertSame( gmdate( 'Y-m-d H:i:s', self::NOW ), $row['created_at'] );
		$this->assertNull( $row['last_used_at'] );
		$this->assertNull( $row['counter_anomaly_at'] );
	}

	/** R-13: same raw ID for the same or another user is caught by the SELECT; no INSERT runs, nothing printed. */
	public function test_duplicate_is_detected_before_the_insert_for_any_user(): void {
		global $wpdb;
		$raw = random_bytes( 32 );
		self::insert( 5, $raw );
		$wpdb->show_errors( true );

		foreach ( [ 5, 6 ] as $user_id ) {
			$wpdb->query_log = [];
			ob_start();
			$result = CredentialStore::insert( self::record( $user_id, $raw ) );
			$out    = (string) ob_get_clean();

			$this->assertInstanceOf( WP_Error::class, $result );
			$this->assertSame( 'magicauth_duplicate_credential', $result->get_error_code() );
			$this->assertSame( '', $out );
			$this->assertSame( [], array_values( array_filter( $wpdb->query_log, static fn( string $q ): bool => 0 === stripos( $q, 'INSERT' ) ) ), 'no INSERT attempted' );
		}
		$wpdb->show_errors( false );
		$this->assertSame( [], $wpdb->error_log );
		$this->assertSame( 1, self::count_rows() );
	}

	/** @return array<string,array{0:string}> */
	public static function failing_queries(): array {
		return [
			'duplicate SELECT' => [ 'SELECT * FROM wp_magicauth_passkeys WHERE credential_hash' ],
			'INSERT'           => [ 'INSERT INTO wp_magicauth_passkeys' ],
		];
	}

	/** @dataProvider failing_queries */
	public function test_query_error_on_insert_is_a_db_error_not_a_duplicate( string $pattern ): void {
		global $wpdb;
		$wpdb->show_errors( true );
		$wpdb->fail_next_query( $pattern );

		ob_start();
		$result = CredentialStore::insert( self::record( 5 ) );
		$out    = (string) ob_get_clean();
		$wpdb->show_errors( false );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'magicauth_db_error', $result->get_error_code() );
		$this->assertSame( '', $out );
		$this->assertFalse( $wpdb->suppress_errors );
		$this->assertSame( 0, self::count_rows() );
	}

	/** @return array<string,array{0:array<string,mixed>}> */
	public static function invalid_records(): array {
		return [
			'unknown column'       => [ [ 'credential_hash' => str_repeat( 'a', 64 ) ] ],
			'user 0'               => [ [ 'user_id' => 0 ] ],
			'user as string'       => [ [ 'user_id' => '5' ] ],
			'alg -35'              => [ [ 'alg' => -35 ] ],
			'alg as string'        => [ [ 'alg' => '-7' ] ],
			'credential id short'  => [ [ 'credential_id' => Base64Url::encode( random_bytes( 15 ) ) ] ],
			'credential id long'   => [ [ 'credential_id' => Base64Url::encode( random_bytes( 1024 ) ) ] ],
			'credential id padded' => [ [ 'credential_id' => base64_encode( random_bytes( 16 ) ) ] ],
			'empty rp'             => [ [ 'rp_id' => '' ] ],
			'handle too long'      => [ [ 'user_handle' => Base64Url::encode( random_bytes( 65 ) ) ] ],
			'empty public key'     => [ [ 'public_key' => '' ] ],
			'counter negative'     => [ [ 'sign_count' => -1 ] ],
			'counter above 2^32'   => [ [ 'sign_count' => 4294967296 ] ],
			'name 65 chars'        => [ [ 'name' => str_repeat( 'n', 65 ) ] ],
			'no snapshot'          => [ [ 'user_registered' => '' ] ],
			'aaguid upper case'    => [ [ 'aaguid' => 'EA9B8D66-4D01-1D21-3CE4-B6B48CB575D4' ] ],
			'unknown transport'    => [ [ 'transports' => 'internal,carrier-pigeon' ] ],
			'repeated transport'   => [ [ 'transports' => 'usb,usb' ] ],
		];
	}

	/** @dataProvider invalid_records */
	public function test_invalid_record_is_refused( array $over ): void {
		$result = CredentialStore::insert( self::record( 5, '', $over ) );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'magicauth_invalid_record', $result->get_error_code() );
		$this->assertSame( 0, self::count_rows() );
	}

	public function test_counter_up_to_2_32_minus_1_and_emoji_name_are_stored(): void {
		$id  = self::insert( 5, '', [ 'sign_count' => 4294967295, 'name' => str_repeat( 'é', 63 ) . '🔑' ] );
		$row = self::row( $id );
		$this->assertNotNull( $row );
		$this->assertSame( '4294967295', (string) $row['sign_count'] );
		$this->assertSame( str_repeat( 'é', 63 ) . '🔑', $row['name'] );
	}

	/* -------------------------------------------------------- tri-state lookups */

	public function test_find_by_raw_id_is_tri_state(): void {
		global $wpdb;
		$raw = random_bytes( 32 );
		$id  = self::insert( 5, $raw );

		$found = CredentialStore::find_by_raw_id( $raw );
		$this->assertIsObject( $found );
		$this->assertSame( (string) $id, (string) $found->id );
		$this->assertSame( CredentialStore::NOT_FOUND, CredentialStore::find_by_raw_id( random_bytes( 32 ) ) );
		$this->assertSame( CredentialStore::NOT_FOUND, CredentialStore::find_by_raw_id( '' ) );

		$wpdb->show_errors( true );
		$wpdb->fail_next_query( 'credential_hash' );
		ob_start();
		$error = CredentialStore::find_by_raw_id( $raw );
		$out   = (string) ob_get_clean();
		$wpdb->show_errors( false );
		$this->assertInstanceOf( WP_Error::class, $error, 'a failed query is never NOT_FOUND' );
		$this->assertSame( '', $out );
	}

	public function test_handle_issued_is_tri_state_over_every_users_meta(): void {
		global $wpdb, $magicauth_test_state;
		$h5 = Base64Url::encode( random_bytes( 64 ) );
		$h6 = Base64Url::encode( random_bytes( 64 ) );
		update_user_meta( 5, CredentialStore::HANDLE_META, $h5 );
		update_user_meta( 6, 'first_name', $h6 );
		$magicauth_test_state['usermeta_extra'][5][ CredentialStore::HANDLE_META ][] = $h6 . 'x';

		$this->assertTrue( CredentialStore::handle_issued( $h5 ) );
		$this->assertTrue( CredentialStore::handle_issued( $h6 . 'x' ), 'a second meta row counts too' );
		$this->assertFalse( CredentialStore::handle_issued( $h6 ), 'same value under another key is not an issued handle' );
		$this->assertFalse( CredentialStore::handle_issued( Base64Url::encode( random_bytes( 64 ) ) ) );
		$this->assertFalse( CredentialStore::handle_issued( '' ) );

		$wpdb->fail_next_query( 'FROM wp_usermeta' );
		$this->assertInstanceOf( WP_Error::class, CredentialStore::handle_issued( $h5 ) );
		$this->assertTrue( CredentialStore::handle_issued( $h5 ) );
	}

	/* ----------------------------------------------- per-user reads, snapshot */

	public function test_for_user_lists_oldest_first_and_filters_by_rp(): void {
		$user = self::user( 5 );
		$a    = self::insert( 5 );
		Clock::set_for_tests( self::NOW + 10 );
		$b = self::insert( 5, '', [ 'rp_id' => 'old.example.com' ] );
		Clock::set_for_tests( self::NOW + 20 );
		$c = self::insert( 5 );
		self::insert( 6 );

		$all = CredentialStore::for_user( $user );
		$this->assertIsArray( $all );
		$this->assertSame( [ $a, $b, $c ], array_map( static fn( $r ): int => (int) $r->id, $all ) );
		$here = CredentialStore::for_user( $user, self::RP );
		$this->assertIsArray( $here );
		$this->assertSame( [ $a, $c ], array_map( static fn( $r ): int => (int) $r->id, $here ) );
		$this->assertSame( 3, CredentialStore::count_for_user( $user ) );
		$this->assertSame( 2, CredentialStore::count_for_user( $user, self::RP ) );
		$this->assertSame( 4, CredentialStore::site_count() );
	}

	/** 7.6 rule X (T-AUTH 16b at store level): a former holder's row is invisible and never counted, but still deleted. */
	public function test_reused_user_id_row_is_invisible_to_reads_but_deleted(): void {
		$user  = self::user( 5, '2026-09-30 08:00:00' );
		$stale = self::insert( 5, '', [ 'user_registered' => '2025-01-01 10:00:00' ] );
		$mine  = self::insert( 5 );

		$rows = CredentialStore::for_user( $user );
		$this->assertIsArray( $rows );
		$this->assertSame( [ $mine ], array_map( static fn( $r ): int => (int) $r->id, $rows ) );
		$this->assertSame( 1, CredentialStore::count_for_user( $user ) );
		$this->assertSame( 1, CredentialStore::count_for_user( $user, self::RP ) );

		$this->assertSame( 2, CredentialStore::delete_all_for_user( 5 ), 'deletes match by user_id only' );
		$this->assertNull( self::row( $stale ) );
		$this->assertSame( 0, self::count_rows() );
	}

	/** Snapshot compared as a string: a user_registered written in local time is harmless when equal (16c). */
	public function test_snapshot_is_compared_verbatim(): void {
		$user = self::user( 5, '2026-09-30 10:00:00' );
		self::insert( 5, '', [ 'user_registered' => '2026-09-30 10:00:00' ] );
		self::insert( 5, '', [ 'user_registered' => '2026-09-30 08:00:00' ] );
		$this->assertSame( 1, CredentialStore::count_for_user( $user ) );
	}

	public function test_user_without_a_snapshot_value_sees_nothing(): void {
		global $wpdb;
		$user = self::user( 5, '' );
		self::insert( 5 );
		$wpdb->query_log = [];
		$this->assertSame( [], CredentialStore::for_user( $user ) );
		$this->assertSame( 0, CredentialStore::count_for_user( $user ) );
		$this->assertSame( [], $wpdb->query_log );
	}

	public function test_per_user_reads_return_null_on_a_failed_query(): void {
		global $wpdb;
		$user = self::user( 5 );
		self::insert( 5 );
		$wpdb->show_errors( true );
		ob_start();
		$wpdb->fail_next_query( 'FROM wp_magicauth_passkeys WHERE user_id' );
		$rows = CredentialStore::for_user( $user );
		$wpdb->fail_next_query( 'SELECT COUNT(*) FROM wp_magicauth_passkeys' );
		$count = CredentialStore::count_for_user( $user );
		$wpdb->fail_next_query( 'SELECT COUNT(*) FROM wp_magicauth_passkeys' );
		$site = CredentialStore::site_count();
		$out  = (string) ob_get_clean();
		$wpdb->show_errors( false );

		$this->assertNull( $rows, 'never an incomplete (empty) list' );
		$this->assertNull( $count );
		$this->assertNull( $site );
		$this->assertSame( '', $out );
	}

	/* ------------------------------------------------------- rename, delete */

	public function test_rename_by_owner_only(): void {
		self::user( 5 );
		self::user( 6 );
		$id = self::insert( 5, '', [ 'name' => 'Laptop' ] );

		$this->assertTrue( CredentialStore::rename( 5, $id, 'Work laptop' ) );
		$this->assertSame( 'Work laptop', self::row( $id )['name'] ?? null );

		$other = CredentialStore::rename( 6, $id, 'Mine now' );
		$this->assertInstanceOf( WP_Error::class, $other );
		$this->assertSame( 'magicauth_not_found', $other->get_error_code(), 'another user\'s id is not found (IDOR)' );
		$this->assertSame( 'Work laptop', self::row( $id )['name'] ?? null, 'row untouched' );

		$missing = CredentialStore::rename( 5, $id + 100, 'x' );
		$this->assertInstanceOf( WP_Error::class, $missing );
		$this->assertSame( 'magicauth_not_found', $missing->get_error_code() );
	}

	/** An unchanged name changes 0 rows on MySQL; success comes from the row existing. */
	public function test_rename_to_the_same_name_succeeds_under_changed_rows(): void {
		global $wpdb;
		self::user( 5 );
		$id = self::insert( 5, '', [ 'name' => 'Phone' ] );
		$this->assertSame( 0, $wpdb->query( $wpdb->prepare( 'UPDATE ' . CredentialStore::table() . ' SET name = %s WHERE id = %d', 'Phone', $id ) ), 'the shim reports 0 changed rows' );
		$this->assertTrue( CredentialStore::rename( 5, $id, 'Phone' ) );
	}

	public function test_rename_refuses_a_duplicate_name_case_insensitively(): void {
		self::user( 5 );
		$a = self::insert( 5, '', [ 'name' => 'Phone' ] );
		$b = self::insert( 5, '', [ 'name' => 'Laptop' ] );
		self::insert( 6, '', [ 'name' => 'Tablet' ] );

		$dup = CredentialStore::rename( 5, $b, 'PHONE' );
		$this->assertInstanceOf( WP_Error::class, $dup );
		$this->assertSame( 'magicauth_duplicate_name', $dup->get_error_code() );
		$dup = CredentialStore::rename( 5, $b, 'phone' );
		$this->assertInstanceOf( WP_Error::class, $dup );
		$this->assertSame( 'Laptop', self::row( $b )['name'] ?? null );

		$this->assertTrue( CredentialStore::rename( 5, $b, 'Tablet' ), 'another user\'s name is no conflict' );
		$this->assertTrue( CredentialStore::rename( 5, $a, 'phone' ), 'case change of its own name' );
	}

	public function test_rename_refuses_empty_and_overlong_names(): void {
		self::user( 5 );
		$id = self::insert( 5 );
		foreach ( [ '', str_repeat( 'x', 65 ) ] as $name ) {
			$r = CredentialStore::rename( 5, $id, $name );
			$this->assertInstanceOf( WP_Error::class, $r );
			$this->assertSame( 'magicauth_invalid_name', $r->get_error_code() );
		}
		$this->assertTrue( CredentialStore::rename( 5, $id, str_repeat( 'ü', 64 ) ), '64 characters, multibyte' );
	}

	public function test_rename_query_error_is_reported(): void {
		global $wpdb;
		self::user( 5 );
		$id = self::insert( 5 );
		$wpdb->fail_next_query( 'SELECT id, name' );
		$r = CredentialStore::rename( 5, $id, 'x' );
		$this->assertInstanceOf( WP_Error::class, $r );
		$this->assertSame( 'magicauth_db_error', $r->get_error_code() );
		$wpdb->fail_next_query( 'UPDATE wp_magicauth_passkeys SET name' );
		$r = CredentialStore::rename( 5, $id, 'x' );
		$this->assertInstanceOf( WP_Error::class, $r );
		$this->assertSame( 'magicauth_db_error', $r->get_error_code() );
	}

	/** 7.6 rule X: a former holder's row of the same ID neither blocks a name nor can be renamed. */
	public function test_rename_ignores_a_former_holders_row(): void {
		self::user( 5, self::REGISTERED );
		$stale = self::insert( 5, '', [
			'name'            => 'Phone',
			'user_registered' => '2025-01-01 10:00:00',
		] );
		$mine  = self::insert( 5, '', [ 'name' => 'Laptop' ] );

		$this->assertTrue( CredentialStore::rename( 5, $mine, 'phone' ), 'hidden row is no duplicate' );
		$this->assertSame( 'phone', self::row( $mine )['name'] ?? null );

		$r = CredentialStore::rename( 5, $stale, 'Old' );
		$this->assertInstanceOf( WP_Error::class, $r );
		$this->assertSame( 'magicauth_not_found', $r->get_error_code(), 'invisible row, as in for_user()' );
		$this->assertSame( 'Phone', self::row( $stale )['name'] ?? null );
	}

	/** No user, or no snapshot value: nothing is visible, so nothing is renamed and no query runs. */
	public function test_rename_without_a_user_or_snapshot_is_not_found(): void {
		global $wpdb;
		$id              = self::insert( 5, '', [ 'name' => 'Laptop' ] );
		$wpdb->query_log = [];
		$r               = CredentialStore::rename( 5, $id, 'x' );
		$this->assertInstanceOf( WP_Error::class, $r );
		$this->assertSame( 'magicauth_not_found', $r->get_error_code(), 'unknown user' );

		self::user( 5, '' );
		$r = CredentialStore::rename( 5, $id, 'x' );
		$this->assertInstanceOf( WP_Error::class, $r );
		$this->assertSame( 'magicauth_not_found', $r->get_error_code(), 'empty snapshot' );
		$this->assertSame( [], $wpdb->query_log );
		$this->assertSame( 'Laptop', self::row( $id )['name'] ?? null );
	}

	public function test_delete_by_owner_only(): void {
		$id = self::insert( 5 );

		$other = CredentialStore::delete( 6, $id );
		$this->assertInstanceOf( WP_Error::class, $other );
		$this->assertSame( 'magicauth_not_found', $other->get_error_code() );
		$this->assertNotNull( self::row( $id ), 'row intact (IDOR)' );

		$this->assertTrue( CredentialStore::delete( 5, $id ) );
		$this->assertNull( self::row( $id ) );
		$again = CredentialStore::delete( 5, $id );
		$this->assertInstanceOf( WP_Error::class, $again );
		$this->assertSame( 'magicauth_not_found', $again->get_error_code() );
	}

	public function test_delete_query_error_is_reported(): void {
		global $wpdb;
		$id = self::insert( 5 );
		$wpdb->fail_next_query( 'DELETE FROM wp_magicauth_passkeys' );
		$r = CredentialStore::delete( 5, $id );
		$this->assertInstanceOf( WP_Error::class, $r );
		$this->assertSame( 'magicauth_db_error', $r->get_error_code() );
		$wpdb->fail_next_query( 'DELETE FROM wp_magicauth_passkeys' );
		$r = CredentialStore::delete_all_for_user( 5 );
		$this->assertInstanceOf( WP_Error::class, $r );
		$this->assertNotNull( self::row( $id ) );
	}

	public function test_delete_all_for_user_leaves_other_users(): void {
		self::insert( 5 );
		self::insert( 5 );
		$other = self::insert( 6 );
		$this->assertSame( 2, CredentialStore::delete_all_for_user( 5 ) );
		$this->assertSame( 0, CredentialStore::delete_all_for_user( 5 ) );
		$this->assertSame( 0, CredentialStore::delete_all_for_user( 0 ) );
		$this->assertNotNull( self::row( $other ) );
	}

	/* ----------------------------------------------------------- counter (7.6) */

	public function test_counter_cas_only_raises(): void {
		$id = self::insert( 5, '', [ 'sign_count' => 0 ] );
		$this->assertSame( 1, CredentialStore::advance_counter( $id, 5 ) );
		$this->assertSame( 0, CredentialStore::advance_counter( $id, 5 ), 'equal: nothing changed' );
		$this->assertSame( 0, CredentialStore::advance_counter( $id, 4 ), 'lower: never written' );
		$this->assertSame( '5', (string) ( self::row( $id )['sign_count'] ?? '' ) );
		$this->assertSame( 1, CredentialStore::advance_counter( $id, 4294967295 ) );
		$this->assertSame( '4294967295', (string) ( self::row( $id )['sign_count'] ?? '' ) );
	}

	/** The WHERE alone decides: equal or lower is 0 even where the connection reports matched rows (CLIENT_FOUND_ROWS). */
	public function test_counter_cas_holds_with_matched_rows_semantics(): void {
		global $wpdb;
		$wpdb->mysql_changed_rows = false;
		$id                       = self::insert( 5, '', [ 'sign_count' => 7 ] );
		$this->assertSame( 0, CredentialStore::advance_counter( $id, 7 ) );
		$this->assertSame( 0, CredentialStore::advance_counter( $id, 6 ) );
		$this->assertSame( 1, CredentialStore::advance_counter( $id, 8 ) );
		$this->assertSame( 1, CredentialStore::block( $id ) );
		$this->assertSame( 0, CredentialStore::block( $id ), 'the IS NULL guard, not the changed-rows count' );
	}

	/** Out-of-order assertions: a concurrent higher counter wins, the later lower write changes nothing. */
	public function test_counter_cas_loses_to_a_concurrent_higher_counter(): void {
		global $wpdb;
		$id    = self::insert( 5, '', [ 'sign_count' => 3 ] );
		$inner = [];
		$wpdb->before_next_query(
			'SET sign_count',
			static function () use ( $id, &$inner ): void {
				$inner[] = CredentialStore::advance_counter( $id, 10 );
			}
		);

		$this->assertSame( 0, CredentialStore::advance_counter( $id, 8 ) );
		$this->assertSame( [ 1 ], $inner );
		$this->assertSame( '10', (string) ( self::row( $id )['sign_count'] ?? '' ) );
	}

	public function test_counter_cas_query_error_is_false(): void {
		global $wpdb;
		$id = self::insert( 5 );
		$wpdb->fail_next_query( 'SET sign_count' );
		$this->assertFalse( CredentialStore::advance_counter( $id, 9 ) );
	}

	public function test_block_changes_one_row_once(): void {
		$id = self::insert( 5, '', [ 'backup_eligible' => false ] );
		$this->assertSame( 1, CredentialStore::block( $id ) );
		Clock::set_for_tests( self::NOW + 60 );
		$this->assertSame( 0, CredentialStore::block( $id ), 'already blocked: the blocked email goes once' );
		$this->assertSame( gmdate( 'Y-m-d H:i:s', self::NOW ), self::row( $id )['counter_anomaly_at'] ?? null, 'first block time kept' );
	}

	public function test_record_use_is_not_judged_by_changed_rows(): void {
		$id = self::insert( 5, '', [ 'backup_state' => false ] );
		$this->assertTrue( CredentialStore::record_use( $id, true ) );
		$this->assertTrue( CredentialStore::record_use( $id, true ), 'a no-op write is still a success' );
		$row = self::row( $id );
		$this->assertSame( '1', (string) ( $row['backup_state'] ?? '' ) );
		$this->assertSame( gmdate( 'Y-m-d H:i:s', self::NOW ), $row['last_used_at'] ?? null );
	}

	/* ------------------------------------------------------------- user handle */

	public function test_user_handle_is_created_once_and_reused(): void {
		$this->assertNull( CredentialStore::user_handle( 5, false ), 'not created on read' );
		$this->assertSame( [], get_user_meta( 5, CredentialStore::HANDLE_META ) );

		$handle = CredentialStore::user_handle( 5, true );
		$this->assertIsString( $handle );
		$this->assertSame( 86, strlen( $handle ) );
		$this->assertSame( 64, strlen( (string) Base64Url::decode( $handle, 64, 64 ) ) );
		$this->assertSame( [ $handle ], get_user_meta( 5, CredentialStore::HANDLE_META ) );

		$this->assertSame( $handle, CredentialStore::user_handle( 5, true ) );
		$this->assertSame( $handle, CredentialStore::user_handle( 5, false ) );
		$this->assertSame( [ $handle ], get_user_meta( 5, CredentialStore::HANDLE_META ), 'no second row' );
		$this->assertNull( CredentialStore::user_handle( 0, true ) );
	}

	public function test_user_handle_is_never_derived_from_id_or_email(): void {
		self::user( 5 );
		$a = (string) CredentialStore::user_handle( 5, true );
		magicauth_test_reset_state();
		self::user( 5 );
		$b = (string) CredentialStore::user_handle( 5, true );
		$this->assertNotSame( $a, $b, 'random, not a function of the user' );
		$raw = (string) Base64Url::decode( $a, 64, 64 );
		foreach ( [ 'u5@example.test', Base64Url::encode( 'u5@example.test' ), hash( 'sha256', 'u5@example.test', true ), hash( 'sha256', '5', true ) ] as $needle ) {
			$this->assertStringNotContainsString( $needle, $a );
			$this->assertStringNotContainsString( $needle, $raw );
		}
	}

	/** Uniqueness check across users: a taken candidate is regenerated, three taken in a row fail closed. */
	public function test_user_handle_uniqueness_check(): void {
		global $magicauth_test_state;
		$magicauth_test_state['get_users_queue'] = [ [ '9' ] ];
		$handle                                  = CredentialStore::user_handle( 5, true );
		$this->assertIsString( $handle );
		$calls = $magicauth_test_state['get_users_calls'];
		$this->assertCount( 2, $calls );
		$this->assertSame( CredentialStore::HANDLE_META, $calls[0]['meta_key'] );
		$this->assertNotSame( $calls[0]['meta_value'], $calls[1]['meta_value'], 'regenerated' );
		$this->assertSame( $handle, $calls[1]['meta_value'] );

		$magicauth_test_state['get_users_queue'] = [ [ '9' ], [ '9' ], [ '9' ] ];
		$this->assertNull( CredentialStore::user_handle( 6, true ) );
		$this->assertSame( [], get_user_meta( 6, CredentialStore::HANDLE_META ), 'nothing stored' );
	}

	/**
	 * Two requests: B runs its whole user_handle() between A's unique-check
	 * COUNT and A's INSERT (core's add_metadata()). Both rows land; A keeps the
	 * earliest and deletes its own. Both callers return the survivor.
	 */
	public function test_interleaved_creation_ends_with_one_row_and_one_answer(): void {
		global $magicauth_test_state;
		$from_b                                     = [];
		$magicauth_test_state['add_user_meta_race'] = static function () use ( &$from_b ): void {
			$from_b[] = CredentialStore::user_handle( 5, true );
		};

		$from_a = CredentialStore::user_handle( 5, true );

		$this->assertCount( 1, $from_b );
		$this->assertIsString( $from_a );
		$this->assertSame( $from_b[0], $from_a, 'both callers return the survivor' );
		$this->assertSame( [ $from_a ], get_user_meta( 5, CredentialStore::HANDLE_META ), 'exactly one meta row' );
		$this->assertContains( [ 5, 'user_meta' ], $magicauth_test_state['cache_deletes'] ?? [], 'meta cache dropped before the re-read' );
	}

	/** Both inserts land before either re-read: every reader picks the same (earliest) value. */
	public function test_two_rows_resolve_to_the_earliest(): void {
		global $magicauth_test_state;
		$first  = Base64Url::encode( str_repeat( "\xff", 64 ) );
		$second = Base64Url::encode( str_repeat( "\x00", 64 ) );
		$magicauth_test_state['usermeta'][5][ CredentialStore::HANDLE_META ]         = $first;
		$magicauth_test_state['usermeta_extra'][5][ CredentialStore::HANDLE_META ][] = $second;

		$this->assertSame( $first, CredentialStore::user_handle( 5, false ), 'earliest inserted, although not the smallest' );
		$this->assertSame( $first, CredentialStore::user_handle( 5, true ) );
	}

	/* ----------------------------------------------------- orphans, delete_user */

	public function test_orphan_sweep_removes_rows_of_missing_users_only(): void {
		global $wpdb;
		self::user( 5 );
		$keep  = self::insert( 5 );
		$gone  = self::insert( 6 );
		$gone2 = self::insert( 6 );
		$sess  = SessionState::table();
		$chal  = ChallengeStore::table();
		ChallengeStore::issue( 'register', 5, self::SESSION, '', '-7', 420 );
		ChallengeStore::issue( 'register', 6, self::SESSION, '', '-7', 420 );
		ChallengeStore::issue( 'signin', 0, '', str_repeat( 'c', 64 ), '', 600 );
		foreach ( [ [ str_repeat( '1', 64 ), 5 ], [ str_repeat( '2', 64 ), 6 ] ] as [ $hash, $uid ] ) {
			$wpdb->insert( $sess, [ 'session_hash' => $hash, 'user_id' => $uid, 'expires_at' => '2030-01-01 00:00:00' ] );
		}

		$this->assertSame( 4, Installer::sweep_orphans( 1000 ) );

		$this->assertNotNull( self::row( $keep ) );
		$this->assertNull( self::row( $gone ) );
		$this->assertNull( self::row( $gone2 ) );
		$this->assertSame( [ '5', '0' ], array_map( 'strval', $wpdb->get_col( "SELECT user_id FROM {$chal} ORDER BY id" ) ), 'anonymous signin rows are not orphans' );
		$this->assertSame( [ '5' ], array_map( 'strval', $wpdb->get_col( "SELECT user_id FROM {$sess}" ) ) );
		$this->assertSame( 0, Installer::sweep_orphans( 1000 ) );
	}

	public function test_orphan_sweep_honours_its_limit_and_prints_nothing_on_error(): void {
		global $wpdb;
		for ( $i = 0; $i < 3; $i++ ) {
			self::insert( 6 );
		}
		$this->assertSame( 2, Installer::sweep_orphans( 2 ) );
		$this->assertSame( 1, self::count_rows() );

		$wpdb->show_errors( true );
		$wpdb->fail_next_query( 'LEFT JOIN' );
		ob_start();
		Installer::sweep_orphans( 10 );
		$out = (string) ob_get_clean();
		$wpdb->show_errors( false );
		$this->assertSame( '', $out );
		$this->assertSame( 1, self::count_rows(), 'failed SELECT: nothing deleted from this table' );
		$this->assertSame( 1, Installer::sweep_orphans( 10 ), 'swept on the next run' );
		$this->assertSame( 0, self::count_rows() );
	}

	private function seed_user_data( int $user_id ): void {
		global $wpdb;
		self::insert( $user_id );
		ChallengeStore::issue( 'register', $user_id, self::SESSION, '', '-7', 420 );
		$wpdb->insert( SessionState::table(), [ 'session_hash' => hash( 'sha256', (string) $user_id ), 'user_id' => $user_id, 'expires_at' => '2030-01-01 00:00:00' ] );
		$issued = TokenManager::issue( $user_id, "u{$user_id}@example.test" );
		$this->assertIsArray( $issued );
		foreach ( [ CredentialStore::HANDLE_META, 'magicauth_passkey_prompt', 'magicauth_passkey_details_at', 'magicauth_passkey_details_sent', 'magicauth_email_verified_at', 'magicauth_email_changed_at', 'first_name' ] as $key ) {
			update_user_meta( $user_id, $key, '1' );
		}
	}

	/** @return array<string,int> Rows of the user per table. */
	private static function rows_of( int $user_id ): array {
		global $wpdb;
		$out = [];
		foreach ( [ CredentialStore::table(), ChallengeStore::table(), SessionState::table(), TokenManager::table() ] as $table ) {
			$out[ $table ] = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE user_id = %d", $user_id ) );
		}
		return $out;
	}

	public function test_delete_user_on_single_site_removes_rows_and_meta(): void {
		$this->seed_user_data( 5 );
		$this->seed_user_data( 6 );

		CredentialStore::on_delete_user( 5 );

		$this->assertSame( [ 0, 0, 0, 0 ], array_values( self::rows_of( 5 ) ) );
		$this->assertSame( [ 1, 1, 1, 1 ], array_values( self::rows_of( 6 ) ), 'other users untouched' );
		foreach ( [ CredentialStore::HANDLE_META, 'magicauth_passkey_prompt', 'magicauth_passkey_details_at', 'magicauth_passkey_details_sent', 'magicauth_email_verified_at', 'magicauth_email_changed_at' ] as $key ) {
			$this->assertSame( [], get_user_meta( 5, $key ), $key );
			$this->assertSame( '1', get_user_meta( 6, $key, true ), $key );
		}
		$this->assertSame( '1', get_user_meta( 5, 'first_name', true ), 'core deletes its own meta' );
	}

	public function test_delete_user_on_multisite_keeps_network_meta_and_wpmu_delete_user_removes_it(): void {
		global $magicauth_test_state;
		$magicauth_test_state['multisite'] = true;
		$this->seed_user_data( 5 );

		CredentialStore::on_delete_user( 5 );

		$this->assertSame( [ 0, 0, 0, 0 ], array_values( self::rows_of( 5 ) ), 'this site\'s rows go' );
		$this->assertSame( '1', get_user_meta( 5, CredentialStore::HANDLE_META, true ), 'network-wide meta stays: the user may still exist on another site' );
		$this->assertSame( '1', get_user_meta( 5, 'magicauth_email_verified_at', true ) );

		CredentialStore::on_wpmu_delete_user( 5 );
		foreach ( [ CredentialStore::HANDLE_META, 'magicauth_passkey_prompt', 'magicauth_passkey_details_at', 'magicauth_passkey_details_sent', 'magicauth_email_verified_at', 'magicauth_email_changed_at' ] as $key ) {
			$this->assertSame( [], get_user_meta( 5, $key ), $key );
		}
		$this->assertSame( '1', get_user_meta( 5, 'first_name', true ) );
	}

	public function test_delete_user_ignores_non_positive_ids(): void {
		global $wpdb;
		$wpdb->query_log = [];
		CredentialStore::on_delete_user( 0 );
		CredentialStore::on_wpmu_delete_user( -1 );
		$this->assertSame( [], $wpdb->query_log );
	}
}
