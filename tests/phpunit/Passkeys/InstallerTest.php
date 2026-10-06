<?php
/**
 * T-INST (SPEC 15 steps 2 and 5, 5.4, 5.5, 14.1): maybe_upgrade() on
 * wp_loaded, the atomic INSERT IGNORE lock with its stale CAS takeover,
 * owner-only release, schema verification, cron self-heal, activation through
 * the same locked path; default_settings() as the single defaults array; Clock.
 * Step 5: delete_user removes the user's magicauth_requests rows (B10);
 * uninstall.php removes the 5.5 list (B9), run in a separate process.
 *
 * Step 8: DB version 2. The upgrade from 1 (requests table without
 * issued_by) creates the three passkey tables and adds the column; schema
 * verification covers all four tables and the column; the orphan sweep runs
 * after the version bump; daily cleanup purges challenge and session rows;
 * DDL parity between Installer::schema() and the harness DDL; the passkey
 * parts of the uninstall list. available() S8f comes with step 9.
 *
 * Part of the real-database suite (group realdb): table checks go through
 * the shim's portable helpers, never sqlite_master.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Installer;
use MagicAuth\Passkeys\Clock;
use MagicAuth\Passkeys\CredentialStore;
use MagicAuth\Passkeys\Module;
use MagicAuth\Plugin;
use PHPUnit\Framework\TestCase;

/**
 * @group realdb
 */
final class InstallerTest extends TestCase {

	private const NOW = 1790000000;

	private const LOCK = 'magicauth_upgrade_lock';

	/** @var array{0:string,1:string}|null Capture file and the previous error_log ini value. */
	private ?array $log_capture = null;

	protected function setUp(): void {
		global $wpdb;
		magicauth_test_reset_state();
		$wpdb->install_magicauth_schema();
		$wpdb->install_magicauth_passkeys_schema();
		$wpdb->query_log = [];
		Clock::set_for_tests( self::NOW );
	}

	protected function tearDown(): void {
		global $wpdb;
		$wpdb->install_magicauth_schema();
		$wpdb->install_magicauth_passkeys_schema();
		$this->release_debug_log();
		magicauth_test_reset_state();
	}

	/* ------------------------------------------------------------- helpers */

	private static function requests_table(): string {
		global $wpdb;
		return $wpdb->prefix . 'magicauth_requests';
	}

	/** @return array<int,string> The four tables of DB version 2. */
	private static function all_tables(): array {
		global $wpdb;
		return [
			$wpdb->prefix . 'magicauth_requests',
			$wpdb->prefix . 'magicauth_passkeys',
			$wpdb->prefix . 'magicauth_passkey_challenges',
			$wpdb->prefix . 'magicauth_passkey_sessions',
		];
	}

	/** Drops all four tables: a fresh boot has none of them. */
	private static function drop_requests_table(): void {
		global $wpdb;
		foreach ( self::all_tables() as $table ) {
			$wpdb->query( 'DROP TABLE IF EXISTS ' . $table );
		}
		$wpdb->query_log = [];
	}

	private static function table_exists( string $table = '' ): bool {
		global $wpdb;
		return $wpdb->table_exists( '' !== $table ? $table : self::requests_table() );
	}

	/** @return array{value:string,autoload:string}|null */
	private static function lock_row(): ?array {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT option_value, autoload FROM {$wpdb->options} WHERE option_name = %s", self::LOCK ), ARRAY_A );
		if ( ! is_array( $row ) ) {
			return null;
		}
		return [
			'value'    => (string) $row['option_value'],
			'autoload' => (string) $row['autoload'],
		];
	}

	private static function seed_lock( string $value ): void {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( "INSERT INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'off')", self::LOCK, $value ) );
		$wpdb->query_log = [];
	}

	private static function dbdelta_count(): int {
		global $magicauth_test_state;
		return count( $magicauth_test_state['dbdelta_calls'] ?? [] );
	}

	/** @return array{0:int,1:string}|null */
	private static function cron_event(): ?array {
		global $magicauth_test_state;
		return $magicauth_test_state['cron']['magicauth_daily_cleanup'] ?? null;
	}

	/* ----------------------------------------------------------- the hook */

	public function test_boot_hooks_maybe_upgrade_on_wp_loaded_priority_1(): void {
		$plugin = ( new \ReflectionClass( Plugin::class ) )->newInstanceWithoutConstructor();
		$plugin->boot();

		$this->assertSame( 1, has_action( 'wp_loaded', [ Installer::class, 'maybe_upgrade' ] ) );
		$this->assertFalse( has_action( 'plugins_loaded', [ Installer::class, 'maybe_upgrade' ] ) );
		$this->assertFalse( has_action( 'init', [ Installer::class, 'maybe_upgrade' ] ) );
	}

	/** Acceptance: fresh boot with option 0 installs the schema (file deploy, activation never ran). */
	public function test_fresh_boot_with_option_0_installs_schema_on_wp_loaded(): void {
		self::drop_requests_table();
		$this->assertFalse( get_option( 'magicauth_db_version' ) );

		$plugin = ( new \ReflectionClass( Plugin::class ) )->newInstanceWithoutConstructor();
		$plugin->boot();
		$this->assertSame( 0, self::dbdelta_count(), 'nothing migrates before wp_loaded' );

		do_action( 'wp_loaded' );

		foreach ( self::all_tables() as $table ) {
			$this->assertTrue( self::table_exists( $table ), $table );
		}
		$this->assertSame( 1, self::dbdelta_count(), 'dbDelta ran once' );
		$this->assertSame( MAGICAUTH_DB_VERSION, get_option( 'magicauth_db_version' ) );
		$this->assertNull( self::lock_row(), 'lock released' );

		$event = self::cron_event();
		$this->assertNotNull( $event, 'cleanup cron scheduled' );
		$this->assertSame( 'daily', $event[1] );

		do_action( 'wp_loaded' );
		$this->assertSame( 1, self::dbdelta_count(), 'the next request does not migrate again' );
	}

	public function test_fresh_install_from_option_0_creates_a_working_table(): void {
		global $wpdb;
		self::drop_requests_table();

		Installer::maybe_upgrade();

		$this->assertSame( 1, self::dbdelta_count() );
		$this->assertSame( 1, $wpdb->insert(
			self::requests_table(),
			[
				'selector'           => 'sel',
				'link_verifier_hash' => 'l',
				'code_verifier_hash' => 'c',
				'user_id'            => 1,
				'email_hmac'         => 'e',
				'ip_hmac'            => 'i',
				'created_at'         => '2026-10-01 00:00:00',
				'expires_at'         => '2026-10-01 00:10:00',
			]
		) );
		$this->assertSame( MAGICAUTH_DB_VERSION, get_option( 'magicauth_db_version' ) );
	}

	/** Option missing but the table already exists (older install): dbDelta keeps the rows. */
	public function test_upgrade_over_an_existing_table_keeps_rows(): void {
		global $wpdb;
		$wpdb->insert(
			self::requests_table(),
			[
				'selector'           => 'keep',
				'link_verifier_hash' => 'l',
				'code_verifier_hash' => 'c',
				'user_id'            => 7,
				'email_hmac'         => 'e',
				'ip_hmac'            => 'i',
				'created_at'         => '2026-10-01 00:00:00',
				'expires_at'         => '2026-10-01 00:10:00',
			]
		);

		Installer::maybe_upgrade();

		$this->assertSame( 1, self::dbdelta_count() );
		$this->assertSame( '7', $wpdb->get_var( 'SELECT user_id FROM ' . self::requests_table() . " WHERE selector = 'keep'" ) );
		$this->assertSame( MAGICAUTH_DB_VERSION, get_option( 'magicauth_db_version' ) );
	}

	/** Current version (int or the string the DB returns): one option read, no query, no lock, no cron write. */
	public function test_current_version_does_nothing(): void {
		global $wpdb, $magicauth_test_state;
		foreach ( [ MAGICAUTH_DB_VERSION, (string) MAGICAUTH_DB_VERSION ] as $stored ) {
			update_option( 'magicauth_db_version', $stored );
			$wpdb->query_log = [];

			Installer::maybe_upgrade();

			$this->assertSame( [], $wpdb->query_log, 'no query at all' );
			$this->assertSame( 0, self::dbdelta_count() );
			$this->assertNull( self::cron_event(), 'cron self-heal runs only with a migration' );
			$this->assertArrayNotHasKey( 'cache_deletes', $magicauth_test_state );
			$this->assertSame( $stored, get_option( 'magicauth_db_version' ) );
		}
	}

	/** Rollback then roll forward (5.7): a stored version above the code's is left alone, never lowered. */
	public function test_newer_stored_version_is_left_alone(): void {
		global $wpdb;
		update_option( 'magicauth_db_version', MAGICAUTH_DB_VERSION + 1 );

		Installer::maybe_upgrade();

		$this->assertSame( [], $wpdb->query_log );
		$this->assertSame( 0, self::dbdelta_count() );
		$this->assertSame( MAGICAUTH_DB_VERSION + 1, get_option( 'magicauth_db_version' ) );
	}

	/* ------------------------------------------------- version 1 to 2 (5.4) */

	/** A 1.0.5 install (requests table without issued_by, version 1) migrates once to 2. */
	public function test_upgrade_from_1_to_2_creates_the_passkey_tables_and_adds_issued_by(): void {
		global $wpdb, $magicauth_test_state;
		self::drop_requests_table();
		$wpdb->install_magicauth_schema( true );
		$this->assertNotContains( 'issued_by', $wpdb->table_columns( self::requests_table() ) );
		self::insert_request( 'v1-row', 7 );
		update_option( 'magicauth_db_version', 1 );

		Installer::maybe_upgrade();

		$this->assertSame( 1, self::dbdelta_count(), 'dbDelta ran once' );
		$this->assertCount( 4, $magicauth_test_state['dbdelta_calls'][0]['queries'], 'all four CREATE TABLE strings in one call' );
		foreach ( self::all_tables() as $table ) {
			$this->assertTrue( self::table_exists( $table ), $table );
		}
		$this->assertContains( 'issued_by', $wpdb->table_columns( self::requests_table() ) );
		$this->assertSame( '0', (string) $wpdb->get_var( 'SELECT issued_by FROM ' . self::requests_table() . " WHERE selector = 'v1-row'" ), 'existing rows keep working: issued_by 0' );
		$this->assertContains( 'user_registered', $wpdb->table_columns( $wpdb->prefix . 'magicauth_passkeys' ), 'passkeys table with the snapshot column' );
		$this->assertContains( 'user_handle', $wpdb->table_columns( $wpdb->prefix . 'magicauth_passkey_challenges' ) );
		$this->assertSame( 2, get_option( 'magicauth_db_version' ) );
		$this->assertSame( 2, MAGICAUTH_DB_VERSION );
		$this->assertNull( self::lock_row() );

		Installer::maybe_upgrade();
		$this->assertSame( 1, self::dbdelta_count(), 'version 2: nothing more to do' );
	}

	/**
	 * r2-session-02: 1.0.5 did not record who created a link. A row still
	 * outstanding at the v1 to v2 step is voided, so an administrator's
	 * "Create magic-link" from before the update cannot sign in as 'link'
	 * (fresh, mailbox proof, prompt) afterwards.
	 */
	public function test_upgrade_from_1_voids_outstanding_1_0_5_links(): void {
		global $wpdb;
		self::drop_requests_table();
		$wpdb->install_magicauth_schema( true );
		magicauth_test_register_user( 7, 'learner7@example.test' );
		$issued = \MagicAuth\Auth\TokenManager::issue( 7, 'learner7@example.test' );
		$this->assertIsArray( $issued, '1.0.5 table: issue writes no issued_by' );
		self::insert_request( 'v1-used', 8, '2026-09-30 12:00:00' );
		update_option( 'magicauth_db_version', 1 );

		Installer::maybe_upgrade();

		$this->assertSame( 2, get_option( 'magicauth_db_version' ) );
		$this->assertSame( gmdate( 'Y-m-d H:i:s', self::NOW ), (string) $wpdb->get_var( $wpdb->prepare( 'SELECT consumed_at FROM ' . self::requests_table() . ' WHERE selector = %s', $issued['selector'] ) ), 'outstanding row voided' );
		$this->assertSame( '2026-09-30 12:00:00', (string) $wpdb->get_var( 'SELECT consumed_at FROM ' . self::requests_table() . " WHERE selector = 'v1-used'" ), 'a consumed row keeps its time' );
		parse_str( (string) wp_parse_url( (string) $issued['link_url'], PHP_URL_QUERY ), $args );
		$this->assertInstanceOf( \WP_Error::class, \MagicAuth\Auth\TokenManager::validate_link( (string) $args['s'], (string) $args['v'] ), 'a 1.0.5 link does not sign in after the upgrade' );

		$after = \MagicAuth\Auth\TokenManager::issue( 7, 'learner7@example.test' );
		$this->assertIsArray( $after );
		Installer::activate();
		parse_str( (string) wp_parse_url( (string) $after['link_url'], PHP_URL_QUERY ), $args );
		$this->assertInstanceOf( \WP_User::class, \MagicAuth\Auth\TokenManager::validate_link( (string) $args['s'], (string) $args['v'] ), 'at version 2 (reactivation) links are left alone' );
	}

	/** r2-session-02: a failed void is a failed migration: no version bump, backoff, lock kept. */
	public function test_failed_void_of_1_0_5_links_keeps_version_1(): void {
		global $wpdb;
		$log = $this->capture_debug_log();
		self::drop_requests_table();
		$wpdb->install_magicauth_schema( true );
		self::insert_request( 'v1-open', 7, null, '2099-01-01 00:00:00' );
		update_option( 'magicauth_db_version', 1 );
		$wpdb->fail_next_query( 'UPDATE ' . self::requests_table() . ' SET consumed_at' );

		Installer::maybe_upgrade();

		$this->assertSame( 1, get_option( 'magicauth_db_version' ), 'version NOT bumped' );
		$this->assertNotNull( self::lock_row(), 'lock kept' );
		$this->assertIsArray( get_option( 'magicauth_upgrade_retry' ), 'backoff scheduled' );
		$this->assertNull( $wpdb->get_var( 'SELECT consumed_at FROM ' . self::requests_table() . " WHERE selector = 'v1-open'" ) );
		$this->assertStringContainsString( 'maybe_upgrade: voiding 1.0.5 sign-in links failed', (string) file_get_contents( $log ) );

		Clock::set_for_tests( self::NOW + 600 );
		Installer::maybe_upgrade();
		$this->assertSame( 2, get_option( 'magicauth_db_version' ), 'retried after the backoff' );
		$this->assertNotNull( $wpdb->get_var( 'SELECT consumed_at FROM ' . self::requests_table() . " WHERE selector = 'v1-open'" ) );
	}

	/** Rollback to 1.0.5 and forward again (5.7): stored 2 with the tables present runs nothing. */
	public function test_roll_forward_at_version_2_is_a_no_op(): void {
		global $wpdb;
		update_option( 'magicauth_db_version', '2' );
		$wpdb->query_log = [];

		Installer::maybe_upgrade();

		$this->assertSame( [], $wpdb->query_log );
		$this->assertSame( 0, self::dbdelta_count() );
	}

	/** @return array<string,array{0:string}> */
	public static function schema_checks(): array {
		return [
			'requests'        => [ 'SELECT 1 FROM wp_magicauth_requests' ],
			'passkeys'        => [ 'SELECT 1 FROM wp_magicauth_passkeys ' ],
			'challenges'      => [ 'SELECT 1 FROM wp_magicauth_passkey_challenges' ],
			'sessions'        => [ 'SELECT 1 FROM wp_magicauth_passkey_sessions' ],
			'issued_by column' => [ 'SELECT issued_by FROM wp_magicauth_requests' ],
		];
	}

	/** @dataProvider schema_checks */
	public function test_schema_verification_covers_every_table_and_issued_by( string $failing ): void {
		global $wpdb;
		$this->capture_debug_log();
		update_option( 'magicauth_db_version', 1 );
		$wpdb->fail_next_query( $failing );

		Installer::maybe_upgrade();

		$this->assertSame( 1, get_option( 'magicauth_db_version' ), 'version stays 1' );
		$this->assertNotNull( self::lock_row(), 'lock kept' );
		$this->assert_s8f();
	}

	/** The module is unavailable with S8f (an https site, so the earlier S8 checks pass). */
	private function assert_s8f(): void {
		global $magicauth_test_state;
		$magicauth_test_state['is_ssl'] = true;
		$available                      = Module::available();
		$this->assertInstanceOf( \WP_Error::class, $available );
		$this->assertSame( 'magicauth_pk_schema', $available->get_error_code(), 'S8f' );
		$magicauth_test_state['is_ssl'] = false;
	}

	/** A requests table that exists but lost issued_by (a failed ALTER) fails the check. */
	public function test_schema_verification_fails_without_the_issued_by_column(): void {
		global $wpdb;
		$this->capture_debug_log();
		update_option( 'magicauth_db_version', 1 );
		$wpdb->install_magicauth_schema( true );
		$wpdb->fail_next_query( 'ALTER TABLE ' . self::requests_table() );

		Installer::maybe_upgrade();

		$this->assertSame( 1, get_option( 'magicauth_db_version' ) );
	}

	/** The orphan sweep runs right after the version bump, and never when the schema check failed. */
	public function test_migration_sweeps_orphans_after_the_bump_only(): void {
		global $wpdb;
		$this->capture_debug_log();
		magicauth_test_register_user( 5, 'kept@example.test' );
		$passkeys = $wpdb->prefix . 'magicauth_passkeys';
		foreach ( [ 5, 6 ] as $uid ) {
			$wpdb->insert(
				$passkeys,
				[
					'user_id'         => $uid,
					'rp_id'           => 'example.test',
					'credential_id'   => 'id' . $uid,
					'credential_hash' => str_repeat( (string) $uid, 64 ),
					'user_handle'     => 'h',
					'public_key'      => 'k',
					'alg'             => -7,
					'created_at'      => '2026-10-01 00:00:00',
				]
			);
		}
		update_option( 'magicauth_db_version', 1 );
		$wpdb->fail_next_query( 'SELECT 1 FROM ' . $passkeys . ' ' );

		Installer::maybe_upgrade();
		$this->assertSame( [ '5', '6' ], array_map( 'strval', $wpdb->get_col( "SELECT user_id FROM {$passkeys} ORDER BY user_id" ) ), 'no sweep before the schema is verified' );

		Clock::set_for_tests( self::NOW + 600 );
		Installer::maybe_upgrade();
		$this->assertSame( 2, get_option( 'magicauth_db_version' ) );
		$this->assertSame( [ '5' ], array_map( 'strval', $wpdb->get_col( "SELECT user_id FROM {$passkeys}" ) ), 'user 6 does not exist: swept' );
	}

	/** DDL parity: the harness DDL has the production columns (in order) and the same keys. */
	public function test_ddl_parity_between_production_and_the_harness(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$schema = Installer::schema();
		$this->assertCount( 4, $schema );

		foreach ( $schema as $i => $ddl ) {
			$parsed = \magicauth_test_parse_create_table( $ddl );
			$this->assertNotNull( $parsed, "statement {$i} parses" );
			$table = $parsed['table'];
			$this->assertSame( self::all_tables()[ $i ], $table );
			$this->assertSame( array_keys( $parsed['columns'] ), $wpdb->table_columns( $table ), "{$table}: columns" );

			$want = [];
			foreach ( $parsed['indexes'] as $name => $info ) {
				$want[ $name ] = [
					'unique'  => $info['unique'],
					'columns' => $info['columns'],
				];
			}
			ksort( $want );
			$this->assertSame( $want, $wpdb->table_indexes( $table ), "{$table}: keys" );
			$this->assertStringContainsString( 'PRIMARY KEY  (', $ddl, 'dbDelta wants two spaces' );
			$this->assertStringNotContainsString( '`', $ddl );
		}
	}

	/** The production DDL run through dbDelta yields the harness tables, and the UNIQUE keys hold. */
	public function test_production_ddl_through_dbdelta_matches_and_enforces_unique_keys(): void {
		global $wpdb;
		$harness = [];
		foreach ( self::all_tables() as $table ) {
			$harness[ $table ] = [ $wpdb->table_columns( $table ), $wpdb->table_indexes( $table ) ];
		}
		self::drop_requests_table();

		Installer::maybe_upgrade();

		foreach ( self::all_tables() as $table ) {
			$this->assertSame( $harness[ $table ], [ $wpdb->table_columns( $table ), $wpdb->table_indexes( $table ) ], $table );
		}
		$challenge = [
			'lookup_hash' => str_repeat( 'a', 64 ),
			'ceremony'    => 'signin',
			'created_at'  => '2026-10-01 00:00:00',
			'expires_at'  => '2026-10-01 00:10:00',
		];
		$this->assertSame( 1, $wpdb->insert( $wpdb->prefix . 'magicauth_passkey_challenges', $challenge ) );
		$wpdb->suppress_errors( true );
		$this->assertFalse( $wpdb->insert( $wpdb->prefix . 'magicauth_passkey_challenges', $challenge ), 'UNIQUE lookup_hash' );
		$session = [ 'session_hash' => str_repeat( 'b', 64 ), 'user_id' => 1, 'expires_at' => '2030-01-01 00:00:00' ];
		$this->assertSame( 1, $wpdb->insert( $wpdb->prefix . 'magicauth_passkey_sessions', $session ) );
		$this->assertFalse( $wpdb->insert( $wpdb->prefix . 'magicauth_passkey_sessions', $session ), 'PRIMARY KEY session_hash' );
		$credential = [ 'user_id' => 1, 'rp_id' => 'r', 'credential_id' => 'c', 'credential_hash' => str_repeat( 'c', 64 ), 'user_handle' => 'h', 'public_key' => 'k', 'alg' => -7, 'created_at' => '2026-10-01 00:00:00' ];
		$this->assertSame( 1, $wpdb->insert( $wpdb->prefix . 'magicauth_passkeys', $credential ) );
		$this->assertFalse( $wpdb->insert( $wpdb->prefix . 'magicauth_passkeys', [ 'user_id' => 2 ] + $credential ), 'UNIQUE credential_hash across users' );
		$wpdb->suppress_errors( false );
	}

	/* --------------------------------------------------------- daily cleanup */

	public function test_daily_cleanup_purges_challenges_sessions_and_orphans(): void {
		global $wpdb;
		magicauth_test_register_user( 5, 'kept@example.test' );
		$challenges = $wpdb->prefix . 'magicauth_passkey_challenges';
		$sessions   = $wpdb->prefix . 'magicauth_passkey_sessions';
		$passkeys   = $wpdb->prefix . 'magicauth_passkeys';
		$at         = static fn( int $offset ): string => gmdate( 'Y-m-d H:i:s', self::NOW + $offset );
		foreach ( [ 'old' => -3601, 'recent' => -3599, 'live' => 60 ] as $key => $offset ) {
			$wpdb->insert( $challenges, [ 'lookup_hash' => str_pad( $key, 64, 'x' ), 'ceremony' => 'signin', 'created_at' => $at( $offset - 600 ), 'expires_at' => $at( $offset ) ] );
		}
		foreach ( [ 'gone' => -1, 'live' => 60 ] as $key => $offset ) {
			$wpdb->insert( $sessions, [ 'session_hash' => str_pad( $key, 64, 'x' ), 'user_id' => 5, 'expires_at' => $at( $offset ) ] );
		}
		foreach ( [ 5, 6 ] as $uid ) {
			$wpdb->insert( $passkeys, [ 'user_id' => $uid, 'rp_id' => 'r', 'credential_id' => 'c' . $uid, 'credential_hash' => str_repeat( (string) $uid, 64 ), 'user_handle' => 'h', 'public_key' => 'k', 'alg' => -7, 'created_at' => $at( -9999 ) ] );
		}

		Installer::daily_cleanup();

		$this->assertSame( [ str_pad( 'live', 64, 'x' ), str_pad( 'recent', 64, 'x' ) ], $wpdb->get_col( "SELECT lookup_hash FROM {$challenges} ORDER BY lookup_hash" ), 'challenge rows go one hour after expiry' );
		$this->assertSame( [ str_pad( 'live', 64, 'x' ) ], $wpdb->get_col( "SELECT session_hash FROM {$sessions}" ) );
		$this->assertSame( [ '5' ], array_map( 'strval', $wpdb->get_col( "SELECT user_id FROM {$passkeys}" ) ), 'credentials only when their user is gone' );
		$this->assertSame( '', $wpdb->last_error );
	}

	/* ---------------------------------------------------------- the lock */

	public function test_lock_row_is_unique_per_request_autoload_off_and_timestamped(): void {
		global $wpdb, $magicauth_test_state;
		self::drop_requests_table();
		$seen = [];
		$wpdb->before_next_query(
			'CREATE TABLE ' . self::requests_table(),
			static function () use ( &$seen ): void {
				$seen[] = self::lock_row();
			}
		);

		Installer::maybe_upgrade();

		$this->assertCount( 1, $seen );
		$this->assertNotNull( $seen[0] );
		$this->assertSame( 'off', $seen[0]['autoload'] );
		$this->assertMatchesRegularExpression( '/^\d+:[0-9a-f]{16}$/', $seen[0]['value'] );
		$this->assertSame( self::NOW, (int) $seen[0]['value'], '(int) of the lock value is the time it was taken' );
		$this->assertNull( self::lock_row(), 'released after the migration' );
		$this->assertContains( [ self::LOCK, 'options' ], $magicauth_test_state['cache_deletes'] ?? [], 'option cache cleared after the direct SQL' );

		// A second migration takes a different value (random part), even at the same second.
		$first = $seen[0]['value'];
		delete_option( 'magicauth_db_version' );
		self::drop_requests_table();
		$wpdb->before_next_query(
			'CREATE TABLE ' . self::requests_table(),
			static function () use ( &$seen ): void {
				$seen[] = self::lock_row();
			}
		);
		Installer::maybe_upgrade();
		$this->assertCount( 2, $seen );
		$this->assertNotNull( $seen[1] );
		$this->assertNotSame( $first, $seen[1]['value'] );
	}

	public function test_lock_held_by_a_fresh_value_skips(): void {
		$held = ( self::NOW - 599 ) . ':aaaaaaaaaaaaaaaa';
		self::seed_lock( $held );
		self::drop_requests_table();

		Installer::maybe_upgrade();

		$this->assertSame( 0, self::dbdelta_count(), 'another request is migrating' );
		$this->assertFalse( self::table_exists() );
		$this->assertFalse( get_option( 'magicauth_db_version' ), 'version not written' );
		$this->assertNull( self::cron_event() );
		$this->assertSame( $held, self::lock_row()['value'] ?? null, 'a lock this request does not own is never touched' );
	}

	/** Two requests: the second starts while the first is inside dbDelta. Exactly one migrates. */
	public function test_second_lock_attempt_while_the_first_holds_it_gives_one_migrator(): void {
		global $wpdb;
		self::drop_requests_table();
		$inner = [];
		$wpdb->before_next_query(
			'CREATE TABLE ' . self::requests_table(),
			static function () use ( &$inner ): void {
				$before  = self::lock_row();
				Installer::maybe_upgrade();
				$inner[] = [ $before, self::lock_row(), get_option( 'magicauth_db_version' ) ];
			}
		);

		Installer::maybe_upgrade();

		$this->assertSame( 1, self::dbdelta_count(), 'exactly one migrator' );
		$this->assertCount( 1, $inner, 'the second request ran mid-migration' );
		$this->assertNotNull( $inner[0][0] );
		$this->assertSame( $inner[0][0], $inner[0][1], 'the loser leaves the holder\'s lock alone' );
		$this->assertFalse( $inner[0][2], 'the loser does not write the version' );
		$this->assertSame( MAGICAUTH_DB_VERSION, get_option( 'magicauth_db_version' ) );
		$this->assertNull( self::lock_row() );
		$this->assertTrue( self::table_exists() );
	}

	public function test_lock_exactly_600_seconds_old_is_stale_and_taken_over(): void {
		self::seed_lock( ( self::NOW - 600 ) . ':aaaaaaaaaaaaaaaa' );
		self::drop_requests_table();

		Installer::maybe_upgrade();

		$this->assertSame( 1, self::dbdelta_count() );
		$this->assertTrue( self::table_exists() );
		$this->assertSame( MAGICAUTH_DB_VERSION, get_option( 'magicauth_db_version' ) );
		$this->assertNull( self::lock_row(), 'the taken-over lock is released by its new owner' );
	}

	/** A lock row without a parsable time (or left empty) counts as stale, so it cannot wedge upgrades. */
	public function test_garbage_lock_value_is_stale(): void {
		self::seed_lock( 'garbage' );
		self::drop_requests_table();

		Installer::maybe_upgrade();

		$this->assertSame( 1, self::dbdelta_count() );
		$this->assertNull( self::lock_row() );
	}

	/** Stale lock, two requests: the competitor completes its CAS takeover first; ours must lose. */
	public function test_concurrent_second_takeover_of_a_stale_lock_loses(): void {
		global $wpdb;
		$stale = ( self::NOW - 3600 ) . ':aaaaaaaaaaaaaaaa';
		self::seed_lock( $stale );
		self::drop_requests_table();

		// The competitor read the same stale value and wins the CAS just before ours runs.
		$winner = self::NOW . ':bbbbbbbbbbbbbbbb';
		$wpdb->before_next_query(
			"/^UPDATE {$wpdb->options} SET option_value/",
			static function () use ( $wpdb, $stale, $winner ): void {
				$wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s AND option_value = %s", $winner, self::LOCK, $stale ) );
			}
		);

		Installer::maybe_upgrade();

		$this->assertSame( 0, self::dbdelta_count(), 'the losing takeover does not migrate' );
		$this->assertFalse( get_option( 'magicauth_db_version' ) );
		$this->assertSame( $winner, self::lock_row()['value'] ?? null, 'the winner\'s lock is left in place' );
	}

	/** Same race with a real second maybe_upgrade() as the competitor: exactly one migrator. */
	public function test_two_stale_takeovers_run_one_migration(): void {
		global $wpdb;
		self::seed_lock( ( self::NOW - 3600 ) . ':aaaaaaaaaaaaaaaa' );
		self::drop_requests_table();
		$wpdb->before_next_query(
			"/^UPDATE {$wpdb->options} SET option_value/",
			static function (): void {
				Installer::maybe_upgrade();
			}
		);

		Installer::maybe_upgrade();

		$this->assertSame( 1, self::dbdelta_count(), 'exactly one migrator' );
		$this->assertSame( MAGICAUTH_DB_VERSION, get_option( 'magicauth_db_version' ) );
		$this->assertNull( self::lock_row(), 'the winner released its own lock' );
	}

	/** Our lock was taken over mid-migration (we ran past 600 s): the release must not delete the new owner's lock. */
	public function test_lock_released_only_by_its_owner(): void {
		global $wpdb;
		self::drop_requests_table();
		$other = ( self::NOW + 700 ) . ':cccccccccccccccc';
		$wpdb->before_next_query(
			'CREATE TABLE ' . self::requests_table(),
			static function () use ( $wpdb, $other ): void {
				$wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s", $other, self::LOCK ) );
			}
		);

		Installer::maybe_upgrade();

		$this->assertSame( $other, self::lock_row()['value'] ?? null, 'the other owner\'s lock survives our release' );
		$this->assertSame( 1, self::dbdelta_count() );
	}

	/* ------------------------------------------------ schema verification */

	public function test_schema_verification_failure_keeps_version_and_lock_until_stale(): void {
		global $wpdb;
		$log = $this->capture_debug_log();
		self::drop_requests_table();
		$wpdb->fail_next_query( 'SELECT 1 FROM ' . self::requests_table() );

		Installer::maybe_upgrade();

		$this->assertSame( 1, self::dbdelta_count() );
		$this->assertFalse( get_option( 'magicauth_db_version' ), 'version NOT bumped' );
		$this->assertNull( self::cron_event(), 'no cron before the schema is verified' );
		$kept = self::lock_row();
		$this->assertNotNull( $kept, 'lock kept, so requests do not retry dbDelta every time' );
		$this->assertSame( self::NOW, (int) $kept['value'] );
		$this->assertStringContainsString( 'maybe_upgrade: schema verification failed', (string) file_get_contents( $log ) );
		$this->assert_s8f();

		Clock::set_for_tests( self::NOW + 599 );
		Installer::maybe_upgrade();
		$this->assertSame( 1, self::dbdelta_count(), 'no retry while the kept lock is fresh' );

		Clock::set_for_tests( self::NOW + 600 );
		Installer::maybe_upgrade();
		$this->assertSame( 2, self::dbdelta_count(), 'retried by the stale takeover' );
		$this->assertSame( MAGICAUTH_DB_VERSION, get_option( 'magicauth_db_version' ) );
		$this->assertNull( self::lock_row() );
		$this->assertNotNull( self::cron_event() );
		$GLOBALS['magicauth_test_state']['is_ssl'] = true;
		$this->assertTrue( Module::available(), 'available once the migration is verified' );
	}

	/**
	 * r1-data-05: a schema check that keeps failing backs off exponentially.
	 * Inside the window a request runs no query at all (no lock INSERT or
	 * SELECT, no dbDelta); a success clears the backoff.
	 */
	public function test_repeated_schema_failure_backs_off_without_queries(): void {
		global $wpdb;
		$this->capture_debug_log();
		$fail = function (): void {
			global $wpdb;
			self::drop_requests_table();
			$wpdb->fail_next_query( 'SELECT 1 FROM ' . self::requests_table() );
		};

		$fail();
		Installer::maybe_upgrade();
		$this->assertSame( 1, self::dbdelta_count() );
		$this->assertSame( [ 'at' => self::NOW + 600, 'n' => 1 ], get_option( 'magicauth_upgrade_retry' ) );

		$wpdb->query_log = [];
		Clock::set_for_tests( self::NOW + 599 );
		Installer::maybe_upgrade();
		$this->assertSame( [], $wpdb->query_log, 'inside the backoff: no query at all' );

		// Second failure: the wait doubles.
		Clock::set_for_tests( self::NOW + 600 );
		$fail();
		Installer::maybe_upgrade();
		$this->assertSame( 2, self::dbdelta_count() );
		$this->assertSame( [ 'at' => self::NOW + 600 + 1200, 'n' => 2 ], get_option( 'magicauth_upgrade_retry' ) );

		$wpdb->query_log = [];
		Clock::set_for_tests( self::NOW + 600 + 1199 );
		Installer::maybe_upgrade();
		$this->assertSame( [], $wpdb->query_log, 'a stale lock alone no longer triggers a retry' );
		$this->assertSame( 2, self::dbdelta_count() );

		Clock::set_for_tests( self::NOW + 600 + 1200 );
		Installer::maybe_upgrade();
		$this->assertSame( 3, self::dbdelta_count(), 'retried when the backoff ends' );
		$this->assertSame( MAGICAUTH_DB_VERSION, get_option( 'magicauth_db_version' ) );
		$this->assertFalse( get_option( 'magicauth_upgrade_retry' ), 'success clears the backoff' );
		$this->assertNull( self::lock_row() );
	}

	/** The backoff is capped at a day. */
	public function test_schema_failure_backoff_is_capped_at_a_day(): void {
		global $wpdb;
		$this->capture_debug_log();
		update_option( 'magicauth_upgrade_retry', [ 'at' => self::NOW - 1, 'n' => 9 ] );
		self::drop_requests_table();
		$wpdb->fail_next_query( 'SELECT 1 FROM ' . self::requests_table() );

		Installer::maybe_upgrade();

		$this->assertSame( [ 'at' => self::NOW + DAY_IN_SECONDS, 'n' => 10 ], get_option( 'magicauth_upgrade_retry' ) );
	}

	/**
	 * The S8f reason on the settings screen says "Reload this page to retry":
	 * an administrator there is not held by the backoff (only by a fresh lock).
	 */
	public function test_settings_screen_retries_inside_the_backoff(): void {
		global $magicauth_test_state;
		update_option( 'magicauth_upgrade_retry', [ 'at' => self::NOW + 3600, 'n' => 3 ] );
		self::drop_requests_table();
		$_GET = [ 'page' => 'magicauth' ];

		Installer::maybe_upgrade();
		$this->assertSame( 0, self::dbdelta_count(), 'not admin: held' );

		$magicauth_test_state['is_admin'] = true;
		magicauth_test_register_user( 7, 'admin@example.test', [ 'administrator' ] );
		magicauth_test_login_as( 7 );
		Installer::maybe_upgrade();
		$_GET = [];

		$this->assertSame( 1, self::dbdelta_count(), 'the admin on the settings screen retries' );
		$this->assertSame( MAGICAUTH_DB_VERSION, get_option( 'magicauth_db_version' ) );
		$this->assertFalse( get_option( 'magicauth_upgrade_retry' ) );
	}

	/** Activation (force) ignores the backoff. */
	public function test_activation_ignores_the_backoff(): void {
		update_option( 'magicauth_upgrade_retry', [ 'at' => self::NOW + 3600, 'n' => 3 ] );
		self::drop_requests_table();

		Installer::activate();

		$this->assertSame( 1, self::dbdelta_count() );
		$this->assertFalse( get_option( 'magicauth_upgrade_retry' ) );
	}

	/** A failing DDL prints nothing with show_errors on, and suppress_errors is restored to its old value. */
	public function test_failing_ddl_prints_nothing_and_restores_suppress_errors(): void {
		global $wpdb;
		self::drop_requests_table();
		foreach ( [ false, true ] as $previous ) {
			$wpdb->show_errors( true );
			$wpdb->suppress_errors( $previous );
			$wpdb->fail_next_query( 'CREATE TABLE ' . self::requests_table() );

			ob_start();
			Installer::maybe_upgrade();
			$out = (string) ob_get_clean();

			$this->assertSame( '', $out, 'no SQL printed into the page' );
			$this->assertSame( $previous, $wpdb->suppress_errors, 'suppress_errors restored' );
			$this->assertFalse( get_option( 'magicauth_db_version' ), 'table missing: schema check fails, no bump' );
			$this->assertFalse( self::table_exists() );

			// Next round: clear the kept lock and the backoff as a later retry would.
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s", self::LOCK ) );
			delete_option( 'magicauth_upgrade_retry' );
		}
		$wpdb->show_errors( false );
	}

	/* -------------------------------------------------------- cron self-heal */

	public function test_cron_rescheduled_when_missing(): void {
		global $magicauth_test_state;
		$before = time();

		Installer::maybe_upgrade();

		$event = self::cron_event();
		$this->assertNotNull( $event );
		$this->assertSame( 'daily', $event[1] );
		$this->assertGreaterThanOrEqual( $before + DAY_IN_SECONDS, $event[0] );
		$this->assertLessThanOrEqual( time() + DAY_IN_SECONDS, $event[0] );
		$this->assertSame( [ 'magicauth_daily_cleanup' ], $magicauth_test_state['cron_schedule_calls'] );
	}

	public function test_cron_not_duplicated_when_present(): void {
		global $magicauth_test_state;
		$magicauth_test_state['cron']['magicauth_daily_cleanup'] = [ 1234, 'daily' ];

		Installer::maybe_upgrade();

		$this->assertSame( [ 1234, 'daily' ], self::cron_event() );
		$this->assertArrayNotHasKey( 'cron_schedule_calls', $magicauth_test_state );
		$this->assertSame( MAGICAUTH_DB_VERSION, get_option( 'magicauth_db_version' ) );
	}

	/* ------------------------------------------------------------ activate */

	public function test_activate_installs_seeds_and_schedules(): void {
		self::drop_requests_table();

		Installer::activate();

		$this->assertTrue( self::table_exists() );
		$this->assertSame( 1, self::dbdelta_count() );
		$this->assertSame( MAGICAUTH_DB_VERSION, get_option( 'magicauth_db_version' ) );
		$this->assertNotNull( self::cron_event() );
		$this->assertNull( self::lock_row() );

		$seed = get_option( 'magicauth_settings' );
		$this->assertIsArray( $seed );
		$expected                 = Installer::default_settings();
		$expected['company_name'] = (string) get_bloginfo( 'name' );
		$this->assertSame( $expected, $seed );
	}

	/** Reactivation repairs a missing table even when the stored version is current, as 1.0.5 did. */
	public function test_activate_repairs_a_missing_table_at_the_current_version(): void {
		update_option( 'magicauth_db_version', MAGICAUTH_DB_VERSION );
		self::drop_requests_table();

		Installer::activate();

		$this->assertTrue( self::table_exists() );
		$this->assertSame( 1, self::dbdelta_count() );
		$this->assertNull( self::lock_row() );
	}

	public function test_activate_keeps_existing_settings(): void {
		update_option( 'magicauth_settings', [ 'company_name' => 'Acme' ] );

		Installer::activate();

		$this->assertSame( [ 'company_name' => 'Acme' ], get_option( 'magicauth_settings' ) );
	}

	/** Activation during another request's migration: no second dbDelta; settings and cron still set up. */
	public function test_activate_respects_a_fresh_lock(): void {
		$held = ( self::NOW - 10 ) . ':aaaaaaaaaaaaaaaa';
		self::seed_lock( $held );

		Installer::activate();

		$this->assertSame( 0, self::dbdelta_count() );
		$this->assertSame( $held, self::lock_row()['value'] ?? null );
		$this->assertFalse( get_option( 'magicauth_db_version' ), 'the lock holder writes the version' );
		$this->assertIsArray( get_option( 'magicauth_settings' ) );
		$this->assertNotNull( self::cron_event() );
	}

	/* ------------------------------------------------- delete_user (B10) */

	private static function insert_request( string $selector, int $user_id, ?string $consumed_at = null, string $expires_at = '2026-10-01 00:10:00', string $table = '' ): void {
		global $wpdb;
		$wpdb->insert(
			'' !== $table ? $table : self::requests_table(),
			[
				'selector'           => $selector,
				'link_verifier_hash' => 'l',
				'code_verifier_hash' => 'c',
				'user_id'            => $user_id,
				'email_hmac'         => 'e',
				'ip_hmac'            => 'i',
				'created_at'         => '2026-10-01 00:00:00',
				'expires_at'         => $expires_at,
				'consumed_at'        => $consumed_at,
			]
		);
	}

	/** @return array<int,string> Selectors of the user's rows, sorted. */
	private static function selectors_of( int $user_id, string $table = '' ): array {
		global $wpdb;
		$table = '' !== $table ? $table : self::requests_table();
		return $wpdb->get_col( $wpdb->prepare( "SELECT selector FROM {$table} WHERE user_id = %d ORDER BY selector", $user_id ) );
	}

	/** Core fires delete_user with ( $id, $reassign, $user ) before the user row goes. */
	private static function fire_delete_user( int $user_id, ?int $reassign = null ): void {
		do_action( 'delete_user', $user_id, $reassign, magicauth_test_register_user( $user_id, "u{$user_id}@example.test" ) );
	}

	/**
	 * Wired on every request type (wp-admin, front end, cron, CLI), not only in
	 * wp-admin, and with the module off. Since build step 10 through
	 * Passkeys\Module::setup(): CredentialStore::on_delete_user() also runs
	 * Installer::on_delete_user() (one registration, never two deletes).
	 */
	public function test_boot_hooks_delete_user_cleanup_outside_admin(): void {
		$plugin = ( new \ReflectionClass( Plugin::class ) )->newInstanceWithoutConstructor();
		$plugin->boot();

		$this->assertFalse( is_admin() );
		$this->assertSame( 10, has_action( 'delete_user', [ CredentialStore::class, 'on_delete_user' ] ) );
		$this->assertFalse( has_action( 'delete_user', [ Installer::class, 'on_delete_user' ] ), 'requests rows deleted once, by the store' );
		$this->assertSame( 10, has_action( 'wpmu_delete_user', [ CredentialStore::class, 'on_wpmu_delete_user' ] ) );
	}

	public function test_delete_user_removes_every_requests_row_of_that_user(): void {
		self::insert_request( 'u5-open', 5 );
		self::insert_request( 'u5-used', 5, '2026-10-01 00:01:00' );
		self::insert_request( 'u5-expired', 5, null, '2020-01-01 00:00:00' );
		self::insert_request( 'u6-open', 6 );
		$plugin = ( new \ReflectionClass( Plugin::class ) )->newInstanceWithoutConstructor();
		$plugin->boot();

		self::fire_delete_user( 5 );

		$this->assertSame( [], self::selectors_of( 5 ), 'rows gone on delete, not left for cron' );
		$this->assertSame( [ 'u6-open' ], self::selectors_of( 6 ), 'other users keep theirs' );
	}

	/** Core reassigns posts and links only; sign-in rows are never handed to the reassign target. */
	public function test_delete_user_with_reassign_hands_no_rows_to_the_target(): void {
		self::insert_request( 'u5-open', 5 );
		self::insert_request( 'u6-open', 6 );
		$plugin = ( new \ReflectionClass( Plugin::class ) )->newInstanceWithoutConstructor();
		$plugin->boot();

		self::fire_delete_user( 5, 6 );

		$this->assertSame( [], self::selectors_of( 5 ) );
		$this->assertSame( [ 'u6-open' ], self::selectors_of( 6 ) );
	}

	public function test_delete_user_without_rows_changes_nothing(): void {
		global $wpdb;
		self::insert_request( 'u6-open', 6 );

		Installer::on_delete_user( 5 );

		$this->assertSame( '', $wpdb->last_error );
		$this->assertSame( [ 'u6-open' ], self::selectors_of( 6 ) );
	}

	public function test_delete_user_ignores_a_non_positive_id(): void {
		global $wpdb;
		self::insert_request( 'u0-row', 0 );
		$wpdb->query_log = [];

		Installer::on_delete_user( 0 );
		Installer::on_delete_user( -1 );

		$this->assertSame( [], $wpdb->query_log, 'no query at all' );
		$this->assertSame( [ 'u0-row' ], self::selectors_of( 0 ) );
	}

	/**
	 * Before the first migration the table can be missing: deleting a user
	 * must not print SQL into the users screen, and suppress_errors comes
	 * back to its old value.
	 */
	public function test_delete_user_before_the_table_exists_prints_nothing(): void {
		global $wpdb;
		$log = $this->capture_debug_log();
		self::drop_requests_table();
		foreach ( [ false, true ] as $previous ) {
			$wpdb->show_errors( true );
			$wpdb->suppress_errors( $previous );

			ob_start();
			Installer::on_delete_user( 5 );
			$out = (string) ob_get_clean();

			$this->assertSame( '', $out );
			$this->assertSame( $previous, $wpdb->suppress_errors, 'suppress_errors restored' );
			$this->assertSame( [], $wpdb->error_log, 'nothing sent to the PHP error log by wpdb' );
		}
		$wpdb->show_errors( false );
		$this->assertStringContainsString( '[magicauth] delete_user: requests cleanup failed', (string) file_get_contents( $log ) );
	}

	public function test_delete_user_query_error_is_logged_and_leaves_rows(): void {
		global $wpdb;
		$log = $this->capture_debug_log();
		self::insert_request( 'u5-open', 5 );
		$wpdb->fail_next_query( 'DELETE FROM ' . self::requests_table() );

		Installer::on_delete_user( 5 );

		$this->assertStringContainsString( 'delete_user: requests cleanup failed', (string) file_get_contents( $log ) );
		$this->assertSame( [ 'u5-open' ], self::selectors_of( 5 ) );
		$this->assertFalse( $wpdb->suppress_errors );
	}

	/** Multisite: delete_user fires when a user is removed from one site; only this site's table is touched. */
	public function test_delete_user_on_multisite_touches_this_sites_table_only(): void {
		global $wpdb, $magicauth_test_state;
		$other = 'wp_2_magicauth_requests';
		$wpdb->query( "CREATE TABLE {$other} AS SELECT * FROM " . self::requests_table() . ' WHERE 0' );
		self::insert_request( 'site1-u5', 5 );
		self::insert_request( 'site2-u5', 5, null, '2026-10-01 00:10:00', $other );
		$magicauth_test_state['multisite'] = true;
		$plugin = ( new \ReflectionClass( Plugin::class ) )->newInstanceWithoutConstructor();
		$plugin->boot();

		self::fire_delete_user( 5 );

		$this->assertSame( [], self::selectors_of( 5 ) );
		$this->assertSame( [ 'site2-u5' ], self::selectors_of( 5, $other ) );
		$wpdb->query( "DROP TABLE {$other}" );
	}

	/* --------------------------------------------------- uninstall.php (B9) */

	/** The 5.5 list: options, then meta below; the four tables in all_tables(). */
	private const UNINSTALL_OPTIONS = [
		'magicauth_settings',
		'magicauth_db_version',
		'magicauth_upgrade_lock',
		'magicauth_upgrade_retry',
		'magicauth_throttle_registry',
		'magicauth_salt_notice_dismissed',
	];

	private const UNINSTALL_META = [
		'magicauth_disabled',
		'magicauth_passkey_user_handle',
		'magicauth_passkey_prompt',
		'magicauth_passkey_details_at',
		'magicauth_passkey_details_sent',
		'magicauth_email_verified_at',
		'magicauth_email_changed_at',
	];

	/** Rows in wp_options the prefix match must remove (value and timeout rows of MagicAuth transients). */
	private const OWN_TRANSIENT_ROWS = [
		'_transient_magicauth_session_abc',
		'_transient_timeout_magicauth_session_abc',
		'_transient_magicauth_throttle_link_email_cd_ff',
		'_transient_timeout_magicauth_throttle_link_email_cd_ff',
		'_transient_magicauth_salt_notice',
		'_transient_timeout_magicauth_salt_notice',
	];

	/**
	 * Rows it must keep: '_' and '%' are LIKE wildcards, so an unescaped
	 * pattern would also take the first four.
	 */
	private const FOREIGN_OPTION_ROWS = [
		'_transient_magicauthXsession',
		'_transientXmagicauth_x',
		'_transient_timeout_magicauthX1',
		'_transient_timeoutXmagicauth_x',
		'_transient_other_plugin',
		'_site_transient_magicauth_x',
		'magicauth_unrelated_row',
		'xx_transient_magicauth_x',
	];

	/** @return array<int,string> */
	private static function option_rows(): array {
		global $wpdb;
		return $wpdb->get_col( "SELECT option_name FROM {$wpdb->options} ORDER BY option_name" );
	}

	private function seed_uninstall_data(): void {
		global $wpdb;
		foreach ( self::UNINSTALL_OPTIONS as $option ) {
			update_option( $option, 'x' );
		}
		update_option( 'blogname', 'Keep' );
		self::seed_lock( ( self::NOW - 5 ) . ':aaaaaaaaaaaaaaaa' ); // Raw row, as the upgrade lock writes it.
		foreach ( [ 3, 4 ] as $user_id ) {
			foreach ( self::UNINSTALL_META as $key ) {
				update_user_meta( $user_id, $key, '1' );
			}
			update_user_meta( $user_id, 'first_name', 'Keep' );
		}
		set_transient( 'magicauth_session_abc', [ 'e' => 1 ], 1800 );
		set_transient( 'magicauth_throttle_link_email_cd_ff', 1, 60 );
		set_transient( 'magicauth_salt_notice', 1, WEEK_IN_SECONDS );
		foreach ( self::FOREIGN_OPTION_ROWS as $name ) {
			$wpdb->query( $wpdb->prepare( "INSERT INTO {$wpdb->options} (option_name, option_value) VALUES (%s, 'keep')", $name ) );
		}
		$this->assertSame( self::OWN_TRANSIENT_ROWS, array_values( array_intersect( self::OWN_TRANSIENT_ROWS, self::option_rows() ) ), 'seeded' );
		self::insert_request( 'row', 3 );
		Installer::activate(); // Cron scheduled; table and rows kept.
		$this->assertNotNull( self::cron_event() );
		$wpdb->query_log = [];
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_uninstall_removes_the_5_5_list(): void {
		global $wpdb;
		$this->seed_uninstall_data();
		$wpdb->show_errors( true );

		define( 'WP_UNINSTALL_PLUGIN', 'magicauth/magicauth.php' );
		ob_start();
		require MAGICAUTH_DIR . 'uninstall.php';
		$out = (string) ob_get_clean();
		$wpdb->show_errors( false );

		$this->assertSame( '', $out, 'no database error' );
		$this->assertSame( [], $wpdb->error_log );
		foreach ( self::all_tables() as $table ) {
			$this->assertFalse( self::table_exists( $table ), "{$table} dropped" );
		}
		foreach ( self::UNINSTALL_OPTIONS as $option ) {
			$this->assertFalse( get_option( $option ), $option );
		}
		$this->assertNull( self::lock_row(), 'the raw lock row is gone too' );
		$this->assertSame( 'Keep', get_option( 'blogname' ) );
		foreach ( [ 3, 4 ] as $user_id ) {
			foreach ( self::UNINSTALL_META as $key ) {
				$this->assertSame( [], get_user_meta( $user_id, $key ), "{$key} of user {$user_id}" );
			}
			$this->assertSame( 'Keep', get_user_meta( $user_id, 'first_name', true ) );
		}

		$rows = self::option_rows();
		$this->assertSame( [], array_values( array_intersect( self::OWN_TRANSIENT_ROWS, $rows ) ), 'MagicAuth transients gone' );
		$this->assertSame( self::FOREIGN_OPTION_ROWS, array_values( array_intersect( self::FOREIGN_OPTION_ROWS, $rows ) ), 'wildcard look-alikes and other rows kept' );

		$like = array_values( array_filter( $wpdb->query_log, static fn( string $q ): bool => false !== stripos( $q, ' LIKE ' ) ) );
		$this->assertCount( 1, $like, 'one statement for both prefixes' );
		$bs = chr( 92 );
		// A real MySQL connection escapes the backslash once more inside the literal ('\\_'), which is the same pattern.
		$sql = str_replace( $bs . $bs, $bs, $like[0] );
		$this->assertStringContainsString( "'{$bs}_transient{$bs}_magicauth{$bs}_%'", $sql, 'esc_like() pattern' );
		$this->assertStringContainsString( "'{$bs}_transient{$bs}_timeout{$bs}_magicauth{$bs}_%'", $sql );

		$this->assertNull( self::cron_event(), 'cron cleared' );
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_uninstall_keeps_everything_with_magicauth_keep_data(): void {
		global $wpdb;
		$this->seed_uninstall_data();
		$before          = self::option_rows();
		$wpdb->query_log = [];

		define( 'WP_UNINSTALL_PLUGIN', 'magicauth/magicauth.php' );
		define( 'MAGICAUTH_KEEP_DATA', true );
		require MAGICAUTH_DIR . 'uninstall.php';

		$this->assertSame( [], $wpdb->query_log );
		foreach ( self::all_tables() as $table ) {
			$this->assertTrue( self::table_exists( $table ), $table );
		}
		$this->assertSame( [ 'row' ], self::selectors_of( 3 ) );
		$this->assertSame( $before, self::option_rows() );
		foreach ( self::UNINSTALL_OPTIONS as $option ) {
			$this->assertNotFalse( get_option( $option ), $option );
		}
		foreach ( self::UNINSTALL_META as $key ) {
			$this->assertSame( '1', get_user_meta( 3, $key, true ), $key );
		}
		$this->assertNotNull( self::cron_event() );
	}

	/** Loaded outside an uninstall it does nothing (fresh PHP process). */
	public function test_uninstall_exits_without_wp_uninstall_plugin(): void {
		$script = sprintf( 'require %s; echo "continued";', var_export( MAGICAUTH_DIR . 'uninstall.php', true ) );
		$out    = (string) shell_exec( escapeshellarg( PHP_BINARY ) . ' -n -r ' . escapeshellarg( $script ) . ' 2>&1' );
		$this->assertSame( '', $out );
	}

	/** WordPress runs uninstall.php without loading the plugin: no plugin class or helper may be used. */
	public function test_uninstall_uses_no_plugin_code(): void {
		$source = (string) file_get_contents( MAGICAUTH_DIR . 'uninstall.php' );
		$this->assertDoesNotMatchRegularExpression( '/MagicAuth\\\\|\bmagicauth_[a-z_]+\s*\(/i', $source );
	}

	/* -------------------------------------------------------- default settings */

	public function test_runtime_settings_defaults_are_the_installer_defaults(): void {
		$this->assertSame( Installer::default_settings(), magicauth_get_settings() );
	}

	public function test_saved_settings_merge_onto_installer_defaults(): void {
		update_option(
			'magicauth_settings',
			[
				'ttl_minutes' => 15,
				'throttle'    => [ 'per_ip_max' => 3 ],
			]
		);
		$expected                           = Installer::default_settings();
		$expected['ttl_minutes']            = 15;
		$expected['throttle']['per_ip_max'] = 3;

		$this->assertSame( $expected, magicauth_get_settings() );
	}

	public function test_non_array_saved_settings_fall_back_to_defaults(): void {
		update_option( 'magicauth_settings', 'corrupt' );
		$this->assertSame( Installer::default_settings(), magicauth_get_settings() );
	}

	/** One defaults array (4.7): helpers.php no longer carries its own copy. */
	public function test_helpers_has_no_duplicated_defaults_array(): void {
		$src = (string) file_get_contents( MAGICAUTH_DIR . 'includes/helpers.php' );
		$this->assertStringContainsString( 'Installer::default_settings()', $src );
		$this->assertStringNotContainsString( "'ttl_minutes'", $src );
		$this->assertStringNotContainsString( "'per_ip_password_reset_max'", $src );
	}

	/**
	 * The 1.0.5 defaults, value for value (moving the array changed nothing),
	 * plus the six passkey keys of SPEC 4.7 (build step 10).
	 */
	public function test_defaults_equal_the_1_0_5_values(): void {
		$this->assertSame(
			[
				'ttl_minutes'            => 10,
				'max_link_uses'          => 2,
				'throttle'               => [
					'per_email_cooldown_sec'           => 60,
					'per_ip_window_hours'              => 1,
					'per_ip_max'                       => 10,
					'per_ip_code_window_hours'         => 1,
					'per_ip_code_max'                  => 20,
					'per_ip_password_window_min'       => 15,
					'per_ip_password_max'              => 5,
					'per_ip_password_reset_window_min' => 60,
					'per_ip_password_reset_max'        => 5,
					'per_ip_passkey_window_min'        => 15,
					'per_ip_passkey_max'               => 30,
				],
				'replace_default'        => false,
				'company_name'           => '',
				'logo_attachment_id'     => 0,
				'brand_color'            => '#2271b1',
				'agency_credit_name'     => '',
				'agency_credit_url'      => '',
				'agency_credit_icon_id'  => 0,
				'agency_credit_label'    => '',
				'redirect_to_default'    => 'auto',
				'allow_password_login'   => true,
				'hide_language_switcher' => false,
				'from_email_local'       => 'login',
				'db_version'             => MAGICAUTH_DB_VERSION,
				'passkeys_enabled'             => false,
				'passkeys_prompt'              => true,
				'passkeys_manage_page_id'      => 0,
				'passkeys_email_reverify_days' => 0,
			],
			Installer::default_settings()
		);
	}

	/* ---------------------------------------------------------------- Clock */

	public function test_clock_follows_time_until_pinned_and_after_unpinning(): void {
		Clock::set_for_tests( null );
		$before = time();
		$now    = Clock::now();
		$this->assertGreaterThanOrEqual( $before, $now );
		$this->assertLessThanOrEqual( time(), $now );

		Clock::set_for_tests( 42 );
		$this->assertSame( 42, Clock::now() );

		Clock::set_for_tests( null );
		$this->assertGreaterThanOrEqual( $before, Clock::now() );
	}

	public function test_magicauth_test_reset_state_unpins_the_clock(): void {
		Clock::set_for_tests( 42 );
		magicauth_test_reset_state();
		$this->assertNotSame( 42, Clock::now() );
	}

	/** Outside MAGICAUTH_TESTING the override is a no-op (fresh PHP process, production constants only). */
	public function test_clock_override_is_ignored_outside_testing(): void {
		$script = sprintf(
			'define( "ABSPATH", "/" ); require %s; MagicAuth\Passkeys\Clock::set_for_tests( 42 ); echo MagicAuth\Passkeys\Clock::now() === 42 ? "pinned" : "time";',
			var_export( MAGICAUTH_DIR . 'includes/Passkeys/Clock.php', true )
		);
		$out = shell_exec( escapeshellarg( PHP_BINARY ) . ' -n -r ' . escapeshellarg( $script ) . ' 2>&1' );
		$this->assertSame( 'time', $out );
	}

	/* ------------------------------------------------------------ utilities */

	/** Route magicauth_debug_log() into a temp file for this test. */
	private function capture_debug_log(): string {
		$file              = (string) tempnam( sys_get_temp_dir(), 'magicauth-log' );
		$this->log_capture = [ $file, (string) ini_get( 'error_log' ) ];
		ini_set( 'error_log', $file ); // phpcs:ignore WordPress.PHP.IniSet.Risky
		add_filter( 'magicauth_debug_log', static fn() => true );
		return $file;
	}

	private function release_debug_log(): void {
		if ( null === $this->log_capture ) {
			return;
		}
		[ $file, $previous ] = $this->log_capture;
		ini_set( 'error_log', $previous ); // phpcs:ignore WordPress.PHP.IniSet.Risky
		if ( is_file( $file ) ) {
			unlink( $file );
		}
		$this->log_capture = null;
	}
}
