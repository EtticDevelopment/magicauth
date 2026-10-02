<?php
/**
 * T-SS (SPEC 5.6, 3.2, 14.1): per-session state rows. Ensure, then
 * single-column updates; nothing read or written without a session hash or
 * once the core record is gone; step-up stamp with its cookie; rule M clear;
 * purge. Runs with MySQL changed-rows semantics; part of the real-database
 * suite (group realdb).
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Passkeys\Clock;
use MagicAuth\Passkeys\Freshness;
use MagicAuth\Passkeys\SessionState;
use PHPUnit\Framework\TestCase;
use WP_Session_Tokens;

/**
 * @group realdb
 */
final class SessionStateTest extends TestCase {

	private const NOW = 1790000000;

	private const UID = 41;

	protected function setUp(): void {
		global $wpdb;
		magicauth_test_reset_state();
		$wpdb->mysql_changed_rows = true;
		Clock::set_for_tests( self::NOW );
		magicauth_test_register_user( self::UID, 'state@example.test' );
	}

	protected function tearDown(): void {
		magicauth_test_reset_state();
	}

	/** Signs in UID with a real core session record; returns the token. */
	private static function sign_in( int $uid = self::UID, int $expiration = self::NOW + 1209600 ): string {
		global $magicauth_test_state;
		magicauth_test_login_as( $uid );
		$token                                 = WP_Session_Tokens::get_instance( $uid )->create( $expiration );
		$magicauth_test_state['session_token'] = $token;
		return $token;
	}

	/** @return array<int,array<string,mixed>> */
	private static function rows(): array {
		global $wpdb;
		return $wpdb->get_results( 'SELECT * FROM ' . SessionState::table() . ' ORDER BY user_id, session_hash', ARRAY_A );
	}

	/** @return array<int,string> Logged statements against the sessions table. */
	private static function table_queries(): array {
		global $wpdb;
		return array_values( array_filter( $wpdb->query_log, static fn( string $q ): bool => false !== strpos( $q, SessionState::table() ) ) );
	}

	public function test_set_ensures_the_row_then_updates_one_column(): void {
		global $wpdb;
		self::sign_in( self::UID, self::NOW + 3600 );
		$wpdb->query_log = [];

		$this->assertTrue( SessionState::set( 'prompt_done', 1 ) );

		$q = self::table_queries();
		$this->assertCount( 2, $q );
		$this->assertStringContainsString( 'INSERT', $q[0] );
		$this->assertStringContainsString( 'IGNORE INTO ' . SessionState::table(), $q[0] );
		$this->assertMatchesRegularExpression( '/^UPDATE \S+ SET prompt_done = 1 WHERE session_hash = \'[0-9a-f]{64}\'$/', $q[1] );

		$rows = self::rows();
		$this->assertCount( 1, $rows );
		$this->assertSame( Freshness::session_hash(), $rows[0]['session_hash'] );
		$this->assertSame( (string) self::UID, (string) $rows[0]['user_id'] );
		$this->assertSame( gmdate( 'Y-m-d H:i:s', self::NOW + 3600 ), $rows[0]['expires_at'], 'the core record\'s expiration' );
		$this->assertSame( '1', (string) $rows[0]['prompt_done'] );

		$wpdb->query_log = [];
		$this->assertTrue( SessionState::set( 'signals_at', self::NOW ) );
		$q = self::table_queries();
		$this->assertCount( 2, $q );
		$this->assertMatchesRegularExpression( '/^UPDATE \S+ SET signals_at = ' . self::NOW . ' WHERE session_hash = /', $q[1], 'single column: no lost update of prompt_done' );

		$row = SessionState::get();
		$this->assertIsObject( $row );
		$this->assertSame( '1', (string) $row->prompt_done );
		$this->assertSame( (string) self::NOW, (string) $row->signals_at );
		$this->assertCount( 1, self::rows(), 'one row per session' );
	}

	/** Repeating the same value changes 0 rows on MySQL; that is still a success. */
	public function test_set_same_value_twice_succeeds(): void {
		self::sign_in();
		$this->assertTrue( SessionState::set( 'prompt_done', 1 ) );
		$this->assertTrue( SessionState::set( 'prompt_done', 1 ) );
	}

	public function test_set_refuses_other_columns_and_values(): void {
		global $wpdb;
		self::sign_in();
		$wpdb->query_log = [];
		$this->assertFalse( SessionState::set( 'reauth_at', self::NOW ) );
		$this->assertFalse( SessionState::set( 'fresh_hash', 1 ) );
		$this->assertFalse( SessionState::set( 'user_id', 2 ) );
		$this->assertFalse( SessionState::set( 'prompt_done', 2 ) );
		$this->assertFalse( SessionState::set( 'signals_at', -1 ) );
		$this->assertSame( [], self::table_queries() );
	}

	public function test_no_read_or_write_without_a_session_hash(): void {
		global $wpdb;
		magicauth_test_login_as( self::UID ); // Logged in, but no session token (e.g. application password).
		$wpdb->query_log = [];

		$this->assertFalse( SessionState::set( 'prompt_done', 1 ) );
		$this->assertFalse( SessionState::stamp_reauth( 'email_code' ) );
		$this->assertNull( SessionState::get() );
		$this->assertSame( [], self::table_queries() );
		$this->assertSame( [], self::rows() );
	}

	/** The core record was destroyed (Log Out Everywhere) between authentication and the write. */
	public function test_no_write_and_no_read_once_the_core_record_is_gone(): void {
		global $wpdb, $magicauth_test_state;
		$token = self::sign_in();
		$this->assertTrue( SessionState::set( 'prompt_done', 1 ) );
		$this->assertIsObject( SessionState::get() );

		WP_Session_Tokens::get_instance( self::UID )->destroy( $token );
		$wpdb->query_log = [];

		$this->assertNull( SessionState::get(), 'the row no longer counts' );
		$this->assertFalse( SessionState::set( 'signals_at', self::NOW ) );
		$this->assertFalse( SessionState::stamp_reauth( 'passkey' ) );
		$this->assertSame( [], self::table_queries(), 'no query: never re-created' );
		$this->assertSame( [], $magicauth_test_state['sessions'][ self::UID ], 'nothing written back to session_tokens' );
		$this->assertSame( [], $magicauth_test_state['cookies'] ?? [], 'no fresh cookie for a dead session' );

		$rows = self::rows();
		$this->assertCount( 1, $rows );
		$this->assertSame( '0', (string) $rows[0]['signals_at'], 'existing row not written' );
	}

	public function test_stamp_reauth_sets_the_three_columns_and_a_cookie(): void {
		global $magicauth_test_state;
		self::sign_in();
		$this->assertTrue( SessionState::set( 'prompt_done', 1 ) );

		$this->assertTrue( SessionState::stamp_reauth( 'email_code' ) );

		$cookies = $magicauth_test_state['cookies'] ?? [];
		$this->assertCount( 1, $cookies );
		$this->assertSame( Freshness::COOKIE, $cookies[0]['name'] );
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{64}$/', $cookies[0]['value'] );
		$this->assertTrue( $cookies[0]['httponly'] );
		$this->assertSame( 'Strict', $cookies[0]['samesite'] );

		$row = SessionState::get();
		$this->assertIsObject( $row );
		$this->assertSame( (string) self::NOW, (string) $row->reauth_at );
		$this->assertSame( 'email_code', $row->reauth_method );
		$this->assertSame( hash_hmac( 'sha256', 'magicauth-passkey-fresh|' . $cookies[0]['value'], wp_salt( 'auth' ) ), $row->fresh_hash, 'the HMAC of the cookie, never the cookie' );
		$this->assertSame( '1', (string) $row->prompt_done, 'other columns untouched' );

		Clock::set_for_tests( self::NOW + 30 );
		$this->assertTrue( SessionState::stamp_reauth( 'passkey' ) );
		$row = SessionState::get();
		$this->assertIsObject( $row );
		$this->assertSame( (string) ( self::NOW + 30 ), (string) $row->reauth_at );
		$this->assertSame( 'passkey', $row->reauth_method );
		$this->assertCount( 2, $magicauth_test_state['cookies'] );
		$this->assertNotSame( $cookies[0]['value'], $magicauth_test_state['cookies'][1]['value'], 'a new cookie value per step-up' );
	}

	public function test_stamp_reauth_refuses_other_methods(): void {
		global $magicauth_test_state;
		self::sign_in();
		foreach ( [ 'password', 'link', 'admin_link', '' ] as $method ) {
			$this->assertFalse( SessionState::stamp_reauth( $method ), $method );
		}
		$this->assertSame( [], $magicauth_test_state['cookies'] ?? [] );
		$this->assertSame( [], self::rows() );
	}

	public function test_failed_writes_report_false_and_print_nothing(): void {
		global $wpdb;
		self::sign_in();
		$wpdb->show_errors( true );
		ob_start();
		$wpdb->fail_next_query( 'IGNORE INTO ' . SessionState::table() );
		$insert = SessionState::set( 'prompt_done', 1 );
		$wpdb->fail_next_query( 'UPDATE ' . SessionState::table() );
		$update = SessionState::set( 'prompt_done', 1 );
		$wpdb->fail_next_query( 'UPDATE ' . SessionState::table() );
		$stamp = SessionState::stamp_reauth( 'passkey' );
		$wpdb->fail_next_query( 'SELECT * FROM ' . SessionState::table() );
		$read = SessionState::get();
		$out  = (string) ob_get_clean();
		$wpdb->show_errors( false );

		$this->assertFalse( $insert );
		$this->assertFalse( $update );
		$this->assertFalse( $stamp );
		$this->assertNull( $read );
		$this->assertSame( '', $out );
		$this->assertFalse( $wpdb->suppress_errors );
	}

	/** A stamp that is not stored sends no cookie: the browser keeps the fresh cookie it had. */
	public function test_failed_stamp_keeps_the_previous_fresh_cookie(): void {
		global $wpdb, $magicauth_test_state;
		self::sign_in();
		$this->assertTrue( SessionState::stamp_reauth( 'email_code' ) );
		$this->assertCount( 1, $magicauth_test_state['cookies'] );
		$first = $magicauth_test_state['cookies'][0]['value'];
		$hash  = hash_hmac( 'sha256', 'magicauth-passkey-fresh|' . $first, wp_salt( 'auth' ) );

		Clock::set_for_tests( self::NOW + 30 );
		$wpdb->fail_next_query( 'UPDATE ' . SessionState::table() );
		$this->assertFalse( SessionState::stamp_reauth( 'passkey' ), 'failed UPDATE' );

		$table = SessionState::table();
		$wpdb->before_next_query(
			'UPDATE ' . $table . ' SET reauth_at',
			static function () use ( $table ): void {
				global $wpdb;
				$wpdb->query( "DELETE FROM {$table}" );
			}
		);
		$this->assertFalse( SessionState::stamp_reauth( 'passkey' ), 'row gone between ensure and UPDATE: 0 rows' );

		$this->assertCount( 1, $magicauth_test_state['cookies'], 'no cookie for an unstored stamp' );
		$this->assertSame( $first, $magicauth_test_state['cookies'][0]['value'] );

		$this->assertTrue( SessionState::stamp_reauth( 'passkey' ), 'ensure re-creates the row' );
		$this->assertCount( 2, $magicauth_test_state['cookies'] );
		$row = SessionState::get();
		$this->assertIsObject( $row );
		$this->assertNotSame( $hash, $row->fresh_hash );
		$this->assertSame( hash_hmac( 'sha256', 'magicauth-passkey-fresh|' . $magicauth_test_state['cookies'][1]['value'], wp_salt( 'auth' ) ), $row->fresh_hash, 'cookie sent matches the stored HMAC' );
	}

	/** Rows are per session: another session of the same user has its own row, another user's token sees nothing of it. */
	public function test_rows_are_per_session(): void {
		global $magicauth_test_state;
		$first = self::sign_in();
		SessionState::set( 'prompt_done', 1 );
		self::sign_in();
		$this->assertNull( SessionState::get(), 'second session: no row yet' );
		SessionState::set( 'signals_at', 5 );
		$this->assertCount( 2, self::rows() );

		magicauth_test_register_user( 42, 'other@example.test' );
		magicauth_test_login_as( 42 );
		$magicauth_test_state['session_token'] = $first; // A foreign token is no session of user 42.
		$this->assertNull( SessionState::get() );
	}

	public function test_clear_reauth_for_user_clears_every_row_of_that_user_in_one_update(): void {
		global $wpdb;
		self::sign_in();
		SessionState::stamp_reauth( 'email_code' );
		SessionState::set( 'prompt_done', 1 );
		self::sign_in();
		SessionState::stamp_reauth( 'passkey' );
		magicauth_test_register_user( 42, 'other@example.test' );
		self::sign_in( 42 );
		SessionState::stamp_reauth( 'passkey' );
		$wpdb->query_log = [];

		$this->assertSame( 2, SessionState::clear_reauth_for_user( self::UID ) );

		$this->assertCount( 1, self::table_queries(), 'one UPDATE' );
		foreach ( self::rows() as $row ) {
			if ( (string) self::UID === (string) $row['user_id'] ) {
				$this->assertSame( '0', (string) $row['reauth_at'] );
				$this->assertSame( '', $row['reauth_method'] );
				$this->assertSame( '', $row['fresh_hash'] );
			} else {
				$this->assertSame( (string) self::NOW, (string) $row['reauth_at'], 'other users untouched' );
				$this->assertSame( 'passkey', $row['reauth_method'] );
			}
		}
		$this->assertContains( '1', array_map( static fn( $r ): string => (string) $r['prompt_done'], self::rows() ), 'prompt state kept' );
		$this->assertSame( 0, SessionState::clear_reauth_for_user( self::UID ), 'nothing left to clear' );
		$this->assertSame( 0, SessionState::clear_reauth_for_user( 0 ) );
	}

	public function test_delete_for_user(): void {
		self::sign_in();
		SessionState::set( 'prompt_done', 1 );
		magicauth_test_register_user( 42, 'other@example.test' );
		self::sign_in( 42 );
		SessionState::set( 'prompt_done', 1 );

		$this->assertSame( 1, SessionState::delete_for_user( self::UID ) );
		$this->assertSame( [ '42' ], array_map( static fn( $r ): string => (string) $r['user_id'], self::rows() ) );
		$this->assertSame( 0, SessionState::delete_for_user( 0 ) );
	}

	public function test_purge_removes_expired_rows_only(): void {
		global $wpdb;
		self::sign_in( self::UID, self::NOW + 100 );
		SessionState::set( 'prompt_done', 1 );
		self::sign_in( self::UID, self::NOW + 200 );
		SessionState::set( 'prompt_done', 1 );
		self::sign_in( self::UID, self::NOW + 300 );
		SessionState::set( 'prompt_done', 1 );

		Clock::set_for_tests( self::NOW + 200 );
		$wpdb->query_log = [];
		$this->assertSame( 1, SessionState::purge_expired( 5000 ), 'expires_at = now is not yet expired' );
		$log = self::table_queries();
		$this->assertStringStartsWith( 'SELECT session_hash FROM', $log[0] );
		$this->assertStringStartsWith( 'DELETE FROM ' . SessionState::table() . ' WHERE session_hash IN (', $log[1] );
		$this->assertCount( 2, self::rows() );

		Clock::set_for_tests( self::NOW + 1000 );
		$this->assertSame( 1, SessionState::purge_expired( 1 ), 'limit' );
		$this->assertSame( 1, SessionState::purge_expired( 1 ) );
		$this->assertSame( 0, SessionState::purge_expired( 1 ) );
	}
}
