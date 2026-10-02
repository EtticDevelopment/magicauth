<?php
/**
 * T-CS (SPEC 5.2, 7.5, 6.7, 14.1): challenge issue and atomic consume with
 * its reason, bindings, TTLs, step-up codes, purge. Runs with MySQL
 * changed-rows semantics; part of the real-database suite (group realdb).
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Passkeys\Base64Url;
use MagicAuth\Passkeys\ChallengeStore;
use MagicAuth\Passkeys\Clock;
use MagicAuth\Passkeys\Options;
use PHPUnit\Framework\TestCase;
use WP_Error;

/**
 * @group realdb
 */
final class ChallengeStoreTest extends TestCase {

	private const NOW = 1790000000;

	private const SESSION = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

	private const OTHER_SESSION = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

	private const COOKIE = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';

	protected function setUp(): void {
		global $wpdb;
		magicauth_test_reset_state();
		$wpdb->mysql_changed_rows = true;
		Clock::set_for_tests( self::NOW );
	}

	protected function tearDown(): void {
		magicauth_test_reset_state();
	}

	private static function rows(): int {
		global $wpdb;
		return (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . ChallengeStore::table() );
	}

	/** @return array<int,array<string,mixed>> */
	private static function all_rows(): array {
		global $wpdb;
		return $wpdb->get_results( 'SELECT * FROM ' . ChallengeStore::table() . ' ORDER BY id', ARRAY_A );
	}

	/** @return array<string,array{0:string,1:int,2:string,3:string,4:string,5:int,6:string}> */
	public static function ceremonies(): array {
		return [
			'signin'      => [ 'signin', 0, '', self::COOKIE, '', 600, '' ],
			'complete'    => [ 'complete', 7, '', self::COOKIE, '', 120, '' ],
			'register'    => [ 'register', 7, self::SESSION, '', '-7,-8,-257', 420, str_repeat( 'h', 86 ) ],
			'reauth'      => [ 'reauth', 7, self::SESSION, '', '', 420, '' ],
			'reauth_code' => [ 'reauth_code', 7, self::SESSION, '', '', 600, '' ],
		];
	}

	/* ------------------------------------------------------------ issue / consume */

	/** @dataProvider ceremonies */
	public function test_issue_then_consume_returns_the_row_once( string $ceremony, int $user_id, string $session, string $cookie, string $algs, int $ttl, string $handle ): void {
		$raw = ChallengeStore::issue( $ceremony, $user_id, $session, $cookie, $algs, $ttl, $handle );
		$this->assertIsString( $raw );
		$this->assertSame( 32, strlen( $raw ) );

		$reason = 'unset';
		$row    = ChallengeStore::consume( $ceremony, $raw, $reason );
		$this->assertIsObject( $row );
		$this->assertNull( $reason );
		$this->assertSame( $ceremony, $row->ceremony );
		$this->assertSame( (string) $user_id, (string) $row->user_id );
		$this->assertSame( $session, $row->session_hash );
		$this->assertSame( ChallengeStore::binding_hash( $cookie ), $row->binding_hash );
		$this->assertSame( $algs, $row->algs );
		$this->assertSame( $handle, $row->user_handle );
		$this->assertSame( gmdate( 'Y-m-d H:i:s', self::NOW ), $row->created_at );
		$this->assertSame( gmdate( 'Y-m-d H:i:s', self::NOW + $ttl ), $row->expires_at );
		$this->assertSame( gmdate( 'Y-m-d H:i:s', self::NOW ), $row->consumed_at );

		// One second later, inside the TTL: a replay must not match on an unchanged consumed_at.
		Clock::set_for_tests( self::NOW + 1 );
		$this->assertNull( ChallengeStore::consume( $ceremony, $raw, $reason ), 'single use' );
		$this->assertSame( 'replayed', $reason );
		$this->assertSame( gmdate( 'Y-m-d H:i:s', self::NOW ), self::all_rows()[0]['consumed_at'], 'first consume kept' );
	}

	public function test_plaintext_challenge_is_never_stored(): void {
		$raw = ChallengeStore::issue( 'signin', 0, '', self::COOKIE, '', 600 );
		$this->assertIsString( $raw );
		$row  = self::all_rows()[0];
		$dump = implode( '|', array_map( 'strval', $row ) );
		foreach ( [ $raw, bin2hex( $raw ), Base64Url::encode( $raw ), base64_encode( $raw ), self::COOKIE ] as $form ) {
			$this->assertStringNotContainsString( $form, $dump );
		}
		$this->assertSame( hash_hmac( 'sha256', 'magicauth-passkey|signin|' . $raw, wp_salt( 'auth' ) ), $row['lookup_hash'], 'ceremony inside the HMAC' );
		$this->assertSame( hash_hmac( 'sha256', 'magicauth-passkey-bind|' . self::COOKIE, wp_salt( 'auth' ) ), $row['binding_hash'] );
	}

	public function test_unknown_challenge_is_missing(): void {
		ChallengeStore::issue( 'signin', 0, '', self::COOKIE, '', 600 );
		$reason = null;
		$this->assertNull( ChallengeStore::consume( 'signin', random_bytes( 32 ), $reason ) );
		$this->assertSame( 'missing', $reason );
		$this->assertNull( ChallengeStore::consume( 'signin', '', $reason ) );
		$this->assertSame( 'missing', $reason );
	}

	/** A challenge issued for one ceremony is unusable for every other, and stays usable for its own. */
	public function test_other_ceremony_is_missing_and_does_not_burn_the_row(): void {
		$raw = ChallengeStore::issue( 'register', 7, self::SESSION, '', '-7', 420 );
		$this->assertIsString( $raw );
		foreach ( [ 'signin', 'complete', 'reauth', 'reauth_code', 'bogus' ] as $other ) {
			$reason = null;
			$this->assertNull( ChallengeStore::consume( $other, $raw, $reason ), $other );
			$this->assertSame( 'missing', $reason, $other );
		}
		$this->assertIsObject( ChallengeStore::consume( 'register', $raw ) );
	}

	public function test_expired_challenge_and_the_boundary(): void {
		$a = ChallengeStore::issue( 'signin', 0, '', self::COOKIE, '', 600 );
		$b = ChallengeStore::issue( 'signin', 0, '', self::COOKIE, '', 600 );
		$c = ChallengeStore::issue( 'signin', 0, '', self::COOKIE, '', 600 );
		$this->assertIsString( $a );
		$this->assertIsString( $b );
		$this->assertIsString( $c );

		Clock::set_for_tests( self::NOW + 599 );
		$this->assertIsObject( ChallengeStore::consume( 'signin', $a ), 'one second before expiry' );

		Clock::set_for_tests( self::NOW + 600 );
		$reason = null;
		$this->assertNull( ChallengeStore::consume( 'signin', $b, $reason ), 'expires_at = now fails' );
		$this->assertSame( 'expired', $reason );

		Clock::set_for_tests( self::NOW + 4000 );
		$this->assertNull( ChallengeStore::consume( 'signin', $c, $reason ) );
		$this->assertSame( 'expired', $reason );
	}

	public function test_consumed_and_expired_row_is_replayed(): void {
		$raw = ChallengeStore::issue( 'signin', 0, '', self::COOKIE, '', 600 );
		$this->assertIsString( $raw );
		ChallengeStore::consume( 'signin', $raw );
		Clock::set_for_tests( self::NOW + 900 );
		$reason = null;
		$this->assertNull( ChallengeStore::consume( 'signin', $raw, $reason ) );
		$this->assertSame( 'replayed', $reason, 'an earlier request consumed it' );
	}

	public function test_query_error_on_the_select_is_error_and_prints_nothing(): void {
		global $wpdb;
		$raw = ChallengeStore::issue( 'signin', 0, '', self::COOKIE, '', 600 );
		$this->assertIsString( $raw );
		$wpdb->show_errors( true );
		$wpdb->fail_next_query( 'SELECT * FROM ' . ChallengeStore::table() );

		ob_start();
		$reason = null;
		$row    = ChallengeStore::consume( 'signin', $raw, $reason );
		$out    = (string) ob_get_clean();
		$wpdb->show_errors( false );

		$this->assertNull( $row );
		$this->assertSame( 'error', $reason, 'a failed query is never "missing"' );
		$this->assertSame( '', $out );
		$this->assertFalse( $wpdb->suppress_errors, 'suppress_errors restored' );
		$this->assertIsObject( ChallengeStore::consume( 'signin', $raw ), 'row untouched' );
	}

	public function test_query_error_on_the_update_is_error(): void {
		global $wpdb;
		$raw = ChallengeStore::issue( 'register', 7, self::SESSION, '', '-7', 420 );
		$this->assertIsString( $raw );
		$wpdb->fail_next_query( 'UPDATE ' . ChallengeStore::table() );

		$reason = null;
		$this->assertNull( ChallengeStore::consume( 'register', $raw, $reason ) );
		$this->assertSame( 'error', $reason );
	}

	/** consumed() (7.3 condition 1): read-only tri-state, never burns the row. */
	public function test_consumed_reads_without_consuming(): void {
		global $wpdb;
		$raw = ChallengeStore::issue( 'register', 7, self::SESSION, '', '-7', 420 );
		$this->assertIsString( $raw );
		$this->assertFalse( ChallengeStore::consumed( 'register', $raw ), 'unconsumed' );
		$this->assertFalse( ChallengeStore::consumed( 'register', random_bytes( 32 ) ), 'no row' );
		$this->assertFalse( ChallengeStore::consumed( 'signin', $raw ), 'other ceremony: no row' );
		$this->assertFalse( ChallengeStore::consumed( 'bogus', $raw ) );
		$this->assertFalse( ChallengeStore::consumed( 'register', '' ) );

		$wpdb->show_errors( true );
		$wpdb->fail_next_query( 'SELECT * FROM ' . ChallengeStore::table() );
		ob_start();
		$error = ChallengeStore::consumed( 'register', $raw );
		$out   = (string) ob_get_clean();
		$wpdb->show_errors( false );
		$this->assertInstanceOf( WP_Error::class, $error, 'a failed query is never "not consumed"' );
		$this->assertSame( '', $out );
		$this->assertFalse( $wpdb->suppress_errors, 'suppress_errors restored' );

		$this->assertIsObject( ChallengeStore::consume( 'register', $raw ), 'still consumable' );
		$this->assertTrue( ChallengeStore::consumed( 'register', $raw ) );
		Clock::set_for_tests( self::NOW + 900 );
		$this->assertTrue( ChallengeStore::consumed( 'register', $raw ), 'consumed and expired' );
	}

	/** Two requests consume the same challenge: exactly one gets the row, the loser sees "replayed". */
	public function test_concurrent_consume_gives_exactly_one_row(): void {
		global $wpdb;
		$raw = ChallengeStore::issue( 'register', 7, self::SESSION, '', '-7', 420 );
		$this->assertIsString( $raw );
		$inner = [];
		$wpdb->before_next_query(
			'UPDATE ' . ChallengeStore::table() . ' SET consumed_at',
			static function () use ( $raw, &$inner ): void {
				// The winner writes a different consumed_at, so the loser's UPDATE would change the row without its guard.
				Clock::set_for_tests( self::NOW + 1 );
				$reason  = null;
				$row     = ChallengeStore::consume( 'register', $raw, $reason );
				$inner[] = [ $row, $reason ];
			}
		);

		$reason = null;
		$outer  = ChallengeStore::consume( 'register', $raw, $reason );

		$this->assertCount( 1, $inner );
		$this->assertIsObject( $inner[0][0], 'the request that got there first wins' );
		$this->assertNull( $outer );
		$this->assertSame( 'replayed', $reason, 'read unconsumed, lost the UPDATE while unexpired' );
		$this->assertSame( gmdate( 'Y-m-d H:i:s', self::NOW + 1 ), self::all_rows()[0]['consumed_at'], 'winner\'s consume kept' );
	}

	/** @return array<string,array{0:string,1:int,2:string,3:string}> */
	public static function refused(): array {
		return [
			'register without session'    => [ 'register', 7, '', '' ],
			'register without user'       => [ 'register', 0, self::SESSION, '' ],
			'reauth without session'      => [ 'reauth', 7, '', '' ],
			'reauth without user'         => [ 'reauth', 0, self::SESSION, '' ],
			'reauth_code without session' => [ 'reauth_code', 7, '', '' ],
			'reauth_code without user'    => [ 'reauth_code', 0, self::SESSION, '' ],
			'signin without binding'      => [ 'signin', 0, '', '' ],
			'complete without binding'    => [ 'complete', 7, '', '' ],
			'complete without user'       => [ 'complete', 0, '', self::COOKIE ],
			'unknown ceremony'            => [ 'login', 7, self::SESSION, self::COOKIE ],
			'negative user'               => [ 'signin', -1, '', self::COOKIE ],
		];
	}

	/** @dataProvider refused */
	public function test_issue_is_refused_without_its_binding( string $ceremony, int $user_id, string $session, string $cookie ): void {
		$result = ChallengeStore::issue( $ceremony, $user_id, $session, $cookie, '', 420 );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'magicauth_challenge_refused', $result->get_error_code() );
		$this->assertSame( 0, self::rows(), 'no row' );
	}

	public function test_issue_code_is_refused_without_session_or_user(): void {
		$this->assertInstanceOf( WP_Error::class, ChallengeStore::issue_code( 7, '' ) );
		$this->assertInstanceOf( WP_Error::class, ChallengeStore::issue_code( 0, self::SESSION ) );
		$this->assertSame( 0, self::rows() );
	}

	public function test_issue_insert_failure_is_unavailable_and_prints_nothing(): void {
		global $wpdb;
		$wpdb->show_errors( true );
		$wpdb->fail_next_query( 'INSERT INTO ' . ChallengeStore::table() );

		ob_start();
		$result = ChallengeStore::issue( 'signin', 0, '', self::COOKIE, '', 600 );
		$out    = (string) ob_get_clean();
		$wpdb->show_errors( false );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'magicauth_unavailable', $result->get_error_code() );
		$this->assertSame( '', $out );
		$this->assertSame( [], $wpdb->error_log );
	}

	public function test_binding_comparison_fails_when_either_side_is_empty(): void {
		$this->assertFalse( ChallengeStore::binding_matches( '', '' ) );
		$this->assertFalse( ChallengeStore::binding_matches( self::SESSION, '' ) );
		$this->assertFalse( ChallengeStore::binding_matches( '', self::SESSION ) );
		$this->assertFalse( ChallengeStore::binding_matches( self::SESSION, self::OTHER_SESSION ) );
		$this->assertTrue( ChallengeStore::binding_matches( self::SESSION, self::SESSION ) );
		$this->assertSame( '', ChallengeStore::binding_hash( '' ) );
		$this->assertNotSame( ChallengeStore::binding_hash( self::COOKIE ), ChallengeStore::binding_hash( self::SESSION ) );
	}

	/**
	 * TTL invariant (5.2, invariant 9): every browser ceremony's challenge
	 * lives at least its options timeout (Options::TIMEOUT_MS, 7.2) plus 60 s.
	 */
	public function test_ttl_invariant_for_the_browser_ceremonies(): void {
		$timeout_s = intdiv( Options::TIMEOUT_MS, 1000 );
		$this->assertSame( 300, $timeout_s );
		foreach ( [ 'signin', 'register', 'reauth' ] as $ceremony ) {
			$this->assertGreaterThanOrEqual( $timeout_s + 60, ChallengeStore::TTL[ $ceremony ], $ceremony );
		}
		$this->assertSame( [ 'signin' => 600, 'complete' => 120, 'register' => 420, 'reauth' => 420, 'reauth_code' => 600 ], ChallengeStore::TTL );
		$this->assertSame( ChallengeStore::CEREMONIES, array_keys( ChallengeStore::TTL ) );
		// The binding cookie (Max-Age 720, 5.3) outlives every cookie-bound row.
		$this->assertLessThan( 720, ChallengeStore::TTL['signin'] );
		$this->assertLessThan( 720, ChallengeStore::TTL['complete'] );
	}

	public function test_register_row_stores_the_handle_sent_in_the_options(): void {
		$handle = Base64Url::encode( random_bytes( 64 ) );
		$raw    = ChallengeStore::issue( 'register', 7, self::SESSION, '', '-7,-257', 420, $handle );
		$this->assertIsString( $raw );
		$row = ChallengeStore::consume( 'register', $raw );
		$this->assertIsObject( $row );
		$this->assertSame( $handle, $row->user_handle );
		$this->assertSame( '-7,-257', $row->algs );
	}

	/* ------------------------------------------------------------- step-up code */

	public function test_code_verifies_once(): void {
		$issued = ChallengeStore::issue_code( 7, self::SESSION );
		$this->assertIsArray( $issued );
		[ $id, $code ] = $issued;
		$this->assertSame( 16, strlen( $id ) );
		$this->assertMatchesRegularExpression( '/^[0-9A-HJKMNP-TV-Z]{6}$/', $code );
		$row = self::all_rows()[0];
		$this->assertSame( 'reauth_code', $row['ceremony'] );
		$this->assertSame( gmdate( 'Y-m-d H:i:s', self::NOW + 600 ), $row['expires_at'] );
		$this->assertStringNotContainsString( $code, implode( '|', array_map( 'strval', $row ) ), 'code stored only as an HMAC' );

		$this->assertTrue( ChallengeStore::verify_code( $id, $code, 7, self::SESSION ) );
		Clock::set_for_tests( self::NOW + 1 );
		$this->assertFalse( ChallengeStore::verify_code( $id, $code, 7, self::SESSION ), 'consumed' );
		$this->assertSame( '1', (string) self::all_rows()[0]['attempts'], 'a consumed row is not charged' );
		$this->assertSame( gmdate( 'Y-m-d H:i:s', self::NOW ), self::all_rows()[0]['consumed_at'], 'first consume kept' );
	}

	/** Two submissions of the right code pass the charge together: exactly one consumes the row. */
	public function test_concurrent_code_verify_gives_exactly_one_success(): void {
		global $wpdb;
		[ $id, $code ] = ChallengeStore::issue_code( 7, self::SESSION );
		$inner         = [];
		$wpdb->before_next_query(
			'UPDATE ' . ChallengeStore::table() . ' SET consumed_at',
			static function () use ( $id, $code, &$inner ): void {
				Clock::set_for_tests( self::NOW + 1 );
				$inner[] = ChallengeStore::verify_code( $id, $code, 7, self::SESSION );
			}
		);

		$outer = ChallengeStore::verify_code( $id, $code, 7, self::SESSION );

		$this->assertSame( [ true ], $inner, 'the request that got there first wins' );
		$this->assertFalse( $outer );
		$row = self::all_rows()[0];
		$this->assertSame( '2', (string) $row['attempts'] );
		$this->assertSame( gmdate( 'Y-m-d H:i:s', self::NOW + 1 ), $row['consumed_at'], 'winner\'s consume kept' );
	}

	public function test_code_is_normalised_like_the_login_code(): void {
		[ $id, $code ] = ChallengeStore::issue_code( 7, self::SESSION );
		$typed = strtolower( substr( $code, 0, 3 ) . '-' . substr( $code, 3 ) );
		$this->assertTrue( ChallengeStore::verify_code( $id, $typed, 7, self::SESSION ) );
	}

	public function test_code_attempts_are_capped_at_five(): void {
		[ $id, $code ] = ChallengeStore::issue_code( 7, self::SESSION );
		$wrong         = '0000' === substr( $code, 0, 4 ) ? '111111' : '000000';
		for ( $i = 0; $i < 5; $i++ ) {
			$this->assertFalse( ChallengeStore::verify_code( $id, $wrong, 7, self::SESSION ) );
		}
		$this->assertSame( '5', (string) self::all_rows()[0]['attempts'] );
		$this->assertFalse( ChallengeStore::verify_code( $id, $code, 7, self::SESSION ), 'the right code after five misses' );
		$this->assertSame( '5', (string) self::all_rows()[0]['attempts'], 'never charged past the cap' );
	}

	public function test_code_succeeds_on_the_fifth_attempt(): void {
		[ $id, $code ] = ChallengeStore::issue_code( 7, self::SESSION );
		$wrong         = '0000' === substr( $code, 0, 4 ) ? '111111' : '000000';
		for ( $i = 0; $i < 4; $i++ ) {
			$this->assertFalse( ChallengeStore::verify_code( $id, $wrong, 7, self::SESSION ) );
		}
		$this->assertTrue( ChallengeStore::verify_code( $id, $code, 7, self::SESSION ) );
	}

	public function test_code_from_another_session_or_user_fails_without_charging(): void {
		[ $id, $code ] = ChallengeStore::issue_code( 7, self::SESSION );
		$this->assertFalse( ChallengeStore::verify_code( $id, $code, 7, self::OTHER_SESSION ) );
		$this->assertFalse( ChallengeStore::verify_code( $id, $code, 8, self::SESSION ) );
		$this->assertFalse( ChallengeStore::verify_code( $id, $code, 7, '' ) );
		$this->assertFalse( ChallengeStore::verify_code( $id, $code, 0, self::SESSION ) );
		$this->assertFalse( ChallengeStore::verify_code( random_bytes( 16 ), $code, 7, self::SESSION ) );
		$this->assertSame( '0', (string) self::all_rows()[0]['attempts'] );
		$this->assertTrue( ChallengeStore::verify_code( $id, $code, 7, self::SESSION ), 'still usable by its owner' );
	}

	public function test_expired_code_fails(): void {
		[ $id, $code ] = ChallengeStore::issue_code( 7, self::SESSION );
		Clock::set_for_tests( self::NOW + 600 );
		$this->assertFalse( ChallengeStore::verify_code( $id, $code, 7, self::SESSION ) );
	}

	/** A code row is never consumable as a passkey challenge, and a challenge never verifies as a code. */
	public function test_code_and_challenge_do_not_cross(): void {
		[ $id, $code ] = ChallengeStore::issue_code( 7, self::SESSION );
		$reason        = null;
		$this->assertNull( ChallengeStore::consume( 'reauth', $id, $reason ) );
		$this->assertSame( 'missing', $reason );

		$raw = ChallengeStore::issue( 'reauth', 7, self::SESSION, '', '', 420 );
		$this->assertIsString( $raw );
		$this->assertFalse( ChallengeStore::verify_code( $raw, $code, 7, self::SESSION ) );
		$this->assertTrue( ChallengeStore::verify_code( $id, $code, 7, self::SESSION ) );
	}

	/** K4: a query error is a WP_Error (503 retry), never true and never a wrong code. */
	public function test_code_query_error_fails_closed_as_an_error(): void {
		global $wpdb;
		[ $id, $code ] = ChallengeStore::issue_code( 7, self::SESSION );
		foreach ( [ 'UPDATE ' . ChallengeStore::table() . ' SET attempts', 'SELECT * FROM ' . ChallengeStore::table(), 'UPDATE ' . ChallengeStore::table() . ' SET consumed_at' ] as $pattern ) {
			$wpdb->fail_next_query( $pattern );
			$issued = 1;
			$result = ChallengeStore::verify_code( $id, $code, 7, self::SESSION, $issued );
			$this->assertInstanceOf( WP_Error::class, $result, $pattern );
			$this->assertSame( 0, $issued, $pattern );
		}
		$this->assertTrue( ChallengeStore::verify_code( $id, $code, 7, self::SESSION ), 'the code still works after the errors' );
		$this->assertFalse( ChallengeStore::verify_code( $id, $code, 7, self::SESSION ), 'consumed: a refusal, not an error' );
	}

	/* --------------------------------------------------------------- cleanup */

	public function test_purge_selects_then_deletes_only_expired_rows(): void {
		global $wpdb;
		ChallengeStore::issue( 'complete', 7, '', self::COOKIE, '', 120 );   // Expires NOW+120.
		ChallengeStore::issue( 'register', 7, self::SESSION, '', '-7', 420 ); // NOW+420.
		ChallengeStore::issue( 'signin', 0, '', self::COOKIE, '', 600 );      // NOW+600.
		Clock::set_for_tests( self::NOW + 500 );
		$wpdb->query_log = [];

		$this->assertSame( 2, ChallengeStore::purge_expired( 20 ) );
		$log = $wpdb->query_log;

		$this->assertSame( [ 'signin' ], array_column( self::all_rows(), 'ceremony' ) );
		$this->assertCount( 2, $log );
		$this->assertMatchesRegularExpression( '/^SELECT id FROM \S+ WHERE expires_at < \S+ \S+ ORDER BY expires_at LIMIT 20$/', $log[0] );
		$this->assertStringStartsWith( 'DELETE FROM ' . ChallengeStore::table() . ' WHERE id IN (', $log[1] );
		$this->assertStringNotContainsString( 'LIMIT', $log[1], 'no DELETE ... LIMIT (SQLite rejects it)' );
	}

	public function test_purge_respects_limit_and_grace(): void {
		for ( $i = 0; $i < 5; $i++ ) {
			ChallengeStore::issue( 'signin', 0, '', self::COOKIE, '', 600 );
		}
		Clock::set_for_tests( self::NOW + 600 + 3599 );
		$this->assertSame( 0, ChallengeStore::purge_expired( 5000, HOUR_IN_SECONDS ), 'expired less than an hour ago: kept by the daily purge' );
		Clock::set_for_tests( self::NOW + 600 + 3601 );
		$this->assertSame( 3, ChallengeStore::purge_expired( 3, HOUR_IN_SECONDS ) );
		$this->assertSame( 2, self::rows() );
		$this->assertSame( 2, ChallengeStore::purge_expired( 3 ) );
		$this->assertSame( 0, ChallengeStore::purge_expired( 3 ) );
	}

	public function test_delete_for_user_removes_every_ceremony_of_that_user_only(): void {
		ChallengeStore::issue( 'register', 7, self::SESSION, '', '-7', 420 );
		ChallengeStore::issue( 'reauth', 7, self::SESSION, '', '', 420 );
		ChallengeStore::issue_code( 7, self::SESSION );
		ChallengeStore::issue( 'complete', 7, '', self::COOKIE, '', 120 );
		ChallengeStore::issue( 'register', 8, self::OTHER_SESSION, '', '-7', 420 );
		ChallengeStore::issue( 'signin', 0, '', self::COOKIE, '', 600 );

		$this->assertSame( 4, ChallengeStore::delete_for_user( 7 ) );
		$this->assertSame( [ 'register', 'signin' ], array_column( self::all_rows(), 'ceremony' ) );
		$this->assertSame( 0, ChallengeStore::delete_for_user( 0 ), 'never the anonymous signin rows' );
		$this->assertSame( 2, self::rows() );
	}
}
