<?php
/**
 * Self-test of the passkey test harness (SPEC 15 step 1, 14.1): CBOR encoder,
 * SoftAuthenticator (ES256, RS256, EdDSA verified with plain openssl/sodium),
 * the W3C L3 vectors, the SQLite wpdb's MySQL emulation (rewrites, changed
 * rows, error injection, print_error), the dbDelta fake, core-accurate stubs,
 * and the 1.0.5 golden fixtures.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Installer;
use MagicAuth\Tests\Stubs\JsonResponseSent;
use MagicAuth\Tests\Stubs\RedirectSent;
use MagicAuth\Tests\Support\Bytes;
use MagicAuth\Tests\Support\Cbor;
use MagicAuth\Tests\Support\Fixtures;
use MagicAuth\Tests\Support\Golden;
use MagicAuth\Tests\Support\Normalise;
use MagicAuth\Tests\Support\SoftAuthenticator;
use PHPUnit\Framework\TestCase;
use WP_Error;
use WP_Session_Tokens;

final class SupportSelfTest extends TestCase {

	private const SCRATCH = 'wp_magicauth_selftest';

	private const SOURCE_COMMIT = 'd8c8d7de18a6659f351455d77b69c51240fad6ac';

	/**
	 * Fixture files whose expected difference from 1.0.5 a later step owns
	 * (SPEC G6, Appendix D). Each entry names the step; that step's own test
	 * (T-OFF-1, T-MAIL-2) checks the file instead.
	 */
	private const KNOWN_CHANGES = [
		'login-form-a.html'         => 'step 4, B5: ModuleOffTest (T-OFF-1)',
		'shortcode-logged-out.html' => 'step 4, B5: ModuleOffTest (T-OFF-1)',
	];

	protected function setUp(): void {
		global $wpdb;
		magicauth_test_reset_state();
		$wpdb->query( 'DROP TABLE IF EXISTS ' . self::SCRATCH );
		$wpdb->query( 'CREATE TABLE ' . self::SCRATCH . ' (id INTEGER PRIMARY KEY AUTOINCREMENT, k TEXT UNIQUE, v TEXT, consumed_at TEXT DEFAULT NULL)' );
		$wpdb->query_log = [];
	}

	protected function tearDown(): void {
		global $wpdb;
		$wpdb->query( 'DROP TABLE IF EXISTS ' . self::SCRATCH );
		// Tests below drop or alter the requests table; restore the harness DDL.
		$wpdb->install_magicauth_schema();
		unset( $_REQUEST['_ajax_nonce'], $_REQUEST['_wpnonce'] );
		magicauth_test_reset_state();
	}

	/* ---------------------------------------------------------------- CBOR */

	/** @return array<string,array{0:mixed,1:string}> RFC 8949 Appendix A. */
	public static function rfc8949_vectors(): array {
		return [
			'0'                 => [ 0, '00' ],
			'1'                 => [ 1, '01' ],
			'10'                => [ 10, '0a' ],
			'23'                => [ 23, '17' ],
			'24'                => [ 24, '1818' ],
			'25'                => [ 25, '1819' ],
			'100'               => [ 100, '1864' ],
			'1000'              => [ 1000, '1903e8' ],
			'1000000'           => [ 1000000, '1a000f4240' ],
			'1000000000000'     => [ 1000000000000, '1b000000e8d4a51000' ],
			'-1'                => [ -1, '20' ],
			'-10'               => [ -10, '29' ],
			'-100'              => [ -100, '3863' ],
			'-1000'             => [ -1000, '3903e7' ],
			'h""'               => [ Cbor::bytes( '' ), '40' ],
			'h01020304'         => [ Cbor::bytes( "\x01\x02\x03\x04" ), '4401020304' ],
			'""'                => [ '', '60' ],
			'"a"'               => [ 'a', '6161' ],
			'"IETF"'            => [ 'IETF', '6449455446' ],
			'"ü"'              => [ "\u{00fc}", '62c3bc' ],
			'[]'                => [ [], '80' ],
			'[1,2,3]'           => [ [ 1, 2, 3 ], '83010203' ],
			'[1,[2,3],[4,5]]'   => [ [ 1, [ 2, 3 ], [ 4, 5 ] ], '8301820203820405' ],
			'{}'                => [ Cbor::map( [] ), 'a0' ],
			'{1:2,3:4}'         => [ [ 1 => 2, 3 => 4 ], 'a201020304' ],
			'{"a":1,"b":[2,3]}' => [ [ 'a' => 1, 'b' => [ 2, 3 ] ], 'a26161016162820203' ],
			'true'              => [ true, 'f5' ],
			'false'             => [ false, 'f4' ],
			'null'              => [ null, 'f6' ],
		];
	}

	/**
	 * @dataProvider rfc8949_vectors
	 * @param mixed $value
	 */
	public function test_cbor_encodes_rfc8949_appendix_a_vectors( $value, string $hex ): void {
		$this->assertSame( $hex, bin2hex( Cbor::encode( $value ) ) );
	}

	public function test_cbor_sorts_map_keys_ctap2_canonically(): void {
		$cose = Cbor::encode(
			[
				-3 => Cbor::bytes( 'y' ),
				-2 => Cbor::bytes( 'x' ),
				-1 => 1,
				3  => -7,
				1  => 2,
			]
		);
		// 1, 3 (major 0) before -1, -2, -3 (major 1), each by encoded bytes.
		$this->assertSame( 'a5' . '0102' . '0326' . '2001' . '214178' . '224179', bin2hex( $cose ) );

		$att = Cbor::encode(
			[
				'authData' => Cbor::bytes( '' ),
				'fmt'      => 'none',
				'attStmt'  => Cbor::map( [] ),
			]
		);
		$this->assertSame( 'a3' . '63666d74646e6f6e65' . '6761747453746d74a0' . '6861757468446174614' . '0', bin2hex( $att ) );

		// Ints sort before text keys; shorter encodings before longer ones.
		$this->assertSame( 'a3' . '1864' . '01' . '19012c' . '02' . '6161' . '03', bin2hex( Cbor::encode( [ 'a' => 3, 300 => 2, 100 => 1 ] ) ) );
	}

	public function test_cbor_helpers_and_decoder(): void {
		$this->assertSame( "\x81\x81\x81\x80", Cbor::nested_array( 3 ) );
		$this->assertSame( [ [ [ [] ] ] ], Cbor::decode( Cbor::nested_array( 3 ) ) );
		$this->assertSame( "\xa2\x01\x02\x01\x02", Cbor::map_with_duplicate_key() );
		$this->assertSame( "\x81\xf5", Cbor::encode( [ Cbor::raw( "\xf5" ) ] ) );

		$decoded = Cbor::decode( Cbor::encode( [ 1 => Cbor::bytes( "\x00\xff" ), 'k' => [ true, null, -300 ] ] ) );
		$this->assertInstanceOf( Bytes::class, $decoded[1] );
		$this->assertSame( "\x00\xff", $decoded[1]->data );
		$this->assertSame( [ true, null, -300 ], $decoded['k'] );

		$this->expectException( \UnexpectedValueException::class );
		Cbor::decode( "\x01\x02" );
	}

	/* ---------------------------------------------------- SoftAuthenticator */

	/** @return array<string,array{0:string}> */
	public static function algs(): array {
		return [
			'ES256' => [ 'ES256' ],
			'RS256' => [ 'RS256' ],
			'EdDSA' => [ 'EdDSA' ],
		];
	}

	/** @dataProvider algs */
	public function test_soft_authenticator_signs_and_verifies_with_openssl_or_sodium( string $alg ): void {
		$auth    = new SoftAuthenticator( $alg );
		$handle  = random_bytes( 32 );
		$options = self::creation_options( $handle );

		$reg = $auth->register( $options, 'https://example.test' );
		$this->assertSame( 'public-key', $reg['type'] );
		$this->assertSame( SoftAuthenticator::b64url( $auth->credentialId() ), $reg['id'] );
		$this->assertSame( $reg['id'], $reg['rawId'] );

		$client = json_decode( SoftAuthenticator::b64url_decode( $reg['response']['clientDataJSON'] ), true );
		$this->assertSame(
			[
				'type'        => 'webauthn.create',
				'challenge'   => $options['challenge'],
				'origin'      => 'https://example.test',
				'crossOrigin' => false,
			],
			$client
		);

		$att = Cbor::decode( SoftAuthenticator::b64url_decode( $reg['response']['attestationObject'] ) );
		$this->assertSame( 'none', $att['fmt'] );
		$this->assertSame( [], $att['attStmt'] );
		$parsed = self::parse_auth_data( $att['authData']->data );
		$this->assertSame( hash( 'sha256', 'example.test', true ), $parsed['rp_id_hash'] );
		$expected_flags = SoftAuthenticator::FLAG_UP | SoftAuthenticator::FLAG_UV | SoftAuthenticator::FLAG_BE | SoftAuthenticator::FLAG_BS | SoftAuthenticator::FLAG_AT;
		$this->assertSame( $expected_flags, $parsed['flags'] );
		$this->assertSame( 0, $parsed['sign_count'] );
		$this->assertSame( str_repeat( "\0", 16 ), $parsed['aaguid'] );
		$this->assertSame( $auth->credentialId(), $parsed['credential_id'] );
		$this->assertSame( '', $parsed['rest'], 'no bytes after the COSE key' );
		$this->assertSame( $auth->coseAlg(), $parsed['cose'][3] );

		// The COSE key alone, re-encoded as SPKI, must equal the key the authenticator signs with.
		$spki = self::spki_from_cose( $parsed['cose'] );
		$this->assertSame( SoftAuthenticator::b64url( $spki ), $reg['response']['publicKey'] );

		$assertion = $auth->assert(
			[
				'challenge' => SoftAuthenticator::b64url( random_bytes( 32 ) ),
				'rpId'      => 'example.test',
			],
			'https://example.test'
		);
		$this->assertSame( SoftAuthenticator::b64url( $handle ), $assertion['response']['userHandle'] );
		$auth_data = SoftAuthenticator::b64url_decode( $assertion['response']['authenticatorData'] );
		$cdj       = SoftAuthenticator::b64url_decode( $assertion['response']['clientDataJSON'] );
		$signature = SoftAuthenticator::b64url_decode( $assertion['response']['signature'] );
		$this->assertSame( 37, strlen( $auth_data ), 'assertion authData carries no attested credential data' );

		$this->assertTrue( self::verify( $alg, $parsed['cose'], $auth_data . hash( 'sha256', $cdj, true ), $signature ) );
		$this->assertFalse( self::verify( $alg, $parsed['cose'], $auth_data . hash( 'sha256', $cdj . ' ', true ), $signature ), 'a signature over other client data fails' );

		// Packed self attestation: {alg, sig} signed with the credential key.
		$self = $auth->register( $options, 'https://example.test', [ 'self_attest' => true ] );
		$satt = Cbor::decode( SoftAuthenticator::b64url_decode( $self['response']['attestationObject'] ) );
		$this->assertSame( 'packed', $satt['fmt'] );
		$this->assertSame( [ 'alg', 'sig' ], array_keys( $satt['attStmt'] ) );
		$this->assertSame( $auth->coseAlg(), $satt['attStmt']['alg'] );
		$self_cdj = SoftAuthenticator::b64url_decode( $self['response']['clientDataJSON'] );
		$this->assertTrue( self::verify( $alg, $parsed['cose'], $satt['authData']->data . hash( 'sha256', $self_cdj, true ), $satt['attStmt']['sig']->data ) );
	}

	public function test_soft_authenticator_overrides(): void {
		$auth = new SoftAuthenticator(
			'ES256',
			[
				'be'         => false,
				'bs'         => false,
				'sign_count' => 5,
			]
		);
		$reg  = $auth->register(
			self::creation_options( 'handle' ),
			'https://example.test',
			[
				'clientData'   => [
					'type'                         => SoftAuthenticator::OMIT,
					'other_keys_can_be_added_here' => 'x',
				],
				'crossOrigin'  => 'true',
				'topOrigin'    => 'https://evil.example',
				'bom'          => true,
				'credProps_rk' => null,
				'cose'         => static fn( array $cose ) => Cbor::raw( "\xa0" ),
			]
		);
		$cdj  = SoftAuthenticator::b64url_decode( $reg['response']['clientDataJSON'] );
		$this->assertSame( "\xEF\xBB\xBF", substr( $cdj, 0, 3 ) );
		$client = json_decode( substr( $cdj, 3 ), true );
		$this->assertArrayNotHasKey( 'type', $client );
		$this->assertSame( 'true', $client['crossOrigin'] );
		$this->assertSame( 'https://evil.example', $client['topOrigin'] );
		$this->assertSame( 'x', $client['other_keys_can_be_added_here'] );
		$this->assertEquals( (object) [], $reg['clientExtensionResults'] );

		$auth_data = SoftAuthenticator::b64url_decode( $reg['response']['authenticatorData'] );
		$this->assertSame( SoftAuthenticator::FLAG_UP | SoftAuthenticator::FLAG_UV | SoftAuthenticator::FLAG_AT, ord( $auth_data[32] ) );
		$this->assertSame( "\xa0", substr( $auth_data, -1 ), 'a Raw COSE key is used verbatim' );

		$first  = $auth->assert( [ 'challenge' => 'AA', 'rpId' => 'example.test' ], 'https://example.test', [ 'userHandle' => null ] );
		$second = $auth->assert( [ 'challenge' => 'AA', 'rpId' => 'example.test' ], 'https://example.test', [ 'flags' => 0x01 ] );
		$this->assertArrayNotHasKey( 'userHandle', $first['response'] );
		$this->assertSame( 6, unpack( 'N', substr( SoftAuthenticator::b64url_decode( $first['response']['authenticatorData'] ), 33, 4 ) )[1] );
		$this->assertSame( 7, $auth->signCount(), 'a non-zero counter increments per assertion' );
		$this->assertSame( 0x01, ord( SoftAuthenticator::b64url_decode( $second['response']['authenticatorData'] )[32] ) );
	}

	/* ------------------------------------------------------ W3C L3 vectors */

	public function test_w3c_vectors_are_copied_intact(): void {
		$this->assertSame( [ '16.2', '16.4', '16.5', '16.6', '16.10', '16.11' ], Fixtures::ids() );
		foreach ( Fixtures::ids() as $id ) {
			$vector = Fixtures::vector( $id );
			$this->assertStringStartsWith( Fixtures::SOURCE, $vector['source'] );

			$reg_cdj = json_decode( Fixtures::bin( $id, 'registration', 'clientDataJSON' ), true );
			$this->assertSame( 'webauthn.create', $reg_cdj['type'], $id );
			$this->assertSame( SoftAuthenticator::b64url( Fixtures::bin( $id, 'registration', 'challenge' ) ), $reg_cdj['challenge'], $id );
			$this->assertSame( Fixtures::ORIGIN, $reg_cdj['origin'], $id );

			$att    = Cbor::decode( Fixtures::bin( $id, 'registration', 'attestationObject' ) );
			$parsed = self::parse_auth_data( $att['authData']->data );
			$this->assertSame( hash( 'sha256', Fixtures::RP_ID, true ), $parsed['rp_id_hash'], $id );
			$this->assertSame( Fixtures::bin( $id, 'registration', 'credential_id' ), $parsed['credential_id'], $id );
			$this->assertSame( Fixtures::bin( $id, 'registration', 'aaguid' ), $parsed['aaguid'], $id );

			$auth_cdj = json_decode( Fixtures::bin( $id, 'authentication', 'clientDataJSON' ), true );
			$this->assertSame( 'webauthn.get', $auth_cdj['type'], $id );
			$this->assertSame( SoftAuthenticator::b64url( Fixtures::bin( $id, 'authentication', 'challenge' ) ), $auth_cdj['challenge'], $id );
		}
		$this->assertTrue( json_decode( Fixtures::bin( '16.4', 'authentication', 'clientDataJSON' ), true )['crossOrigin'] );
		$this->assertSame( Fixtures::TOP_ORIGIN, json_decode( Fixtures::bin( '16.5', 'authentication', 'clientDataJSON' ), true )['topOrigin'] );
		$this->assertSame( 1023, strlen( Fixtures::bin( '16.6', 'registration', 'credential_id' ) ) );
		$this->assertSame( 'none', Cbor::decode( Fixtures::bin( '16.2', 'registration', 'attestationObject' ) )['fmt'] );
		$this->assertSame( 'packed', Cbor::decode( Fixtures::bin( '16.10', 'registration', 'attestationObject' ) )['fmt'] );
	}

	/** @return array<string,array{0:string,1:string}> */
	public static function w3c_signature_vectors(): array {
		return [
			'16.2 ES256'   => [ '16.2', 'ES256' ],
			'16.4 ES256'   => [ '16.4', 'ES256' ],
			'16.5 ES256'   => [ '16.5', 'ES256' ],
			'16.6 ES256'   => [ '16.6', 'ES256' ],
			'16.10 RS256'  => [ '16.10', 'RS256' ],
			'16.11 EdDSA'  => [ '16.11', 'EdDSA' ],
		];
	}

	/** @dataProvider w3c_signature_vectors */
	public function test_w3c_authentication_signatures_verify( string $id, string $alg ): void {
		$att    = Cbor::decode( Fixtures::bin( $id, 'registration', 'attestationObject' ) );
		$cose   = self::parse_auth_data( $att['authData']->data )['cose'];
		$signed = Fixtures::bin( $id, 'authentication', 'authenticatorData' ) . hash( 'sha256', Fixtures::bin( $id, 'authentication', 'clientDataJSON' ), true );
		$sig    = Fixtures::bin( $id, 'authentication', 'signature' );

		$this->assertTrue( self::verify( $alg, $cose, $signed, $sig ) );
		$this->assertFalse( self::verify( $alg, $cose, $signed . "\0", $sig ) );
	}

	/* ------------------------------------------------- wpdb MySQL emulation */

	public function test_sqlite_rewrites_delete_limit_and_insert_ignore(): void {
		global $wpdb;
		foreach ( [ 'a', 'b', 'c', 'd', 'e' ] as $k ) {
			$wpdb->insert( self::SCRATCH, [ 'k' => $k, 'v' => 'x' ] );
		}

		$this->assertSame( 2, $wpdb->query( 'DELETE FROM ' . self::SCRATCH . " WHERE v = 'x' LIMIT 2" ) );
		$this->assertSame( '', $wpdb->last_error );
		$this->assertSame( '3', $wpdb->get_var( 'SELECT COUNT(*) FROM ' . self::SCRATCH ) );
		$this->assertSame( 1, $wpdb->query( 'DELETE FROM ' . self::SCRATCH . ' ORDER BY id DESC LIMIT 1' ) );
		$this->assertNull( $wpdb->get_var( 'SELECT k FROM ' . self::SCRATCH . " WHERE k = 'e'" ) );

		$this->assertSame( 1, $wpdb->query( 'INSERT IGNORE INTO ' . self::SCRATCH . " (k, v) VALUES ('dup', '1')" ) );
		$this->assertGreaterThan( 0, $wpdb->insert_id );
		$this->assertSame( 0, $wpdb->query( 'INSERT IGNORE INTO ' . self::SCRATCH . " (k, v) VALUES ('dup', '2')" ) );
		$this->assertSame( 0, $wpdb->rows_affected );
		$this->assertSame( 0, $wpdb->insert_id, 'an ignored INSERT IGNORE reports insert_id 0' );
		$this->assertSame( '', $wpdb->last_error );

		// The production DELETE ... LIMIT in Installer::daily_cleanup() now runs.
		$wpdb->query_log = [];
		Installer::daily_cleanup();
		$this->assertSame( '', $wpdb->last_error );
		$requests = array_values( array_filter( $wpdb->query_log, static fn( string $q ): bool => 0 === strpos( ltrim( $q ), 'DELETE FROM wp_magicauth_requests' ) ) );
		$this->assertCount( 1, $requests );
		$this->assertStringContainsString( 'WHERE rowid IN (SELECT rowid FROM wp_magicauth_requests', $requests[0] );
	}

	/**
	 * LIKE follows MySQL's default escape character, the backslash that
	 * esc_like() writes (SQLite has none). An explicit ESCAPE fails, as on the
	 * WordPress SQLite driver, which appends its own.
	 */
	public function test_like_uses_the_mysql_default_escape(): void {
		global $wpdb;
		$bs = chr( 92 );
		foreach ( [ 'a_b', 'aXb', 'a%b', 'zz' ] as $k ) {
			$wpdb->insert( self::SCRATCH, [ 'k' => $k, 'v' => 'x' ] );
		}

		$sql = 'SELECT k FROM ' . self::SCRATCH . ' WHERE k LIKE %s OR k like %s ORDER BY k';
		$this->assertSame( [ 'a%b', 'a_b' ], $wpdb->get_col( $wpdb->prepare( $sql, $wpdb->esc_like( 'a_' ) . '%', $wpdb->esc_like( 'a%' ) . '%' ) ) );
		$this->assertSame( '', $wpdb->last_error );
		$this->assertSame( 2, substr_count( (string) end( $wpdb->query_log ), "%' ESCAPE '{$bs}'" ), 'appended to both patterns' );
		$this->assertSame( [ 'a%b', 'aXb', 'a_b' ], $wpdb->get_col( 'SELECT k FROM ' . self::SCRATCH . " WHERE k LIKE 'a_b' OR k LIKE 'a%' ORDER BY k" ), 'unescaped wildcards stay wildcards' );

		foreach ( [ "ESCAPE '{$bs}'", "ESCAPE '{$bs}{$bs}'", "escape '!'" ] as $clause ) {
			$wpdb->show_errors( true );
			ob_start();
			$rows = $wpdb->get_col( $wpdb->prepare( 'SELECT k FROM ' . self::SCRATCH . " WHERE k LIKE %s {$clause}", 'a%' ) );
			$out  = (string) ob_get_clean();
			$wpdb->show_errors( false );
			$this->assertSame( [], $rows, $clause );
			$this->assertStringContainsString( 'Explicit LIKE ... ESCAPE', $wpdb->last_error, $clause );
			$this->assertStringContainsString( 'Explicit LIKE ... ESCAPE', $out, 'printed like any query error' );
		}

		// The same words inside a quoted value are data.
		foreach ( [ "x LIKE 'a' ESCAPE '{$bs}'", "LIKE 'q'" ] as $value ) {
			$wpdb->insert( self::SCRATCH, [ 'k' => $value, 'v' => 'x' ] );
			$this->assertSame( '', $wpdb->last_error );
			$this->assertSame( $value, $wpdb->get_var( $wpdb->prepare( 'SELECT k FROM ' . self::SCRATCH . ' WHERE k = %s', $value ) ) );
		}
	}

	public function test_mysql_changed_rows_emulation(): void {
		global $wpdb;
		$wpdb->insert( self::SCRATCH, [ 'k' => 'c1', 'v' => 'same' ] );
		$wpdb->insert( self::SCRATCH, [ 'k' => 'c2', 'v' => 'same' ] );
		$wpdb->insert( self::SCRATCH, [ 'k' => 'c3', 'v' => 'other' ] );

		$consume = 'UPDATE ' . self::SCRATCH . " SET consumed_at = '2026-10-01 12:00:00' WHERE k = 'c1' AND consumed_at IS NULL";
		$rename  = 'UPDATE ' . self::SCRATCH . " SET v = 'same' WHERE k = 'c2'";

		// Off: SQLite counts matched rows.
		$this->assertSame( 1, $wpdb->query( $rename ) );

		$wpdb->mysql_changed_rows = true;
		$this->assertSame( 1, $wpdb->query( $consume ), 'consume' );
		$this->assertSame( 0, $wpdb->query( $consume ), 'replay' );
		$this->assertSame( 0, $wpdb->query( $rename ), 'rename to the same name' );
		$this->assertSame( 1, $wpdb->query( 'UPDATE ' . self::SCRATCH . " SET v = 'renamed' WHERE k = 'c2'" ) );
		$this->assertSame( 2, $wpdb->query( 'UPDATE ' . self::SCRATCH . " SET v = 'same'" ), 'three matched, two changed' );
		$this->assertSame( 0, $wpdb->query( 'UPDATE ' . self::SCRATCH . " SET v = 'WHERE x' WHERE k = 'nope'" ), 'WHERE inside a quoted value is not the clause' );

		magicauth_test_reset_state();
		$this->assertFalse( $wpdb->mysql_changed_rows, 'reset restores the default' );
	}

	public function test_error_injection(): void {
		global $wpdb;
		$wpdb->insert( self::SCRATCH, [ 'k' => 'e1', 'v' => 'v' ] );
		$select = 'SELECT * FROM ' . self::SCRATCH;

		$wpdb->fail_next_query( self::SCRATCH );
		$this->assertFalse( $wpdb->query( $select ) );
		$this->assertNotSame( '', $wpdb->last_error );
		$this->assertCount( 1, $wpdb->get_results( $select ), 'one injected failure, then normal' );
		$this->assertSame( '', $wpdb->last_error, 'last_error resets per query' );

		$wpdb->fail_next_query( '/^SELECT k/' );
		$this->assertSame( '1', $wpdb->get_var( 'SELECT COUNT(*) FROM ' . self::SCRATCH ), 'a non-matching query is untouched' );
		$this->assertNull( $wpdb->get_var( 'SELECT k FROM ' . self::SCRATCH ) );

		$wpdb->fail_next_query( self::SCRATCH );
		$this->assertNull( $wpdb->get_row( $select ) );
		$wpdb->fail_next_query( self::SCRATCH );
		$this->assertSame( [], $wpdb->get_results( $select ), 'core returns an empty array on error; check last_error' );
		$this->assertNotSame( '', $wpdb->last_error );
		$wpdb->fail_next_query( self::SCRATCH );
		$this->assertSame( [], $wpdb->get_col( $select ) );
		$wpdb->fail_next_query( 'INSERT' );
		$this->assertFalse( $wpdb->insert( self::SCRATCH, [ 'k' => 'e2' ] ) );
		$this->assertNull( $wpdb->get_var( 'SELECT k FROM ' . self::SCRATCH . " WHERE k = 'e2'" ), 'the injected INSERT did not run' );
	}

	public function test_print_error_echoes_only_when_shown_and_not_suppressed(): void {
		global $wpdb, $magicauth_test_state;
		$wpdb->insert( self::SCRATCH, [ 'k' => 'u1' ] );

		ob_start();
		$wpdb->insert( self::SCRATCH, [ 'k' => 'u1' ] );
		$this->assertSame( '', (string) ob_get_clean(), 'show_errors off: nothing printed' );
		$this->assertStringContainsString( 'UNIQUE', $wpdb->last_error );
		$this->assertCount( 1, $wpdb->error_log );

		$wpdb->show_errors();
		ob_start();
		$wpdb->insert( self::SCRATCH, [ 'k' => 'u1' ] );
		$printed = (string) ob_get_clean();
		$this->assertStringContainsString( 'WordPress database error:', $printed );
		$this->assertStringContainsString( 'INSERT INTO ' . self::SCRATCH, $printed, 'the SQL is printed' );

		$previous = $wpdb->suppress_errors();
		$this->assertFalse( $previous );
		ob_start();
		$wpdb->fail_next_query( self::SCRATCH );
		$wpdb->query( 'SELECT * FROM ' . self::SCRATCH );
		$this->assertSame( '', (string) ob_get_clean(), 'suppressed: nothing printed' );
		$wpdb->suppress_errors( false );

		$magicauth_test_state['multisite'] = true;
		ob_start();
		$wpdb->fail_next_query( self::SCRATCH );
		$wpdb->query( 'SELECT * FROM ' . self::SCRATCH );
		$this->assertSame( '', (string) ob_get_clean(), 'multisite: core logs instead of printing' );
	}

	/* -------------------------------------------------------- dbDelta fake */

	public function test_dbdelta_fake_runs_the_production_ddl(): void {
		global $wpdb, $magicauth_test_state;
		$table = $wpdb->prefix . 'magicauth_requests';
		$stub  = self::columns( $table );

		$wpdb->query( 'DROP TABLE ' . $table );
		$install = new \ReflectionMethod( Installer::class, 'install_schema' );
		if ( PHP_VERSION_ID < 80100 ) {
			$install->setAccessible( true ); // Needed on 8.0 only; deprecated in 8.5.
		}
		$install->invoke( null );

		$this->assertCount( 1, $magicauth_test_state['dbdelta_calls'] ?? [], 'dbDelta ran once' );
		$this->assertSame( $stub, self::columns( $table ), 'production DDL and the harness DDL have the same columns' );
		$this->assertSame( '', $wpdb->last_error );

		$row = [
			'selector'           => 'sel',
			'link_verifier_hash' => 'l',
			'code_verifier_hash' => 'c',
			'user_id'            => 1,
			'email_hmac'         => 'e',
			'ip_hmac'            => 'i',
			'created_at'         => '2026-10-01 00:00:00',
			'expires_at'         => '2026-10-01 00:10:00',
		];
		$this->assertSame( 1, $wpdb->insert( $table, $row ) );
		$this->assertSame( '1', $wpdb->get_var( "SELECT id FROM {$table}" ), 'AUTO_INCREMENT primary key' );
		$this->assertFalse( $wpdb->insert( $table, $row ), 'UNIQUE KEY selector is enforced' );
	}

	public function test_dbdelta_fake_adds_missing_columns_and_indexes(): void {
		global $wpdb;
		$table = $wpdb->prefix . 'magicauth_requests';
		$wpdb->insert(
			$table,
			[
				'selector'           => 'old',
				'link_verifier_hash' => 'l',
				'code_verifier_hash' => 'c',
				'user_id'            => 1,
				'email_hmac'         => 'e',
				'ip_hmac'            => 'i',
				'created_at'         => '2026-10-01 00:00:00',
				'expires_at'         => '2026-10-01 00:10:00',
			]
		);
		$ddl = "CREATE TABLE {$table} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  selector char(16) NOT NULL,
  granted_by bigint(20) unsigned NOT NULL,
  note varchar(191) DEFAULT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY selector (selector),
  KEY granted_by (granted_by)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$messages = \dbDelta( $ddl );
		$this->assertArrayHasKey( $table . '.granted_by', $messages );
		$this->assertArrayHasKey( $table . '.note', $messages );
		$this->assertContains( 'Added index ' . $table . ' granted_by', $messages );
		$this->assertContains( 'granted_by', self::columns( $table ) );
		$this->assertSame( '0', $wpdb->get_var( "SELECT granted_by FROM {$table} WHERE selector = 'old'" ), 'existing rows get the type default, as MySQL fills them' );
		$this->assertSame( '', $wpdb->last_error );

		$again = \dbDelta( $ddl );
		$this->assertSame( [], $again, 'a second run changes nothing' );
	}

	/* ----------------------------------------------------- core-like stubs */

	public function test_allcaps_built_as_core_builds_them(): void {
		$admin = magicauth_test_register_user( 11, 'admin@example.test', [ 'administrator' ] );
		$sub   = magicauth_test_register_user( 12, 'sub@example.test', [ 'subscriber' ] );

		$this->assertTrue( $admin->allcaps['administrator'] );
		$this->assertTrue( $admin->allcaps['manage_options'] );
		$this->assertTrue( $sub->allcaps['subscriber'] );
		$this->assertTrue( $sub->allcaps['read'] );
		$this->assertArrayNotHasKey( 'subscriber', $admin->allcaps, 'the B17 shape: role keys differ across roles' );
		$this->assertSame( $admin->allcaps, get_userdata( 11 )->allcaps );

		$sub->add_cap( 'edit_users' );
		$this->assertTrue( user_can( 12, 'edit_users' ) );
		magicauth_test_login_as( 11 );
		$this->assertTrue( current_user_can( 'administrator' ), 'core: a role name is a capability in allcaps' );
		$this->assertTrue( is_super_admin(), 'single site: delete_users' );
		$this->assertFalse( is_super_admin( 12 ) );
	}

	public function test_json_responses_and_ajax_referer(): void {
		global $magicauth_test_state;
		try {
			wp_send_json_success( [ 'a' => 1 ], 201 );
			$this->fail( 'wp_send_json_success must throw' );
		} catch ( JsonResponseSent $sent ) {
			$this->assertSame( [ 'success' => true, 'data' => [ 'a' => 1 ] ], $sent->payload );
			$this->assertSame( 201, $sent->status );
			$this->assertSame( '{"success":true,"data":{"a":1}}', $sent->body );
		}
		try {
			wp_send_json_error( new WP_Error( 'magicauth_x', 'msg' ) );
			$this->fail( 'wp_send_json_error must throw' );
		} catch ( JsonResponseSent $sent ) {
			$this->assertSame( [ 'success' => false, 'data' => [ [ 'code' => 'magicauth_x', 'message' => 'msg' ] ] ], $sent->payload );
			$this->assertNull( $sent->status );
		}
		$this->assertCount( 2, $magicauth_test_state['json_responses'] );

		$_REQUEST['_ajax_nonce'] = wp_create_nonce( 'magicauth_x' );
		$this->assertSame( 1, check_ajax_referer( 'magicauth_x' ) );
		$this->assertFalse( check_ajax_referer( 'magicauth_y', false, false ), 'a nonce is bound to its action' );
		$this->assertSame( wp_create_nonce( 'magicauth_x' ), sanitize_key( wp_create_nonce( 'magicauth_x' ) ) );
		$this->assertNotSame( wp_create_nonce( 'magicauth_x' ), wp_create_nonce( 'magicauth_y' ) );
		$this->assertFalse( wp_verify_nonce( 'test-nonce', 'magicauth_x' ), 'the action-less nonce does not pass an action' );
		$this->assertSame( 1, wp_verify_nonce( 'test-nonce' ) );
		$this->assertFalse( wp_verify_nonce( '', 'magicauth_x' ) );
		$_REQUEST['_ajax_nonce'] = 'bad';
		$this->assertFalse( check_ajax_referer( 'magicauth_x', false, false ) );
		$this->expectException( JsonResponseSent::class );
		check_ajax_referer( 'magicauth_x' );
	}

	public function test_redirects_validate_like_core(): void {
		global $magicauth_test_state;
		wp_safe_redirect( 'https://evil.example/', 303 );
		wp_safe_redirect( 'javascript:alert(1)' );
		wp_safe_redirect( 'https://example.test/deep/link?x=1#part' );
		$this->assertSame(
			[
				[ 'location' => admin_url(), 'status' => 303 ],
				[ 'location' => admin_url(), 'status' => 302 ],
				[ 'location' => 'https://example.test/deep/link?x=1#part', 'status' => 302 ],
			],
			$magicauth_test_state['redirects']
		);
		$this->assertSame( '', wp_validate_redirect( 'https://example.test@evil.example/', '' ) );
		$this->assertSame( 'fallback', wp_validate_redirect( '//evil.example/x', 'fallback' ) );

		$magicauth_test_state['redirect_throws'] = true;
		try {
			wp_safe_redirect( 'https://example.test/x', 303 );
			$this->fail( 'redirect_throws must throw' );
		} catch ( RedirectSent $sent ) {
			$this->assertSame( 'https://example.test/x', $sent->location );
			$this->assertSame( 303, $sent->status );
		}
	}

	public function test_url_helpers_follow_core(): void {
		global $magicauth_test_state;
		$this->assertSame( 'https://example.test/', home_url( '/' ) );
		$this->assertSame( 'http://example.test/wp-admin/admin-ajax.php', admin_url( 'admin-ajax.php' ), 'site_url follows the request scheme' );
		$magicauth_test_state['is_ssl'] = true;
		$this->assertSame( 'https://example.test/wp-admin/admin-ajax.php', admin_url( 'admin-ajax.php' ) );

		$magicauth_test_state['home']    = 'http://localhost:9400';
		$magicauth_test_state['siteurl'] = 'http://localhost:9400/wp';
		$magicauth_test_state['is_ssl']  = false;
		$this->assertSame( 'http://localhost:9400/', home_url( '/' ) );
		$this->assertSame( 'http://localhost:9400/wp/wp-login.php', site_url( 'wp-login.php' ) );
		$this->assertSame( '/wp/x', site_url( 'x', 'relative' ) );

		$this->assertSame( 'https://example.test/x?y=1&magicauth_retry=1#frag', add_query_arg( 'magicauth_retry', '1', 'https://example.test/x?y=1#frag' ) );
		$this->assertSame( 'https://example.test/x?a=1&b=2', add_query_arg( [ 'a' => '1', 'b' => '2' ], 'https://example.test/x' ) );
		$this->assertSame( 'https://example.test/x?keep=1', remove_query_arg( [ 'magicauth_step', 'magicauth_sid' ], 'https://example.test/x?magicauth_step=code&keep=1&magicauth_sid=s' ) );
		$_SERVER['REQUEST_URI'] = '/login/?a=1';
		$this->assertSame( '/login/?a=1&b=2', add_query_arg( 'b', '2' ) );
		unset( $_SERVER['REQUEST_URI'] );

		$this->assertSame( '/wp-login.php?action=magicauth&wp_lang=nl_NL', esc_url_raw( '/wp-login.php?action=magicauth&wp_lang=nl_NL' ) );
		$this->assertSame( 'http://example.test/x%20y', esc_url_raw( 'example.test/x y' ) );
		$this->assertSame( 'https://example.test/xy', esc_url_raw( "https://example.test/x\ny%0D%0a" ) );
		$this->assertSame( '', esc_url_raw( 'javascript:alert(1)' ) );
		$this->assertSame( '', esc_url_raw( 'mailto:a@example.test', [ 'http', 'https' ] ) );

		$this->assertSame( 'en_US', determine_locale() );
		$this->assertSame( [], get_available_languages() );
		$magicauth_test_state['locale']              = 'nl_NL';
		$magicauth_test_state['available_languages'] = [ 'nl_NL', 'de_DE' ];
		$this->assertSame( 'nl_NL', determine_locale() );
		$this->assertSame( [ 'nl_NL', 'de_DE' ], get_available_languages() );
	}

	public function test_hooks_honour_priority_accepted_args_and_removal(): void {
		$order = static function ( $v ) {
			return $v . 'a';
		};
		$early = static function ( $v ) {
			return $v . 'b';
		};
		add_filter( 'magicauth_selftest', $order, 20 );
		add_filter( 'magicauth_selftest', $early, 5 );
		$this->assertSame( 'xba', apply_filters( 'magicauth_selftest', 'x' ) );
		$this->assertSame( 20, has_filter( 'magicauth_selftest', $order ) );

		$this->assertFalse( remove_filter( 'magicauth_selftest', $order ), 'wrong priority removes nothing' );
		$this->assertTrue( remove_filter( 'magicauth_selftest', $order, 20 ) );
		$this->assertSame( 'xb', apply_filters( 'magicauth_selftest', 'x' ) );

		add_filter(
			'magicauth_selftest_args',
			static function ( ...$args ) {
				return count( $args );
			},
			10,
			2
		);
		$this->assertSame( 2, apply_filters( 'magicauth_selftest_args', 1, 2, 3 ) );

		$seen = [];
		add_filter(
			'magicauth_selftest_action',
			static function ( $arg ) use ( &$seen ) {
				$seen[] = $arg;
			}
		);
		do_action( 'magicauth_selftest_action', 'first' );
		do_action( 'magicauth_selftest_action' );
		$this->assertSame( [ 'first', '' ], $seen, 'actions see filter-registered callbacks; no args passes one empty string' );
		$this->assertSame( 2, did_action( 'magicauth_selftest_action' ) );
	}

	public function test_session_tokens_and_auth_cookie(): void {
		global $magicauth_test_state;
		magicauth_test_register_user( 21, 'session@example.test' );
		$stamp = static function ( array $session, int $user_id ): array {
			$session['magicauth_method'] = 'link';
			$session['magicauth_user']   = $user_id;
			return $session;
		};
		add_filter( 'attach_session_information', $stamp, 10, 2 );
		wp_set_auth_cookie( 21, true, true );
		remove_filter( 'attach_session_information', $stamp, 10 );
		wp_set_auth_cookie( 21, false );

		$this->assertSame( 21, $magicauth_test_state['auth_cookie_set_for'] );
		$this->assertCount( 2, $magicauth_test_state['auth_cookies'] );
		$first   = $magicauth_test_state['auth_cookies'][0]['token'];
		$second  = $magicauth_test_state['auth_cookies'][1]['token'];
		$manager = WP_Session_Tokens::get_instance( 21 );
		$this->assertSame( 'link', $manager->get( $first )['magicauth_method'] );
		$this->assertSame( 21, $manager->get( $first )['magicauth_user'] );
		$this->assertArrayNotHasKey( 'magicauth_method', $manager->get( $second ), 'the stamp was removed before the second session' );
		$this->assertGreaterThan( time() + 13 * DAY_IN_SECONDS, $manager->get( $first )['expiration'] );

		magicauth_test_login_as( 21 );
		$magicauth_test_state['session_token'] = $second;
		wp_destroy_other_sessions();
		$this->assertNull( $manager->get( $first ) );
		$this->assertNotNull( $manager->get( $second ) );

		$magicauth_test_state['auth_cookie_throws'] = new \RuntimeException( 'cookie' );
		try {
			wp_set_auth_cookie( 21 );
			$this->fail( 'auth_cookie_throws must throw' );
		} catch ( \RuntimeException $e ) {
			$this->assertSame( 'cookie', $e->getMessage() );
		}

		$this->expectException( \LogicException::class );
		$manager->update( $second, [] );
	}

	public function test_user_meta_follows_core_including_the_unique_race(): void {
		global $magicauth_test_state;
		magicauth_test_register_user( 31, 'meta@example.test' );
		magicauth_test_register_user( 32, 'meta2@example.test' );

		$this->assertSame( '', get_user_meta( 31, 'magicauth_x', true ) );
		$this->assertSame( [], get_user_meta( 31, 'magicauth_x' ) );

		$this->assertIsInt( add_user_meta( 31, 'magicauth_handle', 'A', true ) );
		$this->assertFalse( add_user_meta( 31, 'magicauth_handle', 'B', true ), 'unique without a race' );

		// Another request inserts between our COUNT and our INSERT.
		$magicauth_test_state['add_user_meta_race'] = static function ( int $user_id, string $key ): void {
			add_user_meta( $user_id, $key, 'RACER' );
		};
		$this->assertIsInt( add_user_meta( 32, 'magicauth_handle', 'MINE', true ) );
		$this->assertSame( [ 'RACER', 'MINE' ], get_user_meta( 32, 'magicauth_handle' ) );
		$this->assertSame( 'RACER', get_user_meta( 32, 'magicauth_handle', true ) );

		$this->assertTrue( delete_user_meta( 32, 'magicauth_handle', 'RACER' ) );
		$this->assertSame( [ 'MINE' ], get_user_meta( 32, 'magicauth_handle' ) );

		$this->assertSame( [ '31' ], get_users( [ 'meta_key' => 'magicauth_handle', 'meta_value' => 'A', 'fields' => 'ID' ] ) );
		$this->assertSame( [ '31', '32' ], get_users( [ 'meta_query' => [ [ 'key' => 'magicauth_handle', 'compare' => 'EXISTS' ] ], 'fields' => 'ID' ] ) );

		$this->assertTrue( delete_metadata( 'user', 0, 'magicauth_handle', '', true ) );
		$this->assertSame( [], get_users( [ 'meta_key' => 'magicauth_handle', 'fields' => 'ID' ] ) );
	}

	public function test_sanitize_text_field_and_misc_toggles(): void {
		global $magicauth_test_state;
		$this->assertSame( 'x y z', sanitize_text_field( "<b>x</b>  y\n z" ) );
		$this->assertSame( 'bc', sanitize_text_field( '%41bc' ) );
		$this->assertSame( '', sanitize_text_field( "\xff" ) );
		$this->assertSame( 'a &lt; b', sanitize_text_field( 'a < b' ) );

		$this->assertFalse( is_multisite() );
		$magicauth_test_state['multisite']    = true;
		$magicauth_test_state['sites']        = [
			[ 'domain' => 'example.test', 'path' => '/' ],
			[ 'domain' => 'example.test', 'path' => '/two/' ],
			[ 'domain' => 'other.test', 'path' => '/' ],
		];
		$magicauth_test_state['spammy_users'] = [ 41 ];
		$magicauth_test_state['super_admins'] = [ 'boss' ];
		$this->assertTrue( is_multisite() );
		$this->assertFalse( is_subdomain_install() );
		$this->assertSame( 2, get_sites( [ 'domain' => 'example.test', 'count' => true ] ) );
		$spammy = magicauth_test_register_user( 41, 'spam@example.test' );
		$boss   = magicauth_test_register_user( 42, 'boss@example.test', [ 'subscriber' ] );
		$boss->user_login = 'boss';
		$this->assertTrue( is_user_spammy( $spammy ) );
		$this->assertFalse( is_user_spammy( $boss ) );
		$this->assertTrue( is_super_admin( 42 ) );

		$magicauth_test_state['timezone_string'] = 'Europe/Amsterdam';
		$this->assertSame( '2026-10-01 14:00', wp_date( 'Y-m-d H:i', 1790856000 ) );

		$magicauth_test_state['posts'][9] = [ 'status' => 'publish', 'type' => 'page', 'permalink' => 'https://example.test/account/' ];
		$this->assertSame( 'publish', get_post_status( 9 ) );
		$this->assertSame( 'page', get_post_type( 9 ) );
		$this->assertSame( 'https://example.test/account/', get_permalink( 9 ) );
		$this->assertFalse( get_post_status( 10 ) );
	}

	/* ----------------------------------------------------- golden fixtures */

	public function test_golden_fixtures_match_their_manifest(): void {
		$manifest = json_decode( (string) file_get_contents( Golden::DIR . '/MANIFEST.json' ), true );
		$this->assertSame( self::SOURCE_COMMIT, $manifest['source_commit'] );
		$this->assertSame( Golden::files(), array_keys( $manifest['files'] ) );
		foreach ( $manifest['files'] as $file => $sha256 ) {
			$this->assertSame( $sha256, hash_file( 'sha256', Golden::DIR . '/' . $file ), $file );
		}
	}

	public function test_this_tree_reproduces_the_1_0_5_fixtures(): void {
		$rendered = Golden::render_all();
		$this->assertSame( Golden::files(), array_keys( $rendered ) );
		foreach ( $rendered as $file => $content ) {
			if ( isset( self::KNOWN_CHANGES[ $file ] ) ) {
				continue;
			}
			$this->assertSame( (string) file_get_contents( Golden::DIR . '/' . $file ), $content, $file );
		}
	}

	public function test_normalise_hides_per_request_values_and_layout(): void {
		$a = '<div  id="x" class="c"><form><input type="hidden" name="magicauth_nonce" value="abc123"/>'
			. '<input name="magicauth_sid" value="s1"><input name="magicauth_ts" value="1790000000">'
			. '<a href="/wp-login.php?action=logout&amp;_wpnonce=f00">x</a>'
			. '<script src="https://example.test/a.js?ver=1.0.5"></script><p>Hello   world</p></form></div>';
		$b = "<div class=\"c\" id=\"x\">\n\t<form>\n\t\t<input value=\"zzz\" name=\"magicauth_nonce\" type=\"hidden\">\n"
			. "<input value=\"s2\" name=\"magicauth_sid\">\n<input name=\"magicauth_ts\" value=\"1\">\n"
			. "\t\t<a href=\"/wp-login.php?action=logout&amp;_wpnonce=bar\">x</a>\n\n"
			. "<script src=\"https://example.test/a.js?ver=1.1.0\"></script>\n<p>Hello\n world</p>\n\t</form>\n</div>\n";

		$normal = Normalise::html( $a );
		$this->assertSame( $normal, Normalise::html( $b ) );
		$this->assertStringContainsString( '<input name="magicauth_nonce" type="hidden" value="{{nonce}}" />', $normal );
		$this->assertStringContainsString( 'value="{{sid}}"', $normal );
		$this->assertStringContainsString( 'value="{{ts}}"', $normal );
		$this->assertStringContainsString( '_wpnonce={{nonce}}', $normal );
		$this->assertStringContainsString( 'a.js?ver={{ver}}', $normal );
		$this->assertStringContainsString( '"Hello world"', $normal );
		$this->assertNotSame( $normal, Normalise::html( str_replace( 'Hello', 'Bye', $a ) ) );
		$this->assertSame( "line\n", Normalise::text( "line  \r\n\r\n" ) );
	}

	/* ------------------------------------------------------------- helpers */

	/** @return array<string,mixed> */
	private static function creation_options( string $handle ): array {
		return [
			'challenge'        => SoftAuthenticator::b64url( random_bytes( 32 ) ),
			'rp'               => [
				'id'   => 'example.test',
				'name' => 'example.test',
			],
			'user'             => [
				'id'          => SoftAuthenticator::b64url( $handle ),
				'name'        => 'student@example.test',
				'displayName' => 'Student',
			],
			'pubKeyCredParams' => [
				[ 'type' => 'public-key', 'alg' => -7 ],
				[ 'type' => 'public-key', 'alg' => -8 ],
				[ 'type' => 'public-key', 'alg' => -257 ],
			],
		];
	}

	/** @return array{rp_id_hash:string,flags:int,sign_count:int,aaguid:string,credential_id:string,cose:array<int,mixed>,rest:string} */
	private static function parse_auth_data( string $data ): array {
		$out = [
			'rp_id_hash'    => substr( $data, 0, 32 ),
			'flags'         => ord( $data[32] ),
			'sign_count'    => unpack( 'N', substr( $data, 33, 4 ) )[1],
			'aaguid'        => '',
			'credential_id' => '',
			'cose'          => [],
			'rest'          => '',
		];
		if ( $out['flags'] & SoftAuthenticator::FLAG_AT ) {
			$out['aaguid']        = substr( $data, 37, 16 );
			$length               = unpack( 'n', substr( $data, 53, 2 ) )[1];
			$out['credential_id'] = substr( $data, 55, $length );
			$offset               = 55 + $length;
			$out['cose']          = Cbor::decode_item( $data, $offset );
			$out['rest']          = (string) substr( $data, $offset );
		}
		return $out;
	}

	/** @param array<int,mixed> $cose */
	private static function verify( string $alg, array $cose, string $data, string $signature ): bool {
		if ( 'EdDSA' === $alg ) {
			return 64 === strlen( $signature ) && sodium_crypto_sign_verify_detached( $signature, $data, $cose[-2]->data );
		}
		$der = self::spki_from_cose( $cose );
		$pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split( base64_encode( $der ), 64, "\n" ) . "-----END PUBLIC KEY-----\n";
		return 1 === openssl_verify( $data, $signature, $pem, OPENSSL_ALGO_SHA256 );
	}

	/**
	 * SubjectPublicKeyInfo DER built from the COSE key alone.
	 *
	 * @param array<int,mixed> $cose
	 */
	private static function spki_from_cose( array $cose ): string {
		switch ( $cose[1] ) {
			case 2: // EC2, P-256.
				$algorithm = self::der( 0x30, self::der( 0x06, hex2bin( '2a8648ce3d0201' ) ) . self::der( 0x06, hex2bin( '2a8648ce3d030107' ) ) );
				$key       = "\x04" . $cose[-2]->data . $cose[-3]->data;
				break;
			case 3: // RSA.
				$algorithm = self::der( 0x30, self::der( 0x06, hex2bin( '2a864886f70d010101' ) ) . "\x05\x00" );
				$key       = self::der( 0x30, self::der_uint( $cose[-1]->data ) . self::der_uint( $cose[-2]->data ) );
				break;
			default: // OKP, Ed25519.
				$algorithm = self::der( 0x30, self::der( 0x06, hex2bin( '2b6570' ) ) );
				$key       = $cose[-2]->data;
				break;
		}
		return self::der( 0x30, $algorithm . self::der( 0x03, "\x00" . $key ) );
	}

	private static function der( int $tag, string $content ): string {
		$length = strlen( $content );
		if ( $length < 0x80 ) {
			return chr( $tag ) . chr( $length ) . $content;
		}
		$bytes = ltrim( pack( 'N', $length ), "\0" );
		return chr( $tag ) . chr( 0x80 | strlen( $bytes ) ) . $bytes . $content;
	}

	private static function der_uint( string $bytes ): string {
		$bytes = ltrim( $bytes, "\0" );
		if ( '' === $bytes || ord( $bytes[0] ) & 0x80 ) {
			$bytes = "\0" . $bytes;
		}
		return self::der( 0x02, $bytes );
	}

	/** @return array<int,string> */
	private static function columns( string $table ): array {
		global $wpdb;
		$out = [];
		foreach ( $wpdb->get_results( 'PRAGMA table_info(' . $table . ')' ) as $row ) {
			$out[] = (string) $row->name;
		}
		return $out;
	}
}
