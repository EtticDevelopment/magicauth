<?php
/**
 * T-REG at the verifier level (SPEC 7.3, 15 step 9: cases 9b to 31 plus the
 * happy paths): Verifier::verify_registration() and store_registration()
 * with SoftAuthenticator credentials against real challenge rows, under MySQL
 * changed-rows semantics. Endpoint gates (cases 1 to 9, email, cadence, rule E
 * initialisation) come with build step 11.
 *
 * Every failure after R-2 must carry unknown_credential only when the
 * challenge was not replayed and a successful final SELECT proved the
 * credential absent (orphan flag, invariant 8). Nothing may be printed and no
 * warning, notice or deprecation may escape (phpunit.xml.dist fails on them).
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Passkeys\Base64Url;
use MagicAuth\Passkeys\ChallengeStore;
use MagicAuth\Passkeys\Clock;
use MagicAuth\Passkeys\CredentialStore;
use MagicAuth\Passkeys\Verifier;
use MagicAuth\Tests\Support\Cbor;
use MagicAuth\Tests\Support\Ceremony;
use MagicAuth\Tests\Support\SoftAuthenticator;
use PHPUnit\Framework\TestCase;
use WP_Error;
use WP_User;

final class RegistrationVerifierTest extends TestCase {

	private const OMIT = SoftAuthenticator::OMIT;

	private WP_User $user;

	protected function setUp(): void {
		Ceremony::site();
		$this->user = Ceremony::user( 7 );
	}

	protected function tearDown(): void {
		magicauth_test_reset_state();
	}

	/**
	 * verify_registration() with output captured: nothing may be printed.
	 *
	 * @return array<string,mixed>|WP_Error
	 */
	private function verify( string $credential, ?WP_User $user = null, string $session = Ceremony::SESSION, string $name = '', string $platform = '', string $ua = '' ) {
		global $wpdb;
		$wpdb->show_errors( true );
		ob_start();
		try {
			$result = Verifier::verify_registration( $credential, $user ?? $this->user, $session, $name, $platform, $ua );
		} finally {
			$out = (string) ob_get_clean();
			$wpdb->show_errors( false );
		}
		$this->assertSame( '', $out, 'nothing printed' );
		return $result;
	}

	/** @param mixed $result */
	private function assert_failed( $result, string $code, int $status, bool $flag, string $message = '' ): void {
		$this->assertInstanceOf( WP_Error::class, $result, $message );
		$this->assertSame( $code, $result->get_error_code(), $message );
		$data = $result->get_error_data();
		$this->assertIsArray( $data );
		$this->assertSame( $status, $data['status'], $message );
		$this->assertSame( $flag, $data['unknown_credential'], $message . ': unknown_credential' );
		$this->assertSame( '', $result->get_error_message(), 'no message from the verifier' );
	}

	/**
	 * @param array<string,mixed>|\Closure $o
	 * @return array<string,mixed>|WP_Error
	 */
	private function register( SoftAuthenticator $auth, $o = [] ) {
		return $this->verify( Ceremony::registration( $auth, $this->user, $o ) );
	}

	/** @return array<string,array{string}> */
	public static function algs(): array {
		return [
			'ES256' => [ 'ES256' ],
			'RS256' => [ 'RS256' ],
			'EdDSA' => [ 'EdDSA' ],
		];
	}

	/* ------------------------------------------------------------------ happy */

	/** @dataProvider algs */
	public function test_registers_and_stores( string $alg ): void {
		$auth   = new SoftAuthenticator( $alg, [ 'sign_count' => 3 ] );
		$issued = Ceremony::register_options( $this->user );
		$record = $this->verify( Ceremony::encode( $auth->register( $issued['options'], Ceremony::ORIGIN ) ) );

		$this->assertIsArray( $record );
		$this->assertSame(
			[ 'user_id', 'rp_id', 'credential_id', 'user_handle', 'public_key', 'alg', 'sign_count', 'backup_eligible', 'backup_state', 'transports', 'aaguid', 'name', 'user_registered' ],
			array_keys( $record )
		);
		$this->assertSame( 7, $record['user_id'] );
		$this->assertSame( Ceremony::RP, $record['rp_id'] );
		$this->assertSame( Base64Url::encode( $auth->credentialId() ), $record['credential_id'] );
		$this->assertSame( $issued['handle'], $record['user_handle'] );
		$this->assertSame( $auth->coseAlg(), $record['alg'] );
		$this->assertSame( 3, $record['sign_count'] );
		$this->assertTrue( $record['backup_eligible'] );
		$this->assertTrue( $record['backup_state'] );
		$this->assertSame( 'internal,hybrid', $record['transports'] );
		$this->assertSame( '00000000-0000-0000-0000-000000000000', $record['aaguid'] );
		$this->assertSame( 'Passkey', $record['name'] );
		$this->assertSame( Ceremony::REGISTERED, $record['user_registered'] );
		$this->assertStringStartsWith( '-----BEGIN PUBLIC KEY-----', $record['public_key'] );

		$id = Verifier::store_registration( $record );
		$this->assertIsInt( $id );
		$row = Ceremony::row( $id );
		$this->assertNotNull( $row );
		$this->assertSame( hash( 'sha256', $auth->credentialId() ), $row['credential_hash'] );
		$this->assertSame( (string) $auth->coseAlg(), (string) $row['alg'] );
		$this->assertSame( '3', (string) $row['sign_count'] );
	}

	/** @return array<string,array{bool,bool}> */
	public static function backup_flags(): array {
		return [
			'synced'             => [ true, true ],
			'eligible, unsynced' => [ true, false ],
			'device-bound'       => [ false, false ],
		];
	}

	/** @dataProvider backup_flags */
	public function test_backup_flags_are_stored( bool $be, bool $bs ): void {
		$auth = new SoftAuthenticator(
			'ES256',
			[
				'be' => $be,
				'bs' => $bs,
			]
		);
		$row = Ceremony::row( Ceremony::enrol( $auth, $this->user ) );
		$this->assertNotNull( $row );
		$this->assertSame( $be ? '1' : '0', (string) $row['backup_eligible'] );
		$this->assertSame( $bs ? '1' : '0', (string) $row['backup_state'] );
	}

	/** 15b: packed self attestation is accepted and stored like none. */
	public function test_packed_self_attestation_is_accepted(): void {
		foreach ( [ 'ES256', 'RS256', 'EdDSA' ] as $alg ) {
			$auth   = new SoftAuthenticator( $alg );
			$record = $this->register( $auth, [ 'self_attest' => true ] );
			$this->assertIsArray( $record, $alg );
			$this->assertSame( $auth->coseAlg(), $record['alg'] );
			$this->assertSame( '00000000-0000-0000-0000-000000000000', $record['aaguid'] );
			$this->assertIsInt( Verifier::store_registration( $record ) );
		}
		$this->assertSame( 3, Ceremony::count_rows() );
	}

	/* ------------------------------------------------------------------ 9b, R-5, R-11 */

	/** 9b: options at t=0, email change at t=60 (rule M deletes the row), register at t=120. */
	public function test_email_change_after_options_deletes_the_challenge(): void {
		$auth       = new SoftAuthenticator();
		$credential = Ceremony::registration( $auth, $this->user );

		Clock::set_for_tests( Ceremony::NOW + 60 );
		update_user_meta( 7, 'magicauth_email_changed_at', Ceremony::NOW + 60 );
		ChallengeStore::delete_for_user( 7 );

		Clock::set_for_tests( Ceremony::NOW + 120 );
		$this->assert_failed( $this->verify( $credential ), 'registration_failed', 400, true );
	}

	/** 9b: the same with the row left in place (deletion lost a race): rejected at R-11. */
	public function test_email_change_after_options_is_rejected_at_r11(): void {
		$auth       = new SoftAuthenticator();
		$credential = Ceremony::registration( $auth, $this->user );
		update_user_meta( 7, 'magicauth_email_changed_at', Ceremony::NOW + 60 );

		Clock::set_for_tests( Ceremony::NOW + 120 );
		$this->assert_failed( $this->verify( $credential ), 'registration_failed', 400, true );
		$this->assertSame( 0, Ceremony::count_rows() );
	}

	public function test_email_change_boundary(): void {
		// Changed in the second the challenge was issued: rejected (>=).
		update_user_meta( 7, 'magicauth_email_changed_at', Ceremony::NOW );
		$this->assert_failed( $this->register( new SoftAuthenticator() ), 'registration_failed', 400, true );

		// Changed one second before the challenge: accepted.
		update_user_meta( 7, 'magicauth_email_changed_at', Ceremony::NOW - 1 );
		$this->assertIsArray( $this->register( new SoftAuthenticator() ) );
	}

	public function test_challenge_of_another_user_or_session_is_rejected(): void {
		$other = Ceremony::user( 8 );
		$auth  = new SoftAuthenticator();

		// Issued for user 8, posted by user 7.
		$credential = Ceremony::registration( $auth, $other );
		$this->assert_failed( $this->verify( $credential ), 'registration_failed', 400, true, 'other user' );

		// Issued for another session of the same user.
		$credential = Ceremony::registration( $auth, $this->user, [], str_repeat( 'c', 64 ) );
		$this->assert_failed( $this->verify( $credential ), 'registration_failed', 400, true, 'other session' );

		// Empty session hash on our side never matches.
		$credential = Ceremony::registration( $auth, $this->user );
		$this->assert_failed( $this->verify( $credential, null, '' ), 'registration_failed', 400, true, 'empty session' );
	}

	public function test_signin_challenge_cannot_register(): void {
		$auth    = new SoftAuthenticator();
		$request = Ceremony::signin_options();
		$issued  = Ceremony::register_options( $this->user );
		$options = $issued['options'];
		// The signin challenge in otherwise valid creation options.
		$options['challenge'] = $request['challenge'];
		$this->assert_failed( $this->verify( Ceremony::encode( $auth->register( $options, Ceremony::ORIGIN ) ) ), 'registration_failed', 400, true );
	}

	public function test_expired_and_unknown_challenges_are_flagged(): void {
		$auth       = new SoftAuthenticator();
		$credential = Ceremony::registration( $auth, $this->user );
		Clock::set_for_tests( Ceremony::NOW + ChallengeStore::TTL['register'] );
		$this->assert_failed( $this->verify( $credential ), 'registration_failed', 400, true, 'expired at expires_at' );

		Clock::set_for_tests( Ceremony::NOW );
		$credential = Ceremony::registration(
			$auth,
			$this->user,
			[ 'challenge' => Base64Url::encode( random_bytes( 32 ) ) ]
		);
		$this->assert_failed( $this->verify( $credential ), 'registration_failed', 400, true, 'unknown challenge' );
	}

	public function test_disabled_user_is_rejected_with_the_flag(): void {
		update_user_meta( 7, 'magicauth_disabled', 1 );
		$this->assert_failed( $this->register( new SoftAuthenticator() ), 'registration_failed', 400, true );
	}

	/** 25: the limit counts this RP ID only; reaching it is flagged. */
	public function test_limit_reached(): void {
		for ( $i = 0; $i < 9; $i++ ) {
			Ceremony::enrol( new SoftAuthenticator(), $this->user );
		}
		// A row for another RP ID does not count.
		$extra = Ceremony::enrol( new SoftAuthenticator(), $this->user );
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'UPDATE ' . CredentialStore::table() . " SET rp_id = 'old.example.com' WHERE id = %d", $extra ) );

		$tenth = Ceremony::enrol( new SoftAuthenticator(), $this->user );
		$this->assertIsInt( $tenth );

		$this->assert_failed( $this->register( new SoftAuthenticator() ), 'limit_reached', 409, true );

		add_filter(
			'magicauth_passkey_max_per_user',
			static function () {
				return 11;
			}
		);
		$this->assertIsArray( $this->register( new SoftAuthenticator() ) );
	}

	public function test_limit_read_error_is_retry_without_flag(): void {
		global $wpdb;
		$credential = Ceremony::registration( new SoftAuthenticator(), $this->user );
		$wpdb->fail_next_query( 'SELECT * FROM wp_magicauth_passkeys WHERE user_id' );
		$this->assert_failed( $this->verify( $credential ), 'retry', 503, false );
	}

	/* ------------------------------------------------------------------ 10 to 14: shape */

	public function test_size_caps(): void {
		$auth = new SoftAuthenticator();

		// R-1: the field itself; no trusted ID, no flag.
		$huge = Ceremony::decode( Ceremony::registration( $auth, $this->user ) );
		$huge['padding'] = str_repeat( 'x', Verifier::MAX_CREDENTIAL );
		$this->assert_failed( $this->verify( Ceremony::encode( $huge ) ), 'registration_failed', 400, false, 'credential cap' );

		// R-3: clientDataJSON over 4096 bytes (flagged: after R-2).
		$credential = Ceremony::registration( $auth, $this->user, [ 'clientData' => [ 'pad' => str_repeat( 'p', 4100 ) ] ] );
		$this->assertLessThan( Verifier::MAX_CREDENTIAL, strlen( $credential ) );
		$this->assert_failed( $this->verify( $credential ), 'registration_failed', 400, true, 'clientDataJSON cap' );

		// R-3: attestationObject over 16384 bytes, the field still under 24576.
		$credential = Ceremony::registration( $auth, $this->user, [ 'attestationObject' => random_bytes( 16385 ) ] );
		$this->assertLessThan( Verifier::MAX_CREDENTIAL, strlen( $credential ) );
		$this->assert_failed( $this->verify( $credential ), 'registration_failed', 400, true, 'attestationObject cap' );
	}

	/** 21: the 100k-deep attestationObject never reaches the decoder; a 15 KB depth bomb is rejected by R2. */
	public function test_cbor_depth_bombs(): void {
		$auth = new SoftAuthenticator();
		$bomb = Ceremony::registration( $auth, $this->user, [ 'attestationObject' => Cbor::nested_array( 100000 ) ] );
		$this->assert_failed( $this->verify( $bomb ), 'registration_failed', 400, false, '100k nesting: over the field cap' );

		$json = Ceremony::decode(
			Ceremony::registration(
				$auth,
				$this->user,
				[
					'cose' => static function () {
						return Cbor::raw( Cbor::nested_array( 15000 ) );
					},
				]
			)
		);
		// The verifier reads only clientDataJSON and attestationObject; drop the
		// informational copies so the bomb fits under the field cap.
		unset( $json['response']['authenticatorData'], $json['response']['publicKey'] );
		$credential = Ceremony::encode( $json );
		$this->assertGreaterThan( 15000, strlen( (string) Base64Url::decode( $json['response']['attestationObject'], 1, 16384 ) ) );
		$this->assertLessThan( Verifier::MAX_CREDENTIAL, strlen( $credential ) );
		$this->assert_failed( $this->verify( $credential ), 'registration_failed', 400, true, '15 KB depth bomb' );
	}

	/** @return array<string,array{\Closure}> */
	public static function malformed_before_r2(): array {
		return [
			'not JSON'               => [ static fn( array $c ): string => 'not json' ],
			'JSON array'             => [ static fn( array $c ): string => '[1,2]' ],
			'type missing'           => [ static fn( array $c ): array => array_diff_key( $c, [ 'type' => 1 ] ) ],
			'type not public-key'    => [ static fn( array $c ): array => [ 'type' => 'password' ] + $c ],
			'id missing'             => [ static fn( array $c ): array => array_diff_key( $c, [ 'id' => 1 ] ) ],
			'rawId as array'         => [ static fn( array $c ): array => [ 'rawId' => [ $c['rawId'] ] ] + $c ],
			'id != rawId'            => [ static fn( array $c ): array => [ 'id' => Base64Url::encode( random_bytes( 32 ) ) ] + $c ],
			'id padded'              => [ static fn( array $c ): array => [ 'id' => $c['id'] . '=' ] + $c ],
			'id standard base64'     => [ static fn( array $c ): array => [ 'id' => strtr( $c['id'], '-_', '+/' ) . '+' ] + $c ],
			'id and rawId 15 bytes'  => [ static fn( array $c ): array => ( static fn( string $r ): array => [ 'id' => $r, 'rawId' => $r ] + $c )( Base64Url::encode( random_bytes( 15 ) ) ) ],
			'nesting deeper than 6'  => [ static fn( array $c ): array => [ 'deep' => [ [ [ [ [ [ 1 ] ] ] ] ] ] ] + $c ],
			'non-zero trailing bits' => [ static fn( array $c ): array => [ 'id' => self::trailing_bits( $c['id'] ) ] + $c ],
		];
	}

	/** $b64 (32 bytes, 43 chars) with a non-zero padding bit in its last character. */
	private static function trailing_bits( string $b64 ): string {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
		$last     = (int) strpos( $alphabet, substr( $b64, -1 ) );
		return substr( $b64, 0, -1 ) . $alphabet[ $last | 1 ];
	}

	/**
	 * 11, 12, 13: R-1 and R-2 failures carry no flag (no trusted credential ID).
	 *
	 * @dataProvider malformed_before_r2
	 */
	public function test_malformed_before_r2_has_no_flag( \Closure $mutate ): void {
		$credential = Ceremony::decode( Ceremony::registration( new SoftAuthenticator(), $this->user ) );
		$mutated    = $mutate( $credential );
		$this->assert_failed( $this->verify( is_string( $mutated ) ? $mutated : Ceremony::encode( $mutated ) ), 'registration_failed', 400, false );
	}

	public function test_credential_id_length_limits(): void {
		$this->assert_failed( $this->register( new SoftAuthenticator( 'ES256', [ 'credential_id' => random_bytes( 1024 ) ] ) ), 'registration_failed', 400, false, '1024 bytes' );
		$this->assertIsArray( $this->register( new SoftAuthenticator( 'ES256', [ 'credential_id' => random_bytes( 1023 ) ] ) ), '1023 bytes' );
		$this->assertIsArray( $this->register( new SoftAuthenticator( 'ES256', [ 'credential_id' => random_bytes( 16 ) ] ) ), '16 bytes' );
	}

	/** 19: rawId equal to id but not the ID in authData (R-7). */
	public function test_raw_id_must_match_the_attested_credential_id(): void {
		$other = Base64Url::encode( random_bytes( 32 ) );
		$this->assert_failed(
			$this->register(
				new SoftAuthenticator(),
				[
					'id'    => $other,
					'rawId' => $other,
				]
			),
			'registration_failed',
			400,
			true
		);
	}

	public function test_response_members_are_strict(): void {
		$auth = new SoftAuthenticator();
		$base = Ceremony::decode( Ceremony::registration( $auth, $this->user ) );

		$cases = [
			'response missing'           => array_diff_key( $base, [ 'response' => 1 ] ),
			'clientDataJSON padded'      => array_replace_recursive( $base, [ 'response' => [ 'clientDataJSON' => $base['response']['clientDataJSON'] . '=' ] ] ),
			'attestationObject + and /'  => array_replace_recursive( $base, [ 'response' => [ 'attestationObject' => strtr( $base['response']['attestationObject'], '-_', '+/' ) . '/+' ] ] ),
			'clientDataJSON as a number' => array_replace_recursive( $base, [ 'response' => [ 'clientDataJSON' => 5 ] ] ),
			'attestationObject empty'    => array_replace_recursive( $base, [ 'response' => [ 'attestationObject' => '' ] ] ),
		];
		foreach ( $cases as $label => $credential ) {
			$this->assert_failed( $this->verify( Ceremony::encode( $credential ) ), 'registration_failed', 400, true, $label );
		}
	}

	/** @return array<string,array{\Closure}> */
	public static function client_data_rejections(): array {
		$o = SoftAuthenticator::OMIT;
		return [
			'not JSON'                 => [ static fn( array $opt ): array => [ 'clientDataJSON' => 'not json' ] ],
			'JSON array'               => [ static fn( array $opt ): array => [ 'clientDataJSON' => '["webauthn.create"]' ] ],
			'BOM'                      => [ static fn( array $opt ): array => [ 'bom' => true ] ],
			'invalid UTF-8'            => [ static fn( array $opt ): array => [ 'clientDataJSON' => '{"type":"webauthn.create","challenge":"' . $opt['challenge'] . '","origin":"' . Ceremony::ORIGIN . "\",\"x\":\"\xff\"}" ] ],
			'depth over 4'             => [ static fn( array $opt ): array => [ 'clientData' => [ 'deep' => [ [ [ [ 1 ] ] ] ] ] ] ],
			'type missing'             => [ static fn( array $opt ): array => [ 'clientData' => [ 'type' => $o ] ] ],
			'type webauthn.get'        => [ static fn( array $opt ): array => [ 'type' => 'webauthn.get' ] ],
			'challenge not a string'   => [ static fn( array $opt ): array => [ 'challenge' => 12345 ] ],
			'challenge junk chars'     => [ static fn( array $opt ): array => [ 'challenge' => '!!' . $opt['challenge'] . '**' ] ],
			'challenge padded'         => [ static fn( array $opt ): array => [ 'challenge' => $opt['challenge'] . '=' ] ],
			'challenge 31 bytes'       => [ static fn( array $opt ): array => [ 'challenge' => Base64Url::encode( random_bytes( 31 ) ) ] ],
			'challenge 33 bytes'       => [ static fn( array $opt ): array => [ 'challenge' => Base64Url::encode( random_bytes( 33 ) ) ] ],
			'origin array'             => [ static fn( array $opt ): array => [ 'origin' => [ Ceremony::ORIGIN ] ] ],
			'origin foreign'           => [ static fn( array $opt ): array => [ 'origin' => 'https://evil.example' ] ],
			'origin subdomain'         => [ static fn( array $opt ): array => [ 'origin' => 'https://x.academy.example.com' ] ],
			'origin other port'        => [ static fn( array $opt ): array => [ 'origin' => Ceremony::ORIGIN . ':8443' ] ],
			'origin http'              => [ static fn( array $opt ): array => [ 'origin' => 'http://academy.example.com' ] ],
			'origin upper case'        => [ static fn( array $opt ): array => [ 'origin' => 'https://Academy.example.com' ] ],
			'crossOrigin true'         => [ static fn( array $opt ): array => [ 'crossOrigin' => true ] ],
			'crossOrigin "true"'       => [ static fn( array $opt ): array => [ 'crossOrigin' => 'true' ] ],
			'crossOrigin 1'            => [ static fn( array $opt ): array => [ 'crossOrigin' => 1 ] ],
			'topOrigin, crossOrigin f' => [ static fn( array $opt ): array => [ 'topOrigin' => Ceremony::ORIGIN ] ],
		];
	}

	/**
	 * 14: every T-CD rejection; after R-2, so flagged.
	 *
	 * @dataProvider client_data_rejections
	 */
	public function test_client_data_rejections( \Closure $overrides ): void {
		$this->assert_failed( $this->register( new SoftAuthenticator(), $overrides ), 'registration_failed', 400, true );
	}

	/** A rejected clientData burns nothing: the challenge stays usable (R-4 runs before R-5). */
	public function test_client_data_failure_does_not_consume_the_challenge(): void {
		$auth   = new SoftAuthenticator();
		$issued = Ceremony::register_options( $this->user );
		$bad    = Ceremony::encode( $auth->register( $issued['options'], Ceremony::ORIGIN, [ 'crossOrigin' => true ] ) );
		$this->assert_failed( $this->verify( $bad ), 'registration_failed', 400, true );
		$this->assertIsArray( $this->verify( Ceremony::encode( $auth->register( $issued['options'], Ceremony::ORIGIN ) ) ) );
	}

	/* ------------------------------------------------------------------ 15 to 23: authenticator data */

	/** @return array<string,array{array<string,mixed>}> */
	public static function attestation_rejections(): array {
		return [
			'fido-u2f'                  => [ [ 'fmt' => 'fido-u2f', 'attStmt' => [ 'sig' => Cbor::bytes( 'x' ), 'x5c' => [ Cbor::bytes( 'c' ) ] ] ] ],
			'tpm'                       => [ [ 'fmt' => 'tpm', 'attStmt' => [ 'ver' => '2.0' ] ] ],
			'packed with x5c'           => [ [ 'self_attest' => true, 'attStmt' => [ 'x5c' => [ Cbor::bytes( 'cert' ) ] ] ] ],
			'none with attStmt'         => [ [ 'attStmt' => [ 'sig' => Cbor::bytes( 'x' ) ] ] ],
			'self: bad sig'             => [ [ 'fmt' => 'packed', 'attStmt' => [ 'alg' => -7, 'sig' => Cbor::bytes( random_bytes( 70 ) ) ] ] ],
			'self: alg differs'         => [ [ 'self_attest' => true, 'attStmt' => [ 'alg' => -257 ] ] ],
			'self: extra key'           => [ [ 'self_attest' => true, 'attStmt' => [ 'ecdaaKeyId' => Cbor::bytes( 'k' ) ] ] ],
			'rpIdHash of example.com'    => [ [ 'rpId' => 'example.com' ] ],
			'UP=0'                      => [ [ 'flags' => SoftAuthenticator::FLAG_UV | SoftAuthenticator::FLAG_AT ] ],
			'UV=0'                      => [ [ 'flags' => SoftAuthenticator::FLAG_UP | SoftAuthenticator::FLAG_AT ] ],
			'BS=1 with BE=0'            => [ [ 'flags' => SoftAuthenticator::FLAG_UP | SoftAuthenticator::FLAG_UV | SoftAuthenticator::FLAG_BS | SoftAuthenticator::FLAG_AT ] ],
			'AT missing'                => [ [ 'flags' => SoftAuthenticator::FLAG_UP | SoftAuthenticator::FLAG_UV ] ],
			'trailing bytes, ED=0'      => [ [ 'append_authdata' => "\x00" ] ],
			'alg -35 (ES384)'           => [ [ 'cose' => [ 3 => -35 ] ] ],
			'off-curve point'           => [ [ 'cose' => [ -2 => Cbor::bytes( str_repeat( "\x01", 32 ) ), -3 => Cbor::bytes( str_repeat( "\x01", 32 ) ) ] ] ],
			'COSE missing x'            => [ [ 'cose' => [ -2 => SoftAuthenticator::OMIT ] ] ],
			'y as a CBOR boolean'       => [ [ 'cose' => [ -3 => true ] ] ],
			'x as a text string'        => [ [ 'cose' => [ -2 => str_repeat( 'x', 32 ) ] ] ],
			'kty as text'               => [ [ 'cose' => [ 1 => '2' ] ] ],
			'credProps.rk false'        => [ [ 'credProps_rk' => false ] ],
		];
	}

	/**
	 * 15, 15c, 16, 17, 18, 20 (ES256 cases), 22, 23: rejected with the flag,
	 * nothing stored, no warning or deprecation.
	 *
	 * @dataProvider attestation_rejections
	 * @param array<string,mixed> $o
	 */
	public function test_authenticator_data_rejections( array $o ): void {
		$this->assert_failed( $this->register( new SoftAuthenticator( 'ES256' ), $o ), 'registration_failed', 400, true );
		$this->assertSame( 0, Ceremony::count_rows() );
	}

	/** 15c: non-zero AAGUID and a signature over another clientData hash. */
	public function test_self_attestation_needs_zero_aaguid_and_this_client_data(): void {
		$auth = new SoftAuthenticator( 'ES256', [ 'aaguid' => str_repeat( "\x11", 16 ) ] );
		$this->assert_failed( $this->register( $auth, [ 'self_attest' => true ] ), 'registration_failed', 400, true, 'AAGUID' );

		$auth = new SoftAuthenticator( 'ES256' );
		$this->assert_failed(
			$this->register(
				$auth,
				static function () use ( $auth ): array {
					return [
						'fmt'     => 'packed',
						'attStmt' => [
							'alg' => -7,
							'sig' => Cbor::bytes( $auth->sign( 'authData' . hash( 'sha256', 'other client data', true ) ) ),
						],
					];
				}
			),
			'registration_failed',
			400,
			true,
			'signature over another clientData hash'
		);
	}

	/** 20: -8 when not offered, RSA 3072, duplicate COSE label, text label "3". */
	public function test_cose_rejections_beyond_es256(): void {
		$eddsa = new SoftAuthenticator( 'EdDSA' );
		$this->assert_failed( $this->verify( Ceremony::registration( $eddsa, $this->user, [], Ceremony::SESSION, '-7,-257' ) ), 'registration_failed', 400, true, '-8 not offered' );

		$rsa = new SoftAuthenticator( 'RS256' );
		$this->assert_failed( $this->register( $rsa, [ 'cose' => [ -1 => Cbor::bytes( "\xc1" . random_bytes( 383 ) ) ] ] ), 'registration_failed', 400, true, 'RSA 3072' );

		$es   = new SoftAuthenticator( 'ES256' );
		$dupe = "\xa6";
		foreach ( $es->coseKey() as $label => $value ) {
			$dupe .= Cbor::encode( $label ) . Cbor::encode( $value );
		}
		$dupe .= Cbor::encode( 3 ) . Cbor::encode( -7 );
		$this->assert_failed( $this->register( $es, [ 'cose' => static fn() => Cbor::raw( $dupe ) ] ), 'registration_failed', 400, true, 'duplicate COSE label' );

		$cose = $es->coseKey();
		$text = "\xa5";
		foreach ( $cose as $label => $value ) {
			$text .= Cbor::encode( 3 === $label ? '3' : $label ) . Cbor::encode( $value );
		}
		$this->assert_failed( $this->register( $es, [ 'cose' => static fn() => Cbor::raw( $text ) ] ), 'registration_failed', 400, true, 'text label "3"' );
	}

	public function test_credprops_absent_or_true_is_accepted(): void {
		$this->assertIsArray( $this->register( new SoftAuthenticator(), [ 'credProps_rk' => null ] ), 'absent' );
		$this->assertIsArray( $this->register( new SoftAuthenticator(), [ 'credProps_rk' => true ] ), 'true' );
		$this->assertIsArray( $this->register( new SoftAuthenticator(), [ 'credProps_rk' => 'false' ] ), 'not the boolean false' );
	}

	/* ------------------------------------------------------------------ 24, 24b: R-13 */

	public function test_duplicate_credential_is_never_flagged(): void {
		global $wpdb;
		$auth = new SoftAuthenticator();
		Ceremony::enrol( $auth, $this->user );

		foreach ( [ $this->user, Ceremony::user( 8 ) ] as $user ) {
			$record = $this->verify( Ceremony::registration( $auth, $user ), $user );
			$this->assertIsArray( $record );
			$wpdb->show_errors( true );
			ob_start();
			$stored = Verifier::store_registration( $record );
			$out    = (string) ob_get_clean();
			$wpdb->show_errors( false );
			$this->assertSame( '', $out );
			$this->assert_failed( $stored, 'registration_failed', 400, false, 'user ' . $user->ID );
		}
		$this->assertSame( 1, Ceremony::count_rows() );
	}

	/** @return array<string,array{string}> */
	public static function store_errors(): array {
		return [
			'duplicate SELECT' => [ 'SELECT * FROM wp_magicauth_passkeys WHERE credential_hash' ],
			'INSERT'           => [ 'INSERT INTO wp_magicauth_passkeys' ],
		];
	}

	/** @dataProvider store_errors */
	public function test_store_database_error_is_retry_without_flag( string $pattern ): void {
		global $wpdb;
		$record = $this->register( new SoftAuthenticator() );
		$this->assertIsArray( $record );
		$wpdb->fail_next_query( $pattern );
		$wpdb->show_errors( true );
		ob_start();
		$stored = Verifier::store_registration( $record );
		$out    = (string) ob_get_clean();
		$wpdb->show_errors( false );
		$this->assertSame( '', $out );
		$this->assert_failed( $stored, 'retry', 503, false );
	}

	public function test_store_rejects_a_record_that_was_not_verified(): void {
		$record                  = $this->register( new SoftAuthenticator() );
		$this->assertIsArray( $record );
		$record['alg']           = -35;
		$this->assert_failed( Verifier::store_registration( $record ), 'registration_failed', 400, false );
		$this->assertSame( 0, Ceremony::count_rows() );
	}

	/* ------------------------------------------------------------------ 26, 27, 30, 31 */

	public function test_transports_are_filtered_and_capped(): void {
		$record = $this->register(
			new SoftAuthenticator(),
			[ 'transports' => [ 'usb', 'bogus', 'nfc', 'usb', 7, [ 'ble' ], 'NFC', 'hybrid', 'internal', 'ble' ] ]
		);
		$this->assertIsArray( $record );
		// Only the first 8 inputs count: 'internal' (9th) and 'ble' (10th) are ignored.
		$this->assertSame( 'usb,nfc,hybrid', $record['transports'] );

		$this->assertSame( '', $this->register( new SoftAuthenticator(), [ 'transports' => 'usb' ] )['transports'] ?? null );
		$this->assertSame( 'smart-card,ble', $this->register( new SoftAuthenticator(), [ 'transports' => [ 'smart-card', 'ble' ] ] )['transports'] ?? null );
	}

	/** @return array<string,array{string,string}> */
	public static function names(): array {
		return [
			'markup'          => [ '<b>Work</b> laptop<script>x</script>', 'Work laptop' ],
			'bidi override'   => [ "abc\u{202E}gpj.exe", 'abcgpj.exe' ],
			'bidi marks'      => [ "a\u{200E}b\u{200F}c\u{2066}d\u{2069}", 'abcd' ],
			'controls'        => [ "a\x07b\u{0085}c", 'abc' ],
			'200 characters'  => [ str_repeat( 'n', 200 ), str_repeat( 'n', 64 ) ],
			'emoji (utf8mb4)' => [ "Phone \u{1F4F1}", "Phone \u{1F4F1}" ],
			'whitespace'      => [ "  two\n\nlines  ", 'two lines' ],
			'only markup'     => [ '<i></i>', 'Passkey' ],
		];
	}

	/** @dataProvider names */
	public function test_name_is_sanitised( string $raw, string $expected ): void {
		$record = $this->verify( Ceremony::registration( new SoftAuthenticator(), $this->user ), null, Ceremony::SESSION, $raw );
		$this->assertIsArray( $record );
		$this->assertSame( $expected, $record['name'] );
		$this->assertIsInt( Verifier::store_registration( $record ) );
	}

	public function test_emoji_is_removed_under_utf8(): void {
		global $wpdb;
		$wpdb->charset = 'utf8';
		try {
			$record = $this->verify( Ceremony::registration( new SoftAuthenticator(), $this->user ), null, Ceremony::SESSION, "Phone \u{1F4F1}" );
		} finally {
			$wpdb->charset = 'utf8mb4';
		}
		$this->assertIsArray( $record );
		$this->assertSame( 'Phone', $record['name'] );
	}

	/** 27: a user-chosen name equal (case-insensitive) to another passkey of the user. */
	public function test_duplicate_chosen_name_is_rejected(): void {
		$first = $this->verify( Ceremony::registration( new SoftAuthenticator(), $this->user ), null, Ceremony::SESSION, 'Work Laptop' );
		$this->assertIsArray( $first );
		Verifier::store_registration( $first );

		$this->assert_failed(
			$this->verify( Ceremony::registration( new SoftAuthenticator(), $this->user ), null, Ceremony::SESSION, 'work laptop' ),
			'duplicate_name',
			400,
			true
		);
		// Another user may use the same name.
		$other = Ceremony::user( 8 );
		$this->assertIsArray( $this->verify( Ceremony::registration( new SoftAuthenticator(), $other ), $other, Ceremony::SESSION, 'Work Laptop' ) );
	}

	/** 30: the stored handle is the challenge row's, never a fresh meta read. */
	public function test_stored_handle_is_the_one_sent_in_the_options(): void {
		$auth   = new SoftAuthenticator();
		$issued = Ceremony::register_options( $this->user );
		update_user_meta( 7, CredentialStore::HANDLE_META, Base64Url::encode( random_bytes( 64 ) ) );

		$record = $this->verify( Ceremony::encode( $auth->register( $issued['options'], Ceremony::ORIGIN ) ) );
		$this->assertIsArray( $record );
		$this->assertSame( $issued['handle'], $record['user_handle'] );
		$this->assertSame( $issued['options']['user']['id'], $record['user_handle'] );
	}

	/** 31 and 4.8: default names. */
	public function test_default_names(): void {
		$ipados = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15';
		$win    = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36';
		$cases  = [
			[ 'iPad', $ipados, 'Passkey on iPad' ],
			[ 'Gameboy', $win, 'Passkey on Windows' ],
			[ 'ipad', $ipados, 'Passkey on Mac' ],
			[ '', 'curl/8.0', 'Passkey' ],
		];
		foreach ( $cases as $i => [ $hint, $ua, $expected ] ) {
			$user   = Ceremony::user( 20 + $i );
			$record = $this->verify( Ceremony::registration( new SoftAuthenticator(), $user ), $user, Ceremony::SESSION, '', $hint, $ua );
			$this->assertIsArray( $record );
			$this->assertSame( $expected, $record['name'], "hint {$hint}" );
		}

		// Known AAGUID: the provider name; repeated defaults get (2), (3).
		$google = hex2bin( 'ea9b8d664d011d213ce4b6b48cb575d4' );
		for ( $n = 1; $n <= 3; $n++ ) {
			$record = $this->verify( Ceremony::registration( new SoftAuthenticator( 'ES256', [ 'aaguid' => $google ] ), $this->user ), null, Ceremony::SESSION, '', 'iPad', $ipados );
			$this->assertIsArray( $record );
			$this->assertSame( 1 === $n ? 'Google Password Manager' : "Google Password Manager ({$n})", $record['name'] );
			$this->assertSame( 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4', $record['aaguid'] );
			Verifier::store_registration( $record );
		}
	}

	/* ------------------------------------------------------------------ 29, 29b, 29c: orphan flag */

	/**
	 * 29: throttled at the endpoint: flag from the final SELECT, only for an
	 * unconsumed register challenge of this user and session, which the
	 * check consumes (r1-endpoints-04: no unlimited credential-ID oracle).
	 */
	public function test_flag_for_failures_outside_the_verifier(): void {
		$auth       = new SoftAuthenticator();
		$credential = Ceremony::registration( $auth, $this->user );
		$this->assertTrue( Verifier::unknown_credential_flag( $credential, $this->user, Ceremony::SESSION ) );
		$this->assertFalse( Verifier::unknown_credential_flag( $credential, $this->user, Ceremony::SESSION ), 'challenge consumed by the first check' );
		$this->assertFalse( Verifier::unknown_credential_flag( 'garbage', $this->user, Ceremony::SESSION ), 'no trusted ID' );

		Ceremony::enrol( $auth, $this->user );
		$this->assertFalse( Verifier::unknown_credential_flag( Ceremony::registration( $auth, $this->user ), $this->user, Ceremony::SESSION ), 'stored credential' );

		global $wpdb;
		$wpdb->fail_next_query( 'SELECT * FROM wp_magicauth_passkeys WHERE credential_hash' );
		$this->assertInstanceOf( WP_Error::class, Verifier::unknown_credential_flag( Ceremony::registration( new SoftAuthenticator(), $this->user ), $this->user, Ceremony::SESSION ) );
		$wpdb->fail_next_query( 'SELECT * FROM wp_magicauth_passkey_challenges' );
		$this->assertInstanceOf( WP_Error::class, Verifier::unknown_credential_flag( Ceremony::registration( new SoftAuthenticator(), $this->user ), $this->user, Ceremony::SESSION ) );
	}

	/** r1-endpoints-04: no lookup unless the challenge is this user's and session's. */
	public function test_throttled_flag_needs_an_owned_challenge_and_does_no_lookup_otherwise(): void {
		global $wpdb;
		$other = Ceremony::user( 8 );
		$cases = [
			'other session'    => [ Ceremony::registration( new SoftAuthenticator(), $this->user ), $this->user, str_repeat( 'b', 64 ) ],
			'other user'       => [ Ceremony::registration( new SoftAuthenticator(), $other ), $this->user, Ceremony::SESSION ],
			'never issued'     => [
				Ceremony::encode(
					( new SoftAuthenticator() )->register(
						array_merge( Ceremony::register_options( $this->user, Ceremony::SESSION )['options'], [ 'challenge' => Base64Url::encode( random_bytes( 32 ) ) ] ),
						Ceremony::ORIGIN
					)
				),
				$this->user,
				Ceremony::SESSION,
			],
			'bad clientData'   => [ (string) json_encode( [ 'type' => 'public-key', 'id' => Base64Url::encode( random_bytes( 16 ) ), 'rawId' => Base64Url::encode( random_bytes( 16 ) ), 'response' => [ 'clientDataJSON' => 'e30' ] ] ), $this->user, Ceremony::SESSION ],
		];
		foreach ( $cases as $label => [ $credential, $user, $session ] ) {
			$wpdb->query_log = [];
			$this->assertFalse( Verifier::unknown_credential_flag( $credential, $user, $session ), $label );
			foreach ( $wpdb->query_log as $sql ) {
				$this->assertStringNotContainsString( 'wp_magicauth_passkeys ', (string) $sql . ' ', "{$label}: no credential lookup" );
			}
		}
	}

	/** 29b: a replay of a registration that succeeded is never flagged. */
	public function test_replay_after_success_is_not_flagged(): void {
		$credential = Ceremony::registration( new SoftAuthenticator(), $this->user );
		$record     = $this->verify( $credential );
		$this->assertIsArray( $record );
		$this->assertIsInt( Verifier::store_registration( $record ) );

		$this->assert_failed( $this->verify( $credential ), 'registration_failed', 400, false );
	}

	/** 29b: the first request still in flight (challenge consumed, row not inserted yet). */
	public function test_replay_while_the_first_is_in_flight_is_not_flagged(): void {
		$credential = Ceremony::registration( new SoftAuthenticator(), $this->user );
		$this->assertIsArray( $this->verify( $credential ) );
		$this->assertSame( 0, Ceremony::count_rows() );

		$this->assert_failed( $this->verify( $credential ), 'registration_failed', 400, false );
	}

	/** @return array<string,array{string}> */
	public static function flag_query_errors(): array {
		return [
			'consume SELECT' => [ 'SELECT * FROM wp_magicauth_passkey_challenges' ],
			'consume UPDATE' => [ 'UPDATE wp_magicauth_passkey_challenges' ],
		];
	}

	/**
	 * 29c: errors in the challenge step are 503 retry without the flag.
	 *
	 * @dataProvider flag_query_errors
	 */
	public function test_challenge_query_error_is_retry_without_flag( string $pattern ): void {
		global $wpdb;
		$credential = Ceremony::registration( new SoftAuthenticator(), $this->user );
		$wpdb->fail_next_query( $pattern );
		$this->assert_failed( $this->verify( $credential ), 'retry', 503, false );
	}

	/** 29c: a failed final SELECT turns a flaggable failure into 503 retry without the flag. */
	public function test_final_select_error_is_retry_without_flag(): void {
		global $wpdb;
		$credential = Ceremony::registration( new SoftAuthenticator(), $this->user, [ 'credProps_rk' => false ] );
		$wpdb->fail_next_query( 'SELECT * FROM wp_magicauth_passkeys WHERE credential_hash' );
		$this->assert_failed( $this->verify( $credential ), 'retry', 503, false );
	}

	/** A credential stored for anyone is never flagged, whatever the failure. */
	public function test_failure_for_a_stored_credential_is_not_flagged(): void {
		$auth = new SoftAuthenticator();
		Ceremony::enrol( $auth, Ceremony::user( 8 ) );
		$this->assert_failed( $this->register( $auth, [ 'credProps_rk' => false ] ), 'registration_failed', 400, false );
	}

	/* ------------------------------------------------------------------ 28: W9 */

	/** @return array<string,array{string}> */
	public static function throwables(): array {
		return [
			'TypeError'       => [ 'TypeError' ],
			'SodiumException' => [ 'SodiumException' ],
			'Error'           => [ 'Error' ],
		];
	}

	/**
	 * 28: whatever the library throws (here from inside its Ed25519 self
	 * attestation check), the result is the generic failure; nothing printed.
	 *
	 * @dataProvider throwables
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_library_throwable_gives_the_generic_failure( string $class ): void {
		require_once dirname( __DIR__ ) . '/Support/library-throws.php';
		Ceremony::site();
		$user                                = Ceremony::user( 7 );
		$credential                          = Ceremony::registration( new SoftAuthenticator( 'EdDSA' ), $user, [ 'self_attest' => true ] );
		$GLOBALS['magicauth_library_throw'] = new $class( 'boom <b>' );
		ob_start();
		$result = Verifier::verify_registration( $credential, $user, Ceremony::SESSION );
		$out    = (string) ob_get_clean();
		unset( $GLOBALS['magicauth_library_throw'] );

		$this->assertSame( '', $out );
		$this->assert_failed( $result, 'registration_failed', 400, true );
	}
}
