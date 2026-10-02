<?php
/**
 * T-AUTH at the verifier level (SPEC 7.4, 7.6, 15 step 9: cases 6 to 16d,
 * 20, 21, 8b, 8c plus the happy paths): Verifier::verify_assertion() with
 * SoftAuthenticator credentials enrolled through the registration verifier,
 * against real signin challenge rows bound to a binding cookie, under MySQL
 * changed-rows semantics. Endpoint gates, throttling, jitter, the completion
 * token and the redirect come with build step 12. The counter cases run in
 * the real-database suite too (group realdb).
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Passkeys\Base64Url;
use MagicAuth\Passkeys\ChallengeStore;
use MagicAuth\Passkeys\Clock;
use MagicAuth\Passkeys\CredentialStore;
use MagicAuth\Passkeys\Options;
use MagicAuth\Passkeys\Verifier;
use MagicAuth\Tests\Support\Ceremony;
use MagicAuth\Tests\Support\Cbor;
use MagicAuth\Tests\Support\Fixtures;
use MagicAuth\Tests\Support\SoftAuthenticator;
use PHPUnit\Framework\TestCase;
use WP_Error;
use WP_User;

final class SignInVerifierTest extends TestCase {

	private const UP_UV = SoftAuthenticator::FLAG_UP | SoftAuthenticator::FLAG_UV;

	private WP_User $user;

	protected function setUp(): void {
		Ceremony::site();
		$this->user = Ceremony::user( 7 );
	}

	protected function tearDown(): void {
		magicauth_test_reset_state();
	}

	/**
	 * verify_assertion() with output captured: nothing may be printed.
	 *
	 * @return array{user:WP_User,row:object}|WP_Error
	 */
	private function verify( string $credential, string $cookie = Ceremony::COOKIE ) {
		global $wpdb;
		$wpdb->show_errors( true );
		ob_start();
		try {
			$result = Verifier::verify_assertion( $credential, $cookie );
		} finally {
			$out = (string) ob_get_clean();
			$wpdb->show_errors( false );
		}
		$this->assertSame( '', $out, 'nothing printed' );
		return $result;
	}

	/**
	 * @param mixed $result
	 * @return array<string,mixed> The error data.
	 */
	private function assert_failed( $result, string $reason, bool $counted, bool $flag = false, string $code = 'passkey_failed', int $status = 400 ): array {
		$this->assertInstanceOf( WP_Error::class, $result, $reason );
		$this->assertSame( $code, $result->get_error_code(), $reason );
		$data = $result->get_error_data();
		$this->assertIsArray( $data );
		$this->assertSame( $status, $data['status'], $reason );
		$this->assertSame( $reason, $data['reason'] );
		$this->assertSame( $counted, $data['counted'], $reason . ': counted' );
		$this->assertSame( $flag, $data['unknown_credential'], $reason . ': unknown_credential' );
		return $data;
	}

	/** @param mixed $result */
	private function assert_signed_in( $result, int $user_id = 7 ): void {
		$this->assertIsArray( $result, $result instanceof WP_Error ? $result->get_error_code() . ' ' . print_r( $result->get_error_data(), true ) : '' );
		$this->assertSame( $user_id, (int) $result['user']->ID );
		$this->assertSame( $user_id, (int) $result['row']->user_id );
	}

	/** Enrolled authenticator (device-bound unless $opts says otherwise). */
	private function enrolled( string $alg = 'ES256', array $opts = [] ): SoftAuthenticator {
		$auth = new SoftAuthenticator(
			$alg,
			$opts + [
				'be' => false,
				'bs' => false,
			]
		);
		Ceremony::enrol( $auth, $this->user );
		return $auth;
	}

	/** Consumes the challenge to find out: 'replayed' means an earlier consume happened. */
	private static function challenge_consumed( string $challenge_b64 ): bool {
		$reason = null;
		ChallengeStore::consume( 'signin', (string) Base64Url::decode( $challenge_b64, 32, 32 ), $reason );
		return 'replayed' === $reason;
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
	public function test_signs_in_and_records_use( string $alg ): void {
		$auth = $this->enrolled( $alg, [ 'sign_count' => 4 ] );
		Clock::set_for_tests( Ceremony::NOW + 30 );

		$result = $this->verify( Ceremony::assertion( $auth ) );
		$this->assert_signed_in( $result );

		$row = Ceremony::row( (int) $result['row']->id );
		$this->assertSame( '5', (string) $row['sign_count'], 'counter raised by CAS' );
		$this->assertSame( gmdate( 'Y-m-d H:i:s', Ceremony::NOW + 30 ), $row['last_used_at'] );
		$this->assertNull( $row['counter_anomaly_at'] );
	}

	public function test_backup_state_is_recorded(): void {
		$auth = $this->enrolled(
			'ES256',
			[
				'be' => true,
				'bs' => false,
			]
		);
		$result = $this->verify( Ceremony::assertion( $auth, [ 'flags' => self::UP_UV | SoftAuthenticator::FLAG_BE | SoftAuthenticator::FLAG_BS ] ) );
		$this->assert_signed_in( $result );
		$this->assertSame( '1', (string) Ceremony::row( (int) $result['row']->id )['backup_state'] );
	}

	public function test_signin_needs_no_session(): void {
		// Logged out, no session token: the verifier never reads either.
		$this->assert_signed_in( $this->verify( Ceremony::assertion( $this->enrolled() ) ) );
	}

	/* ------------------------------------------------------------------ A-3: binding (login CSRF) */

	public function test_binding_cookie_is_required(): void {
		$auth = $this->enrolled();
		foreach ( [ '', 'not-hex', strtoupper( Ceremony::COOKIE ), str_repeat( 'f', 64 ) ] as $cookie ) {
			$credential = Ceremony::assertion( $auth );
			$this->assert_failed( $this->verify( $credential, $cookie ), 'binding', false );
			// Consumed whatever the outcome: the right cookie cannot use it afterwards.
			$this->assert_failed( $this->verify( $credential ), 'challenge', false );
		}
	}

	public function test_challenge_states(): void {
		$auth = $this->enrolled();

		$credential = Ceremony::assertion( $auth );
		$this->assert_signed_in( $this->verify( $credential ) );
		$this->assert_failed( $this->verify( $credential ), 'challenge', false, false, 'passkey_failed', 400 );

		$credential = Ceremony::assertion( $auth );
		Clock::set_for_tests( Ceremony::NOW + ChallengeStore::TTL['signin'] );
		$this->assert_failed( $this->verify( $credential ), 'challenge', false );

		Clock::set_for_tests( Ceremony::NOW );
		$this->assert_failed( $this->verify( Ceremony::assertion( $auth, [ 'challenge' => Base64Url::encode( random_bytes( 32 ) ) ] ) ), 'challenge', false );

		// A register challenge is not a signin challenge.
		$issued = Ceremony::register_options( $this->user );
		$this->assert_failed( $this->verify( Ceremony::assertion( $auth, [ 'challenge' => $issued['options']['challenge'] ] ) ), 'challenge', false );
	}

	/** @return array<string,array{string}> */
	public static function consume_errors(): array {
		return [
			'SELECT' => [ 'SELECT * FROM wp_magicauth_passkey_challenges' ],
			'UPDATE' => [ 'UPDATE wp_magicauth_passkey_challenges' ],
		];
	}

	/** @dataProvider consume_errors */
	public function test_challenge_query_error_is_retry( string $pattern ): void {
		global $wpdb;
		$credential = Ceremony::assertion( $this->enrolled() );
		$wpdb->fail_next_query( $pattern );
		$this->assert_failed( $this->verify( $credential ), 'error', false, false, 'retry', 503 );
	}

	/* ------------------------------------------------------------------ 6, 7: caps and shape (A-1) */

	public function test_size_caps_and_the_at_flag_are_checked_before_anything_is_decoded(): void {
		$auth = $this->enrolled();

		$cases = [
			'authData 1025 bytes' => static fn( array $o ): array => [ 'authData' => hash( 'sha256', Ceremony::RP, true ) . chr( self::UP_UV ) . pack( 'N', 9 ) . str_repeat( "\0", 1025 - 37 ) ],
			'authData 36 bytes'   => static fn( array $o ): array => [ 'authData' => str_repeat( "\0", 36 ) ],
			'AT flag set'         => static fn( array $o ): array => [ 'flags' => self::UP_UV | SoftAuthenticator::FLAG_AT ],
			'signature 513 bytes' => static fn( array $o ): array => [ 'signature' => random_bytes( 513 ) ],
			'signature empty'     => static fn( array $o ): array => [ 'signature' => '' ],
			'clientData 4097'     => static fn( array $o ): array => [ 'clientData' => [ 'pad' => str_repeat( 'p', 4100 ) ] ],
		];
		foreach ( $cases as $label => $overrides ) {
			$options    = Ceremony::signin_options();
			$credential = Ceremony::encode( $auth->assert( $options, Ceremony::ORIGIN, $overrides( $options ) ) );
			$this->assert_failed( $this->verify( $credential ), 'malformed', false );
			$this->assertFalse( self::challenge_consumed( $options['challenge'] ), $label . ': rejected before A-3' );
		}
	}

	/** 6: the measured 100 KB ED-flag CBOR bomb never reaches the decoder. */
	public function test_extension_depth_bomb_is_rejected_unread(): void {
		$auth = $this->enrolled();
		$bomb = hash( 'sha256', Ceremony::RP, true ) . chr( self::UP_UV | SoftAuthenticator::FLAG_ED ) . pack( 'N', 1 ) . Cbor::nested_array( 100000 );
		$this->assert_failed( $this->verify( Ceremony::assertion( $auth, [ 'authData' => $bomb ] ) ), 'malformed', false );

		// Even under the field cap, the authData cap (1 KB) stops it.
		$small = hash( 'sha256', Ceremony::RP, true ) . chr( self::UP_UV | SoftAuthenticator::FLAG_ED ) . pack( 'N', 1 ) . Cbor::nested_array( 5000 );
		$json  = Ceremony::assertion( $auth, [ 'authData' => $small ] );
		$this->assertLessThan( Verifier::MAX_CREDENTIAL, strlen( $json ) );
		$this->assert_failed( $this->verify( $json ), 'malformed', false );
	}

	/** @return array<string,array{\Closure}> */
	public static function malformed(): array {
		return [
			'not JSON'           => [ static fn( array $c ): string => '{' ],
			'JSON array'         => [ static fn( array $c ): string => '[]' ],
			'type'               => [ static fn( array $c ): array => [ 'type' => 'public_key' ] + $c ],
			'id != rawId'        => [ static fn( array $c ): array => [ 'rawId' => Base64Url::encode( random_bytes( 32 ) ) ] + $c ],
			'response missing'   => [ static fn( array $c ): array => array_diff_key( $c, [ 'response' => 1 ] ) ],
			'userHandle missing' => [ static fn( array $c ): array => array_replace( $c, [ 'response' => array_diff_key( $c['response'], [ 'userHandle' => 1 ] ) ] ) ],
			'userHandle null'    => [ static fn( array $c ): array => array_replace_recursive( $c, [ 'response' => [ 'userHandle' => null ] ] ) ],
			'userHandle 0 bytes' => [ static fn( array $c ): array => array_replace_recursive( $c, [ 'response' => [ 'userHandle' => '' ] ] ) ],
			'userHandle 65'      => [ static fn( array $c ): array => array_replace_recursive( $c, [ 'response' => [ 'userHandle' => Base64Url::encode( random_bytes( 65 ) ) ] ] ) ],
			'userHandle padded'  => [ static fn( array $c ): array => array_replace_recursive( $c, [ 'response' => [ 'userHandle' => $c['response']['userHandle'] . '=' ] ] ) ],
			'signature as array' => [ static fn( array $c ): array => array_replace_recursive( $c, [ 'response' => [ 'signature' => [ 'x' ] ] ] ) ],
		];
	}

	/**
	 * 7: malformed credentials fail generically, uncounted, unflagged.
	 *
	 * @dataProvider malformed
	 */
	public function test_malformed_credential( \Closure $mutate ): void {
		$credential = Ceremony::decode( Ceremony::assertion( $this->enrolled() ) );
		$mutated    = $mutate( $credential );
		$this->assert_failed( $this->verify( is_string( $mutated ) ? $mutated : Ceremony::encode( $mutated ) ), 'malformed', false );
	}

	/** 20, and the T-CD rejections at A-2. */
	public function test_client_data_is_checked_before_the_challenge(): void {
		$auth  = $this->enrolled();
		$cases = [
			'webauthn.create on get' => [ 'type' => 'webauthn.create' ],
			'foreign origin'         => [ 'origin' => 'https://evil.example' ],
			'crossOrigin true'       => [ 'crossOrigin' => true ],
			'topOrigin'              => [ 'topOrigin' => Ceremony::ORIGIN ],
			'BOM'                    => [ 'bom' => true ],
		];
		foreach ( $cases as $label => $o ) {
			$options = Ceremony::signin_options();
			$this->assert_failed( $this->verify( Ceremony::encode( $auth->assert( $options, Ceremony::ORIGIN, $o ) ) ), 'client_data', false );
			$this->assertFalse( self::challenge_consumed( $options['challenge'] ), $label );
		}
	}

	/* ------------------------------------------------------------------ 8, 8b, 8c: unknown credential (A-4) */

	public function test_unknown_credential_with_an_issued_handle_is_flagged(): void {
		$this->enrolled();
		$handle = (string) CredentialStore::user_handle( 7, false );
		$stray  = new SoftAuthenticator( 'ES256', [ 'user_handle' => (string) Base64Url::decode( $handle, 64, 64 ) ] );

		$data = $this->assert_failed( $this->verify( Ceremony::assertion( $stray ) ), 'unknown_credential', true, true );
		$this->assertSame( 0, $data['user_id'] );
	}

	/** 8c: a handle MagicAuth never issued (another app on the host, a deleted account): no flag. */
	public function test_unknown_credential_with_a_foreign_handle_is_not_flagged(): void {
		$this->enrolled();
		$stray = new SoftAuthenticator( 'ES256', [ 'user_handle' => random_bytes( 64 ) ] );
		$this->assert_failed( $this->verify( Ceremony::assertion( $stray ) ), 'unknown_credential', true, false );
	}

	/** 8: the flag only after the cheap checks passed: a bad origin gives none. */
	public function test_no_flag_before_the_cheap_checks_pass(): void {
		$this->enrolled();
		$stray = new SoftAuthenticator( 'ES256', [ 'user_handle' => (string) Base64Url::decode( (string) CredentialStore::user_handle( 7, false ), 64, 64 ) ] );
		$this->assert_failed( $this->verify( Ceremony::assertion( $stray, [ 'origin' => 'https://evil.example' ] ) ), 'client_data', false, false );
		$this->assert_failed( $this->verify( Ceremony::assertion( $stray ), str_repeat( '9', 64 ) ), 'binding', false, false );
	}

	/** @return array<string,array{string}> */
	public static function lookup_errors(): array {
		return [
			'find_by_raw_id' => [ 'SELECT * FROM wp_magicauth_passkeys WHERE credential_hash' ],
			'handle_issued'  => [ 'SELECT user_id FROM wp_usermeta' ],
		];
	}

	/**
	 * 8b, 8c: a failed lookup is 503 retry: no flag, not counted.
	 *
	 * @dataProvider lookup_errors
	 */
	public function test_lookup_error_is_retry( string $pattern ): void {
		global $wpdb;
		$this->enrolled();
		$stray      = new SoftAuthenticator( 'ES256', [ 'user_handle' => (string) Base64Url::decode( (string) CredentialStore::user_handle( 7, false ), 64, 64 ) ] );
		$credential = Ceremony::assertion( $stray );
		$wpdb->fail_next_query( $pattern );
		$this->assert_failed( $this->verify( $credential ), 'error', false, false, 'retry', 503 );
	}

	/* ------------------------------------------------------------------ 9 to 14 */

	public function test_user_handle_must_match_the_row(): void {
		$auth  = $this->enrolled();
		$other = Ceremony::user( 8 );
		CredentialStore::user_handle( 8, true );
		$foreign = (string) Base64Url::decode( (string) CredentialStore::user_handle( 8, false ), 64, 64 );
		$this->assert_failed( $this->verify( Ceremony::assertion( $auth, [ 'userHandle' => $foreign ] ) ), 'user_handle', true );
		$this->assert_failed( $this->verify( Ceremony::assertion( $auth, [ 'userHandle' => random_bytes( 64 ) ] ) ), 'user_handle', true );
		unset( $other );
	}

	public function test_rp_id_must_match(): void {
		global $wpdb;
		$auth = $this->enrolled();
		$wpdb->query( 'UPDATE ' . CredentialStore::table() . " SET rp_id = 'example.com'" );
		$this->assert_failed( $this->verify( Ceremony::assertion( $auth ) ), 'rp_id', true );
	}

	/** @return array<string,array{string}> */
	public static function signature_algs(): array {
		return [
			'ES256' => [ 'ES256' ],
			'RS256' => [ 'RS256' ],
			'EdDSA' => [ 'EdDSA' ],
		];
	}

	/**
	 * 11: bad signatures fail without an escaping exception.
	 *
	 * @dataProvider signature_algs
	 */
	public function test_bad_signatures( string $alg ): void {
		$auth = $this->enrolled( $alg );

		$this->assert_failed( $this->verify( Ceremony::assertion( $auth, [ 'signature' => random_bytes( 'RS256' === $alg ? 256 : 64 ) ] ) ), 'signature', true );

		// A valid signature over another clientData.
		$options = Ceremony::signin_options();
		$a       = $auth->assert( $options, Ceremony::ORIGIN, [ 'clientData' => [ 'extra' => 'one' ] ] );
		$b       = $auth->assert( $options, Ceremony::ORIGIN, [ 'clientData' => [ 'extra' => 'two' ] ] );
		$a['response']['signature'] = $b['response']['signature'];
		$this->assert_failed( $this->verify( Ceremony::encode( $a ) ), 'signature', true );

		if ( 'EdDSA' === $alg ) {
			$this->assert_failed( $this->verify( Ceremony::assertion( $auth, [ 'signature' => random_bytes( 63 ) ] ) ), 'signature', true );
		}
	}

	/** 11: an ES256 signature as raw r||s instead of DER. */
	public function test_raw_ecdsa_signature_is_rejected(): void {
		$auth    = $this->enrolled( 'ES256' );
		$options = Ceremony::signin_options();
		$good    = $auth->assert( $options, Ceremony::ORIGIN );
		$der     = (string) Base64Url::decode( $good['response']['signature'], 1, 512 );
		$good['response']['signature'] = Base64Url::encode( self::der_to_raw( $der ) );
		$this->assert_failed( $this->verify( Ceremony::encode( $good ) ), 'signature', true );
	}

	private static function der_to_raw( string $der ): string {
		$offset = 2;
		$out    = '';
		for ( $i = 0; $i < 2; $i++ ) {
			$len     = ord( $der[ $offset + 1 ] );
			$int     = substr( $der, $offset + 2, $len );
			$out    .= str_pad( ltrim( $int, "\0" ), 32, "\0", STR_PAD_LEFT );
			$offset += 2 + $len;
		}
		return $out;
	}

	public function test_up_and_uv_are_required(): void {
		$auth = $this->enrolled();
		$this->assert_failed( $this->verify( Ceremony::assertion( $auth, [ 'flags' => SoftAuthenticator::FLAG_UP ] ) ), 'signature', true, false, 'passkey_failed', 400 );
		$this->assert_failed( $this->verify( Ceremony::assertion( $auth, [ 'flags' => SoftAuthenticator::FLAG_UV ] ) ), 'signature', true );
	}

	/** 13: BE may never change, either way; 14: BS without BE. */
	public function test_backup_eligibility_cannot_change(): void {
		$device = $this->enrolled( 'ES256' );
		$this->assert_failed( $this->verify( Ceremony::assertion( $device, [ 'flags' => self::UP_UV | SoftAuthenticator::FLAG_BE ] ) ), 'flags', true );

		$synced = $this->enrolled(
			'ES256',
			[
				'be' => true,
				'bs' => true,
			]
		);
		$this->assert_failed( $this->verify( Ceremony::assertion( $synced, [ 'flags' => self::UP_UV ] ) ), 'flags', true );
		$this->assert_failed( $this->verify( Ceremony::assertion( $device, [ 'flags' => self::UP_UV | SoftAuthenticator::FLAG_BS ] ) ), 'signature', true, false );
		$this->assert_signed_in( $this->verify( Ceremony::assertion( $synced, [ 'flags' => self::UP_UV | SoftAuthenticator::FLAG_BE ] ) ) );
	}

	/* ------------------------------------------------------------------ 15: counter policy (7.6) */

	/** @return array<string,array{bool,int,int|string,bool,int}> be, stored, received, accepted, stored after */
	public static function counters(): array {
		return [
			'device: 0 and 0'           => [ false, 0, 0, true, 0 ],
			'device: stored "0", 0'     => [ false, 0, '0', true, 0 ],
			'device: 4 -> 5'            => [ false, 4, 5, true, 5 ],
			'device: 5 -> 5'            => [ false, 5, 5, false, 5 ],
			'device: 5 -> 4'            => [ false, 5, 4, false, 5 ],
			'device: 5 -> 0'            => [ false, 5, 0, false, 5 ],
			'device: 0 -> 2^32-1'       => [ false, 0, 4294967295, true, 4294967295 ],
			'synced: 0 and 0'           => [ true, 0, 0, true, 0 ],
			'synced: 4 -> 5'            => [ true, 4, 5, true, 5 ],
			'synced: 5 -> 3, never low' => [ true, 5, 3, true, 5 ],
			'synced: 5 -> 0'            => [ true, 5, 0, true, 5 ],
		];
	}

	/**
	 * @dataProvider counters
	 * @param int|string $received
	 *
	 * @group realdb
	 */
	public function test_counter_policy( bool $be, int $stored, $received, bool $accepted, int $after ): void {
		global $wpdb;
		$auth = $this->enrolled(
			'ES256',
			[
				'be' => $be,
				'bs' => $be,
			]
		);
		$wpdb->query( $wpdb->prepare( 'UPDATE ' . CredentialStore::table() . ' SET sign_count = %d', $stored ) );
		$flags  = self::UP_UV | ( $be ? SoftAuthenticator::FLAG_BE | SoftAuthenticator::FLAG_BS : 0 );
		$result = $this->verify( Ceremony::assertion( $auth, [ 'sign_count' => (int) $received, 'flags' => $flags ] ) );

		$row = $wpdb->get_row( 'SELECT * FROM ' . CredentialStore::table(), ARRAY_A );
		if ( $accepted ) {
			$this->assert_signed_in( $result );
			$this->assertNull( $row['counter_anomaly_at'] );
		} else {
			$data = $this->assert_failed( $result, 'counter', true );
			$this->assertTrue( $data['blocked_now'], 'device-bound regression blocks' );
			$this->assertSame( gmdate( 'Y-m-d H:i:s', Ceremony::NOW ), $row['counter_anomaly_at'] );
		}
		$this->assertSame( (string) $after, (string) $row['sign_count'] );
	}

	/** @group realdb */
	public function test_blocked_credential_stays_blocked_and_blocks_once(): void {
		global $wpdb;
		$auth = $this->enrolled();
		$wpdb->query( 'UPDATE ' . CredentialStore::table() . ' SET sign_count = 5' );

		$first = $this->assert_failed( $this->verify( Ceremony::assertion( $auth, [ 'sign_count' => 3 ] ) ), 'counter', true );
		$this->assertTrue( $first['blocked_now'] );

		// Even a higher counter (a clone pushing past the genuine key) is rejected, and no second block.
		$again = $this->assert_failed( $this->verify( Ceremony::assertion( $auth, [ 'sign_count' => 99 ] ) ), 'blocked', true );
		$this->assertFalse( $again['blocked_now'] );
		$this->assertSame( '5', (string) $wpdb->get_var( 'SELECT sign_count FROM ' . CredentialStore::table() ) );
	}

	/**
	 * Two regressions racing: the block UPDATE changes one row once (blocked email once).
	 *
	 * @group realdb
	 */
	public function test_concurrent_regressions_block_once(): void {
		global $wpdb;
		$auth = $this->enrolled();
		$wpdb->query( 'UPDATE ' . CredentialStore::table() . ' SET sign_count = 5' );
		$first  = Ceremony::assertion( $auth, [ 'sign_count' => 2 ] );
		$second = Ceremony::assertion( $auth, [ 'sign_count' => 3 ] );

		$inner = null;
		$wpdb->before_next_query(
			'UPDATE wp_magicauth_passkeys SET counter_anomaly_at',
			function () use ( $second, &$inner ): void {
				$inner = Verifier::verify_assertion( $second, Ceremony::COOKIE );
			}
		);
		$outer = $this->verify( $first );

		$this->assertInstanceOf( WP_Error::class, $inner );
		$this->assertInstanceOf( WP_Error::class, $outer );
		$this->assertSame( 1, (int) $inner->get_error_data()['blocked_now'] + (int) $outer->get_error_data()['blocked_now'] );
	}

	/**
	 * 15: out-of-order CAS: a concurrent assertion with a higher counter wins.
	 *
	 * @group realdb
	 */
	public function test_counter_cas_lost_to_a_concurrent_assertion(): void {
		global $wpdb;
		$auth = $this->enrolled();
		$wpdb->query( 'UPDATE ' . CredentialStore::table() . ' SET sign_count = 5' );
		$credential = Ceremony::assertion( $auth, [ 'sign_count' => 6 ] );

		$wpdb->before_next_query(
			'UPDATE wp_magicauth_passkeys SET sign_count',
			static function () use ( $wpdb ): void {
				$wpdb->query( 'UPDATE ' . CredentialStore::table() . ' SET sign_count = 7' );
			}
		);
		$this->assert_failed( $this->verify( $credential ), 'counter', true );
		$this->assertSame( '7', (string) $wpdb->get_var( 'SELECT sign_count FROM ' . CredentialStore::table() ) );
		$this->assertNull( $wpdb->get_var( 'SELECT last_used_at FROM ' . CredentialStore::table() ) );
	}

	/** @group realdb */
	public function test_counter_write_error_is_retry_for_a_device_bound_key(): void {
		global $wpdb;
		$auth = $this->enrolled();
		$wpdb->fail_next_query( 'UPDATE wp_magicauth_passkeys SET sign_count' );
		$this->assert_failed( $this->verify( Ceremony::assertion( $auth, [ 'sign_count' => 1 ] ) ), 'error', false, false, 'retry', 503 );
	}

	/* ------------------------------------------------------------------ 16 to 18: account (A-9) */

	public function test_disabled_deleted_and_denied_accounts_fail_generically(): void {
		global $magicauth_test_state;
		$auth = $this->enrolled();

		update_user_meta( 7, 'magicauth_disabled', 1 );
		$this->assert_failed( $this->verify( Ceremony::assertion( $auth ) ), 'account', true );
		delete_user_meta( 7, 'magicauth_disabled' );

		$deny = static function () {
			return new WP_Error( 'org_suspended', 'Suspended' );
		};
		add_filter( 'magicauth_allow_login', $deny );
		$this->assert_failed( $this->verify( Ceremony::assertion( $auth ) ), 'account', true );
		remove_filter( 'magicauth_allow_login', $deny );

		unset( $magicauth_test_state['users'][7] );
		$this->assert_failed( $this->verify( Ceremony::assertion( $auth ) ), 'account', true );
	}

	/** 16b: a reused user ID never inherits a deleted person's passkey (7.6 rule X). */
	public function test_reused_user_id_does_not_inherit_the_passkey(): void {
		global $wpdb;
		$auth = $this->enrolled();
		$wpdb->query( 'UPDATE ' . CredentialStore::table() . " SET user_registered = '2025-01-01 10:00:00'" );

		$data = $this->assert_failed( $this->verify( Ceremony::assertion( $auth ) ), 'account_mismatch', true );
		$this->assertSame( 7, $data['user_id'] );

		// Invisible in the new holder's list, count and excludeCredentials.
		$this->assertSame( [], CredentialStore::for_user( $this->user ) );
		$this->assertSame( 0, CredentialStore::count_for_user( $this->user, Ceremony::RP ) );
		$issued = Ceremony::register_options( $this->user );
		$this->assertSame( [], $issued['options']['excludeCredentials'] );
	}

	/** 16c: user_registered written in local time: string equality, no clock maths. */
	public function test_local_time_user_registered_is_harmless(): void {
		global $wpdb;
		Clock::set_for_tests( (int) strtotime( '2026-09-30 06:00:00 UTC' ) );
		$auth = $this->enrolled();
		$this->assertSame( '2026-09-30 06:00:00', $wpdb->get_var( 'SELECT created_at FROM ' . CredentialStore::table() ), 'created two hours before the local-time registration value' );
		$this->assert_signed_in( $this->verify( Ceremony::assertion( $auth ) ) );
	}

	/** 16d: an empty snapshot never matches. */
	public function test_empty_snapshot_is_rejected(): void {
		global $wpdb;
		$auth = $this->enrolled();
		$wpdb->query( 'UPDATE ' . CredentialStore::table() . " SET user_registered = ''" );
		$this->assert_failed( $this->verify( Ceremony::assertion( $auth ) ), 'account_mismatch', true );

		// Also when the user's own value is empty.
		$this->user->user_registered = '';
		$this->assert_failed( $this->verify( Ceremony::assertion( $auth ) ), 'account_mismatch', true );
	}

	/** 17: signed in as another user: 409, nothing written, not counted (r1-endpoints-05). */
	public function test_other_account_is_409_without_state_change(): void {
		global $wpdb;
		$auth = $this->enrolled();
		Ceremony::user( 8 );
		magicauth_test_login_as( 8 );

		$this->assert_failed( $this->verify( Ceremony::assertion( $auth, [ 'sign_count' => 9 ] ) ), 'other_account', false, false, 'other_account', 409 );
		$row = $wpdb->get_row( 'SELECT * FROM ' . CredentialStore::table(), ARRAY_A );
		$this->assertSame( '0', (string) $row['sign_count'] );
		$this->assertNull( $row['last_used_at'] );

		// The same user signed in already: verified, usage recorded.
		magicauth_test_login_as( 7 );
		$this->assert_signed_in( $this->verify( Ceremony::assertion( $auth, [ 'sign_count' => 10 ] ) ) );
		$this->assertSame( '10', (string) $wpdb->get_var( 'SELECT sign_count FROM ' . CredentialStore::table() ) );
	}

	/** 18: rule E maps to 403 reverify_required, not counted (r1-endpoints-05). */
	public function test_rule_e_is_403(): void {
		$auth = $this->enrolled();
		update_option( 'magicauth_settings', [ 'passkeys_email_reverify_days' => 30 ] );
		update_user_meta( 7, 'magicauth_email_verified_at', Ceremony::NOW - 31 * DAY_IN_SECONDS );
		$this->assert_failed( $this->verify( Ceremony::assertion( $auth ) ), 'reverify_required', false, false, 'reverify_required', 403 );

		update_user_meta( 7, 'magicauth_email_verified_at', Ceremony::NOW - 29 * DAY_IN_SECONDS );
		$this->assert_signed_in( $this->verify( Ceremony::assertion( $auth ) ) );
	}

	/* ------------------------------------------------------------------ W9 */

	/** @return array<string,array{string}> */
	public static function throwables(): array {
		return [
			'TypeError'       => [ 'TypeError' ],
			'SodiumException' => [ 'SodiumException' ],
		];
	}

	/**
	 * 11 and W9: whatever processGet() throws, the result is the generic failure.
	 *
	 * @dataProvider throwables
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_library_throwable_gives_the_generic_failure( string $class ): void {
		require_once dirname( __DIR__ ) . '/Support/library-throws.php';
		Ceremony::site();
		$this->user = Ceremony::user( 7 );
		$auth       = $this->enrolled( 'ES256' );
		$credential = Ceremony::assertion( $auth );

		$GLOBALS['magicauth_library_throw'] = new $class( 'boom <b>' );
		ob_start();
		$result = Verifier::verify_assertion( $credential, Ceremony::COOKIE );
		$out    = (string) ob_get_clean();
		unset( $GLOBALS['magicauth_library_throw'] );

		$this->assertSame( '', $out );
		$this->assert_failed( $result, 'signature', true );
	}

	/* ------------------------------------------------------------------ 21: W3C vectors */

	/**
	 * 21: the W3C L3 section 16 vectors through the wrapper's own checks. Their
	 * authentication halves carry no userHandle and only 16.6 sets UV, so they
	 * are checked step by step: clientData (A-2), then the full pipeline for
	 * 16.6 with its credential stored and a userHandle added (not signed).
	 */
	public function test_w3c_vectors(): void {
		global $magicauth_test_state;
		$magicauth_test_state['home'] = Fixtures::ORIGIN;

		// A-2: crossOrigin true (16.4) and topOrigin (16.5) rejected; the others pass.
		foreach ( [ '16.2' => true, '16.4' => false, '16.5' => false, '16.6' => true, '16.10' => true, '16.11' => true ] as $id => $ok ) {
			$client = Verifier::client_data( Fixtures::bin( $id, 'authentication', 'clientDataJSON' ), 'webauthn.get' );
			$this->assertSame( $ok, null !== $client, $id );
			if ( $ok ) {
				$this->assertSame( Fixtures::bin( $id, 'authentication', 'challenge' ), $client['challenge'], $id );
			}
			$reg = Verifier::client_data( Fixtures::bin( $id, 'registration', 'clientDataJSON' ), 'webauthn.create' );
			$this->assertSame( $ok, null !== $reg, $id . ' registration' );
		}

		// Sign-in halves through verify_assertion(). 16.10 is left out: its
		// 436-byte RSA modulus does not parse (library, step 7), so no key is stored.
		$expected = [
			'16.2'  => 'signature', // UV=0 (flags 0x19): rejected by the UV requirement.
			'16.6'  => null,        // UP, UV, BE: signs in.
			'16.11' => 'signature', // UV=0 (flags 0x01).
		];
		foreach ( $expected as $id => $reason ) {
			if ( '16.11' === $id && ! function_exists( 'sodium_crypto_sign_verify_detached' ) && ! defined( 'OPENSSL_KEYTYPE_ED25519' ) ) {
				continue;
			}
			$this->assertSame( $reason, $this->w3c_signin( $id ), $id );
		}
	}

	/** Stores the vector's credential and runs its authentication half; null on success, else the reason. */
	private function w3c_signin( string $id ): ?string {
		global $wpdb;
		$wpdb->query( 'DELETE FROM ' . CredentialStore::table() );

		$att    = \MagicAuth\ThirdParty\Passkeys\CBOR\CborDecoder::decode( Fixtures::bin( $id, 'registration', 'attestationObject' ) );
		$ad     = new \MagicAuth\ThirdParty\Passkeys\Attestation\AuthenticatorData( $att['authData']->getBinaryString() );
		$raw_id = $ad->getCredentialId();
		$handle = random_bytes( 32 );

		$stored = CredentialStore::insert(
			[
				'user_id'         => 7,
				'rp_id'           => Fixtures::RP_ID,
				'credential_id'   => Base64Url::encode( $raw_id ),
				'user_handle'     => Base64Url::encode( $handle ),
				'public_key'      => (string) $ad->getPublicKeyPem(),
				'alg'             => $ad->getCredentialPublicKeyAlg(),
				'sign_count'      => 0,
				'backup_eligible' => (bool) $ad->getIsBackupEligible(),
				'backup_state'    => (bool) $ad->getIsBackup(),
				'user_registered' => Ceremony::REGISTERED,
			]
		);
		$this->assertIsInt( $stored, $id );

		// The vector's challenge as an issued signin row bound to our cookie.
		$wpdb->insert(
			ChallengeStore::table(),
			[
				'lookup_hash'  => hash_hmac( 'sha256', 'magicauth-passkey|signin|' . Fixtures::bin( $id, 'authentication', 'challenge' ), wp_salt( 'auth' ) ),
				'ceremony'     => 'signin',
				'binding_hash' => ChallengeStore::binding_hash( Ceremony::COOKIE ),
				'created_at'   => gmdate( 'Y-m-d H:i:s', Ceremony::NOW ),
				'expires_at'   => gmdate( 'Y-m-d H:i:s', Ceremony::NOW + 600 ),
			]
		);

		$credential = Ceremony::encode(
			[
				'id'       => Base64Url::encode( $raw_id ),
				'rawId'    => Base64Url::encode( $raw_id ),
				'type'     => 'public-key',
				'response' => [
					'clientDataJSON'    => Base64Url::encode( Fixtures::bin( $id, 'authentication', 'clientDataJSON' ) ),
					'authenticatorData' => Base64Url::encode( Fixtures::bin( $id, 'authentication', 'authenticatorData' ) ),
					'signature'         => Base64Url::encode( Fixtures::bin( $id, 'authentication', 'signature' ) ),
					'userHandle'        => Base64Url::encode( $handle ),
				],
			]
		);
		$result = $this->verify( $credential );
		if ( is_array( $result ) ) {
			return null;
		}
		return (string) $result->get_error_data()['reason'];
	}

	/* ------------------------------------------------------------------ Options */

	public function test_request_options_never_name_a_credential_at_sign_in(): void {
		$options = Ceremony::signin_options();
		$this->assertSame( [], $options['allowCredentials'] );
		$this->assertSame( Ceremony::RP, $options['rpId'] );
		$this->assertSame( 'required', $options['userVerification'] );
		$this->assertSame( Options::TIMEOUT_MS, $options['timeout'] );
		$this->assertSame( '[]', (string) json_encode( $options['allowCredentials'] ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode
	}
}
