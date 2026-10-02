<?php
/**
 * Conformance of the vendored report-uri/passkeys-php against the audit
 * (SPEC 15 step 7, 4.9; `02-library-audit.md` sections 2 and 3). Every row of
 * audit section 3 is reproduced through SoftAuthenticator against the raw
 * library, with the result the patches give: R1 typed COSE and the alg check,
 * R2 CBOR depth and keys, R3 packed self attestation, R4 static exception
 * messages, H1 no (un)serialize, H2 Ed25519 signature length on the sodium
 * path, H3 no trailing authData bytes. Rows the wrapper owns (W1 to W9) are
 * pinned as library behaviour, so a library update that changes them shows up
 * here. No PHP warning, notice or deprecation may escape (phpunit.xml.dist
 * fails on them), except the one documented trim(null) row, which is captured.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Tests\Support\Cbor;
use MagicAuth\Tests\Support\Fixtures;
use MagicAuth\Tests\Support\SoftAuthenticator;
use MagicAuth\ThirdParty\Passkeys\Attestation\AuthenticatorData;
use MagicAuth\ThirdParty\Passkeys\Binary\ByteBuffer;
use MagicAuth\ThirdParty\Passkeys\CBOR\CborDecoder;
use MagicAuth\ThirdParty\Passkeys\WebAuthn;
use MagicAuth\ThirdParty\Passkeys\WebAuthnException;
use PHPUnit\Framework\TestCase;

final class LibraryConformanceTest extends TestCase {

	private const RP_ID  = 'academy.example';
	private const ORIGIN = 'https://academy.example';

	private const DIR = MAGICAUTH_DIR . 'includes/ThirdParty/Passkeys/';

	private const PHP_FILES = [
		'Attestation/AttestationObject.php',
		'Attestation/AuthenticatorData.php',
		'Binary/ByteBuffer.php',
		'CBOR/CborDecoder.php',
		'WebAuthn.php',
		'WebAuthnException.php',
	];

	private const PATCHES = [
		'0001-cose-alg.patch',
		'0002-cbor-depth-dupes.patch',
		'0003-bytebuffer-no-serializable.patch',
		'0004-sodium-siglen.patch',
		'0005-authdata-trailing.patch',
		'0006-packed-self-attestation.patch',
		'0007-static-exception-messages.patch',
		'0008-plugin-check-annotations.patch',
	];

	private const FLAGS_UP_UV = SoftAuthenticator::FLAG_UP | SoftAuthenticator::FLAG_UV;

	// ------------------------------------------------------------------
	// Audit 3 row 1: register and sign in, ES256, RS256, EdDSA.
	// ------------------------------------------------------------------

	/** @return array<string,array{string}> */
	public static function algs(): array {
		return [
			'ES256' => [ 'ES256' ],
			'RS256' => [ 'RS256' ],
			'EdDSA' => [ 'EdDSA' ],
		];
	}

	/** @dataProvider algs */
	public function test_register_and_sign_in( string $alg ): void {
		$this->require_alg( $alg );
		$auth = new SoftAuthenticator(
			$alg,
			[
				'aaguid' => str_repeat( "\x5a", 16 ),
				'be'     => true,
				'bs'     => false,
			]
		);
		$data = $this->process_create( $auth );

		$this->assertSame( $auth->credentialId(), $data->credentialId );
		$this->assertSame( $auth->coseAlg(), $data->credentialAlg, 'R1: processCreate() returns the COSE alg' );
		$this->assertIsInt( $data->credentialAlg );
		$this->assertSame( str_repeat( "\x5a", 16 ), $data->AAGUID );
		$this->assertTrue( $data->userPresent );
		$this->assertTrue( $data->userVerified );
		$this->assertTrue( $data->isBackupEligible );
		$this->assertFalse( $data->isBackedUp );
		$this->assertNull( $data->signatureCounter, 'counter 0 is reported as null (W6 stores 0)' );
		$this->assertSame( $auth->publicKeyDer(), self::pem_to_der( $data->credentialPublicKey ) );

		$this->assertTrue( $this->process_get( $auth, $data->credentialPublicKey ) );
		$this->assertTrue( $this->process_get( $auth, $data->credentialPublicKey, [], 0 ) );
	}

	/** @dataProvider algs */
	public function test_r1_authenticator_data_exposes_the_key_alg( string $alg ): void {
		$this->require_alg( $alg );
		$auth = new SoftAuthenticator( $alg );
		$json = $auth->register( self::options( random_bytes( 32 ) ), self::ORIGIN );
		$ad   = new AuthenticatorData( SoftAuthenticator::b64url_decode( $json['response']['authenticatorData'] ) );
		$this->assertSame( $auth->coseAlg(), $ad->getCredentialPublicKeyAlg() );

		$this->expectException( WebAuthnException::class );
		( new AuthenticatorData( hash( 'sha256', self::RP_ID, true ) . chr( self::FLAGS_UP_UV ) . pack( 'N', 0 ) ) )->getCredentialPublicKeyAlg();
	}

	// ------------------------------------------------------------------
	// Audit 3 rows 2 and 3: signature encodings and key confusion.
	// ------------------------------------------------------------------

	public function test_es256_raw_r_s_signature_rejected(): void {
		$auth = new SoftAuthenticator( 'ES256' );
		$pem  = $this->process_create( $auth )->credentialPublicKey;

		$challenge = random_bytes( 32 );
		$json      = $auth->assert( self::request( $challenge ), self::ORIGIN );
		$cdj       = SoftAuthenticator::b64url_decode( $json['response']['clientDataJSON'] );
		$ad        = SoftAuthenticator::b64url_decode( $json['response']['authenticatorData'] );
		$der       = SoftAuthenticator::b64url_decode( $json['response']['signature'] );
		$this->assertTrue( ( new WebAuthn( self::RP_ID, self::RP_ID, true ) )->processGet( $cdj, $ad, $der, $pem, $challenge, null, true, true ) );

		$this->assert_rejected(
			static function () use ( $cdj, $ad, $der, $pem, $challenge ): void {
				( new WebAuthn( self::RP_ID, self::RP_ID, true ) )->processGet( $cdj, $ad, self::der_to_raw( $der ), $pem, $challenge, null, true, true );
			},
			WebAuthnException::INVALID_SIGNATURE
		);
	}

	public function test_es256_signature_against_an_rsa_key_rejected(): void {
		$es  = new SoftAuthenticator( 'ES256' );
		$rsa = new SoftAuthenticator( 'RS256' );
		$this->process_create( $es );
		$rsa_pem = $this->process_create( $rsa )->credentialPublicKey;

		$this->assert_rejected(
			function () use ( $es, $rsa_pem ): void {
				$this->process_get( $es, $rsa_pem );
			},
			WebAuthnException::INVALID_SIGNATURE
		);
	}

	public function test_signature_over_other_client_data_rejected(): void {
		$auth = new SoftAuthenticator( 'ES256' );
		$pem  = $this->process_create( $auth )->credentialPublicKey;
		$this->assert_rejected(
			function () use ( $auth, $pem ): void {
				$this->process_get( $auth, $pem, [ 'signature' => $auth->sign( 'other data' ) ] );
			},
			WebAuthnException::INVALID_SIGNATURE
		);
	}

	// ------------------------------------------------------------------
	// Audit 3 rows 4 to 7: COSE key (R1, R2).
	// ------------------------------------------------------------------

	/** @return array<string,array{string,mixed}> */
	public static function unsupported_algs(): array {
		$p384 = [
			1  => 2,
			3  => -35,
			-1 => 2,
			-2 => Cbor::bytes( str_repeat( "\x01", 48 ) ),
			-3 => Cbor::bytes( str_repeat( "\x02", 48 ) ),
		];
		return [
			'ES384 (-35, audit row 4)' => [ 'ES256', $p384 ],
			'ES512 (-36)'              => [ 'ES256', [ 3 => -36 ] ],
			'PS256 (-37)'              => [ 'RS256', [ 3 => -37 ] ],
			'RS384 (-258)'             => [ 'RS256', [ 3 => -258 ] ],
			'alg 0'                    => [ 'ES256', [ 3 => 0 ] ],
			'alg 7 (positive)'         => [ 'ES256', [ 3 => 7 ] ],
		];
	}

	/**
	 * @dataProvider unsupported_algs
	 * @param mixed $cose
	 */
	public function test_r1_unsupported_alg_rejected( string $alg, $cose ): void {
		$auth = new SoftAuthenticator( $alg );
		if ( isset( $cose[1], $cose[-1] ) ) {
			$cose = static function () use ( $cose ): array {
				return $cose;
			};
		}
		$this->assert_create_rejected( $auth, [ 'cose' => $cose ], WebAuthnException::INVALID_PUBLIC_KEY );
	}

	/** @return array<string,array{string,mixed,int}> */
	public static function malformed_cose(): array {
		$omit = SoftAuthenticator::OMIT;
		$key  = WebAuthnException::INVALID_PUBLIC_KEY;
		return [
			'EC2 crv missing (audit row 6)'   => [ 'ES256', [ -1 => $omit ], $key ],
			'EC2 x missing (audit row 6)'     => [ 'ES256', [ -2 => $omit ], $key ],
			'EC2 y missing (audit row 6)'     => [ 'ES256', [ -3 => $omit ], $key ],
			'EC2 crv, x, y missing'           => [ 'ES256', [ -1 => $omit, -2 => $omit, -3 => $omit ], $key ],
			'EC2 y as a CBOR boolean'         => [ 'ES256', [ -3 => true ], $key ],
			'EC2 y as null'                   => [ 'ES256', [ -3 => null ], $key ],
			'EC2 x as a text string'          => [ 'ES256', [ -2 => str_repeat( 'x', 32 ) ], $key ],
			'EC2 x as an int'                 => [ 'ES256', [ -2 => 7 ], $key ],
			'EC2 x as an array'               => [ 'ES256', [ -2 => [ 1, 2 ] ], $key ],
			'EC2 x 31 bytes'                  => [ 'ES256', [ -2 => Cbor::bytes( str_repeat( "\x01", 31 ) ) ], $key ],
			'EC2 y 33 bytes'                  => [ 'ES256', [ -3 => Cbor::bytes( str_repeat( "\x01", 33 ) ) ], $key ],
			'EC2 crv as text'                 => [ 'ES256', [ -1 => '1' ], $key ],
			'EC2 crv P-384'                   => [ 'ES256', [ -1 => 2 ], $key ],
			'kty as text'                     => [ 'ES256', [ 1 => '2' ], $key ],
			'kty missing'                     => [ 'ES256', [ 1 => $omit ], $key ],
			'kty RSA with ES256'              => [ 'ES256', [ 1 => 3 ], $key ],
			'alg as text'                     => [ 'ES256', [ 3 => '-7' ], $key ],
			'alg missing'                     => [ 'ES256', [ 3 => $omit ], $key ],
			'alg as bytes'                    => [ 'ES256', [ 3 => Cbor::bytes( "\x26" ) ], $key ],
			'RSA n missing'                   => [ 'RS256', [ -1 => $omit ], $key ],
			'RSA n as text'                   => [ 'RS256', [ -1 => str_repeat( 'n', 256 ) ], $key ],
			'RSA n 3072 bits'                 => [ 'RS256', [ -1 => Cbor::bytes( "\xc1" . random_bytes( 383 ) ) ], $key ],
			'RSA n 4104 bits (over R1 range)' => [ 'RS256', [ -1 => Cbor::bytes( "\xc1" . random_bytes( 512 ) ) ], $key ],
			'RSA n 255 bytes'                 => [ 'RS256', [ -1 => Cbor::bytes( "\xc1" . random_bytes( 254 ) ) ], $key ],
			'RSA e missing'                   => [ 'RS256', [ -2 => $omit ], $key ],
			'RSA e as bool'                   => [ 'RS256', [ -2 => false ], $key ],
			'RSA e 9 bytes'                   => [ 'RS256', [ -2 => Cbor::bytes( str_repeat( "\x01", 9 ) ) ], $key ],
			'RSA e empty'                     => [ 'RS256', [ -2 => Cbor::bytes( '' ) ], $key ],
			'OKP x missing'                   => [ 'EdDSA', [ -2 => $omit ], WebAuthnException::MISSING_PUBLIC_KEY ],
			'OKP x as text'                   => [ 'EdDSA', [ -2 => str_repeat( 'x', 32 ) ], $key ],
			'OKP x 31 bytes'                  => [ 'EdDSA', [ -2 => Cbor::bytes( str_repeat( "\x01", 31 ) ) ], $key ],
			'OKP crv missing'                 => [ 'EdDSA', [ -1 => $omit ], $key ],
			'OKP crv as text'                 => [ 'EdDSA', [ -1 => '6' ], $key ],
			'OKP crv X25519'                  => [ 'EdDSA', [ -1 => 4 ], $key ],
		];
	}

	/**
	 * Malformed COSE keys throw WebAuthnException and nothing else: no
	 * TypeError, and no warning or deprecation (failOnWarning and
	 * failOnDeprecation would fail this test).
	 *
	 * @dataProvider malformed_cose
	 * @param mixed $cose
	 */
	public function test_r1_malformed_cose_rejected_without_warnings( string $alg, $cose, int $code ): void {
		$this->require_alg( $alg );
		$this->assert_create_rejected( new SoftAuthenticator( $alg ), [ 'cose' => $cose ], $code );
	}

	/** @return array<string,array{string}> */
	public static function cose_not_a_map(): array {
		return [
			'array'       => [ Cbor::encode( [ 1, 2, 3 ] ) ],
			'int'         => [ Cbor::encode( 2 ) ],
			'byte string' => [ Cbor::encode( Cbor::bytes( str_repeat( "\x01", 64 ) ) ) ],
			'text'        => [ Cbor::encode( 'cose' ) ],
			'null'        => [ Cbor::encode( null ) ],
			'empty map'   => [ "\xa0" ],
		];
	}

	/** @dataProvider cose_not_a_map */
	public function test_r1_cose_key_that_is_not_a_usable_map_rejected( string $raw ): void {
		$this->assert_create_rejected(
			new SoftAuthenticator( 'ES256' ),
			[
				'cose' => static function () use ( $raw ) {
					return Cbor::raw( $raw );
				},
			],
			WebAuthnException::INVALID_PUBLIC_KEY
		);
	}

	public function test_r1_eddsa_key_is_accepted_by_the_library(): void {
		// The library accepts -8 whenever it parses; the wrapper checks
		// credentialAlg against the offered list (R-8, W6).
		$this->require_alg( 'EdDSA' );
		$this->assertSame( -8, $this->process_create( new SoftAuthenticator( 'EdDSA' ) )->credentialAlg );
	}

	public function test_es256_point_off_the_curve_parses_but_its_pem_does_not_load(): void {
		// Audit row 5: the library cannot know; W6 / R-9 loads the PEM.
		$data = $this->process_create(
			new SoftAuthenticator( 'ES256' ),
			[
				'cose' => [
					-2 => Cbor::bytes( str_repeat( "\x01", 32 ) ),
					-3 => Cbor::bytes( str_repeat( "\x01", 32 ) ),
				],
			]
		);
		$this->assertSame( -7, $data->credentialAlg );
		$this->assertFalse( openssl_pkey_get_public( $data->credentialPublicKey ) );
		while ( openssl_error_string() ) {
			// Drain OpenSSL's error queue so later cases start clean.
		}
	}

	public function test_r2_duplicate_cose_label_rejected(): void {
		$auth = new SoftAuthenticator( 'ES256' );
		$cose = $auth->coseKey();
		$raw  = "\xa6";
		foreach ( $cose as $label => $value ) {
			$raw .= Cbor::encode( $label ) . Cbor::encode( $value );
		}
		$raw .= Cbor::encode( 3 ) . Cbor::encode( -7 );
		$this->assert_create_rejected(
			$auth,
			[
				'cose' => static function () use ( $raw ) {
					return Cbor::raw( $raw );
				},
			],
			WebAuthnException::CBOR
		);
	}

	public function test_r2_text_label_3_is_not_read_as_alg(): void {
		// Audit row 7: PHP turns the text key "3" into the integer key 3.
		$auth = new SoftAuthenticator( 'ES256' );
		$cose = $auth->coseKey();
		unset( $cose[3] );
		$cose['3'] = -7;
		$raw       = "\xa5";
		foreach ( $cose as $label => $value ) {
			$raw .= Cbor::encode( 3 === $label ? '3' : $label ) . Cbor::encode( $value );
		}
		$this->assertStringContainsString( "\x61\x33\x26", $raw, 'text "3" => -7 is encoded' );
		$this->assert_create_rejected(
			$auth,
			[
				'cose' => static function () use ( $raw ) {
					return Cbor::raw( $raw );
				},
			],
			WebAuthnException::CBOR
		);
	}

	// ------------------------------------------------------------------
	// Audit 3 row 8 and 4.10: attestation formats, packed self attestation (R3).
	// ------------------------------------------------------------------

	/** @dataProvider algs */
	public function test_r3_packed_self_attestation_accepted( string $alg ): void {
		$this->require_alg( $alg );
		$auth = new SoftAuthenticator( $alg );
		$data = $this->process_create( $auth, [ 'self_attest' => true ] );
		$this->assertSame( $auth->credentialId(), $data->credentialId );
		$this->assertSame( $auth->coseAlg(), $data->credentialAlg );
		$this->assertSame( str_repeat( "\0", 16 ), $data->AAGUID );
		$this->assertTrue( $this->process_get( $auth, $data->credentialPublicKey ) );
	}

	/** @return array<string,array{string,array<string,mixed>}> */
	public static function bad_self_attestations(): array {
		return [
			'x5c present (full attestation)' => [ 'ES256', [ 'attStmt' => [ 'x5c' => [ Cbor::bytes( 'cert' ) ] ] ] ],
			'ecdaaKeyId present'             => [ 'ES256', [ 'attStmt' => [ 'ecdaaKeyId' => Cbor::bytes( 'id' ) ] ] ],
			'extra key'                      => [ 'ES256', [ 'attStmt' => [ 'foo' => 1 ] ] ],
			'alg differs from the key (ES)'  => [ 'ES256', [ 'attStmt' => [ 'alg' => -257 ] ] ],
			'alg differs from the key (RS)'  => [ 'RS256', [ 'attStmt' => [ 'alg' => -7 ] ] ],
			'alg as text'                    => [ 'ES256', [ 'attStmt' => [ 'alg' => '-7' ] ] ],
			'sig as text'                    => [ 'ES256', [ 'attStmt' => [ 'sig' => 'signature' ] ] ],
			'sig empty'                      => [ 'ES256', [ 'attStmt' => [ 'sig' => Cbor::bytes( '' ) ] ] ],
			'sig garbage'                    => [ 'ES256', [ 'attStmt' => [ 'sig' => Cbor::bytes( random_bytes( 72 ) ) ] ] ],
			'sig garbage RS256'              => [ 'RS256', [ 'attStmt' => [ 'sig' => Cbor::bytes( random_bytes( 256 ) ) ] ] ],
			'sig garbage EdDSA'              => [ 'EdDSA', [ 'attStmt' => [ 'sig' => Cbor::bytes( random_bytes( 64 ) ) ] ] ],
			'sig 63 bytes EdDSA'             => [ 'EdDSA', [ 'attStmt' => [ 'sig' => Cbor::bytes( random_bytes( 63 ) ) ] ] ],
			'fmt Packed (case)'              => [ 'ES256', [ 'fmt' => 'Packed' ] ],
		];
	}

	/**
	 * @dataProvider bad_self_attestations
	 * @param array<string,mixed> $o
	 */
	public function test_r3_bad_self_attestation_rejected( string $alg, array $o ): void {
		$this->require_alg( $alg );
		$this->assert_create_rejected( new SoftAuthenticator( $alg ), [ 'self_attest' => true ] + $o );
	}

	public function test_r3_self_attestation_with_a_non_zero_aaguid_rejected(): void {
		$this->assert_create_rejected( new SoftAuthenticator( 'ES256', [ 'aaguid' => str_repeat( "\x01", 16 ) ] ), [ 'self_attest' => true ] );
	}

	public function test_r3_self_attestation_signature_over_other_client_data_rejected(): void {
		$auth      = new SoftAuthenticator( 'ES256' );
		$challenge = random_bytes( 32 );
		$signed    = $auth->register( self::options( $challenge ), self::ORIGIN, [ 'self_attest' => true ] );
		$other     = $auth->register( self::options( $challenge ), self::ORIGIN, [ 'clientData' => [ 'extra' => 'other' ] ] );
		$cdj       = SoftAuthenticator::b64url_decode( $other['response']['clientDataJSON'] );
		$att       = SoftAuthenticator::b64url_decode( $signed['response']['attestationObject'] );
		$this->assertSame( $signed['response']['authenticatorData'], $other['response']['authenticatorData'] );

		$this->assert_rejected(
			static function () use ( $cdj, $att, $challenge ): void {
				( new WebAuthn( self::RP_ID, self::RP_ID, true ) )->processCreate( $cdj, $att, $challenge, true, true );
			}
		);
	}

	public function test_r3_packed_without_sig_or_alg_rejected(): void {
		$auth = new SoftAuthenticator( 'ES256' );
		$this->assert_create_rejected(
			$auth,
			[
				'fmt'     => 'packed',
				'attStmt' => [ 'alg' => -7 ],
			]
		);
		$this->assert_create_rejected(
			$auth,
			[
				'fmt'     => 'packed',
				'attStmt' => [ 'sig' => Cbor::bytes( random_bytes( 70 ) ) ],
			]
		);
		$this->assert_create_rejected(
			$auth,
			[
				'fmt'     => 'packed',
				'attStmt' => [],
			]
		);
	}

	/** @return array<string,array{array<string,mixed>}> */
	public static function other_formats(): array {
		return [
			'fido-u2f'                     => [
				[
					'fmt'     => 'fido-u2f',
					'attStmt' => [
						'sig' => Cbor::bytes( 'x' ),
						'x5c' => [ Cbor::bytes( 'c' ) ],
					],
				],
			],
			'tpm'                          => [ [ 'fmt' => 'tpm' ] ],
			'android-key'                  => [ [ 'fmt' => 'android-key' ] ],
			'apple'                        => [ [ 'fmt' => 'apple' ] ],
			'empty fmt'                    => [ [ 'fmt' => '' ] ],
			'none with a non-empty attStmt' => [
				[
					'fmt'     => 'none',
					'attStmt' => [ 'sig' => Cbor::bytes( 'x' ) ],
				],
			],
		];
	}

	/**
	 * @dataProvider other_formats
	 * @param array<string,mixed> $o
	 */
	public function test_other_attestation_formats_rejected( array $o ): void {
		$this->assert_create_rejected( new SoftAuthenticator( 'ES256' ), $o, WebAuthnException::INVALID_DATA );
	}

	public function test_attestation_object_shape_rejected(): void {
		$auth = new SoftAuthenticator( 'ES256' );
		$bad  = [
			Cbor::encode( [ 1, 2 ] ),
			Cbor::encode( Cbor::map( [ 'attStmt' => Cbor::map( [] ), 'authData' => Cbor::bytes( 'x' ) ] ) ),
			Cbor::encode( Cbor::map( [ 'fmt' => 'none', 'authData' => Cbor::bytes( 'x' ) ] ) ),
			Cbor::encode( Cbor::map( [ 'fmt' => 'none', 'attStmt' => Cbor::map( [] ) ] ) ),
			Cbor::encode( Cbor::map( [ 'fmt' => 'none', 'attStmt' => Cbor::map( [] ), 'authData' => 'text' ] ) ),
			Cbor::encode( Cbor::map( [ 'fmt' => 7, 'attStmt' => Cbor::map( [] ), 'authData' => Cbor::bytes( 'x' ) ] ) ),
		];
		foreach ( $bad as $att ) {
			$this->assert_create_rejected( $auth, [ 'attestationObject' => $att ] );
		}
	}

	// ------------------------------------------------------------------
	// Audit 3 row 9: authData trailing bytes (H3).
	// ------------------------------------------------------------------

	public function test_h3_trailing_bytes_after_the_cose_key_rejected(): void {
		$this->assert_create_rejected( new SoftAuthenticator( 'ES256' ), [ 'append_authdata' => "\x00" ], WebAuthnException::INVALID_DATA );
		$this->assert_create_rejected( new SoftAuthenticator( 'ES256' ), [ 'append_authdata' => Cbor::encode( Cbor::map( [ 'credProtect' => 2 ] ) ) ], WebAuthnException::INVALID_DATA );
	}

	public function test_h3_extension_data_with_the_ed_flag_still_parses(): void {
		$auth  = new SoftAuthenticator( 'ES256' );
		$flags = self::FLAGS_UP_UV | SoftAuthenticator::FLAG_BE | SoftAuthenticator::FLAG_BS | SoftAuthenticator::FLAG_AT | SoftAuthenticator::FLAG_ED;
		$ext   = Cbor::encode( Cbor::map( [ 'credProtect' => 2 ] ) );
		$data  = $this->process_create(
			$auth,
			[
				'flags'           => $flags,
				'append_authdata' => $ext,
			]
		);
		$this->assertSame( $auth->credentialId(), $data->credentialId );

		// ED with trailing bytes after the extension map: the decoder's own check.
		$this->assert_create_rejected(
			$auth,
			[
				'flags'           => $flags,
				'append_authdata' => $ext . "\x00",
			],
			WebAuthnException::CBOR
		);
	}

	public function test_h3_assertion_auth_data_with_trailing_bytes_rejected(): void {
		$auth = new SoftAuthenticator( 'ES256' );
		$pem  = $this->process_create( $auth )->credentialPublicKey;
		$this->assert_rejected(
			function () use ( $auth, $pem ): void {
				$this->process_get( $auth, $pem, [ 'append_authdata' => "\x00" ] );
			},
			WebAuthnException::INVALID_DATA
		);
	}

	// ------------------------------------------------------------------
	// Audit 3 rows 10 to 13: client data (the wrapper's W3 pre-checks).
	// ------------------------------------------------------------------

	public function test_origin_as_a_json_array_throws_type_error(): void {
		// Audit row 10: a TypeError, not WebAuthnException; W3 checks the type
		// first and W9 catches every Throwable.
		$this->expectException( \TypeError::class );
		$this->process_create( new SoftAuthenticator( 'ES256' ), [ 'clientData' => [ 'origin' => [ self::ORIGIN ] ] ] );
	}

	public function test_origin_without_host_rejected_with_a_deprecation(): void {
		// Audit row 11: rejected, and on PHP 8.1+ trim(null) raises a
		// deprecation first (captured here; W3 never passes such an origin).
		$deprecations = [];
		set_error_handler(
			static function ( int $errno, string $errstr ) use ( &$deprecations ): bool {
				$deprecations[] = $errstr;
				return true;
			},
			E_DEPRECATED
		);
		try {
			$this->assert_create_rejected( new SoftAuthenticator( 'ES256' ), [ 'origin' => 'https:' ], WebAuthnException::INVALID_ORIGIN );
		} finally {
			restore_error_handler();
		}
		if ( PHP_VERSION_ID >= 80100 ) {
			$this->assertCount( 1, $deprecations );
			$this->assertStringContainsString( 'trim()', $deprecations[0] );
		} else {
			$this->assertSame( [], $deprecations );
		}
	}

	/** @return array<string,array{string,bool}> */
	public static function origins(): array {
		return [
			'exact'                         => [ 'https://academy.example', true ],
			'subdomain (audit 2, step 9)'   => [ 'https://evil.academy.example', true ],
			'other port (audit 2, step 9)'  => [ 'https://academy.example:8443', true ],
			'uppercase host'                => [ 'https://ACADEMY.example', true ],
			'http'                          => [ 'http://academy.example', false ],
			'other host'                    => [ 'https://academy.example.evil', false ],
			'suffix without a dot'          => [ 'https://evilacademy.example', false ],
			'parent domain'                 => [ 'https://example', false ],
		];
	}

	/** @dataProvider origins */
	public function test_library_origin_check_is_a_suffix_match( string $origin, bool $accepted ): void {
		// The library check is the second layer; W3 is the exact allowlist.
		$auth = new SoftAuthenticator( 'ES256' );
		if ( $accepted ) {
			$this->assertSame( $auth->credentialId(), $this->process_create( $auth, [ 'origin' => $origin ] )->credentialId );
			return;
		}
		$this->assert_create_rejected( $auth, [ 'origin' => $origin ], WebAuthnException::INVALID_ORIGIN );
	}

	public function test_http_origin_allowed_only_for_rp_id_localhost(): void {
		$auth      = new SoftAuthenticator( 'ES256' );
		$challenge = random_bytes( 32 );
		$opts      = self::options( $challenge );
		$opts['rp']['id'] = 'localhost';
		$json      = $auth->register( $opts, 'http://localhost:9400' );
		$data      = ( new WebAuthn( 'localhost', 'localhost', true ) )->processCreate(
			SoftAuthenticator::b64url_decode( $json['response']['clientDataJSON'] ),
			SoftAuthenticator::b64url_decode( $json['response']['attestationObject'] ),
			$challenge,
			true,
			true
		);
		$this->assertSame( $auth->credentialId(), $data->credentialId );
	}

	public function test_challenge_with_junk_characters_accepted(): void {
		// Audit row 12: lenient base64 decoding; W3 compares the exact string.
		$challenge = random_bytes( 32 );
		$junk      = '!!' . SoftAuthenticator::b64url( $challenge ) . '**';
		$auth      = new SoftAuthenticator( 'ES256' );
		$json      = $auth->register( self::options( $challenge ), self::ORIGIN, [ 'challenge' => $junk ] );
		$this->assertStringContainsString( $junk, SoftAuthenticator::b64url_decode( $json['response']['clientDataJSON'] ) );
		$data = ( new WebAuthn( self::RP_ID, self::RP_ID, true ) )->processCreate(
			SoftAuthenticator::b64url_decode( $json['response']['clientDataJSON'] ),
			SoftAuthenticator::b64url_decode( $json['response']['attestationObject'] ),
			$challenge,
			true,
			true
		);
		$this->assertSame( $auth->credentialId(), $data->credentialId );
	}

	public function test_wrong_challenge_rejected(): void {
		$auth = new SoftAuthenticator( 'ES256' );
		$this->assert_create_rejected( $auth, [ 'challenge' => SoftAuthenticator::b64url( random_bytes( 32 ) ) ], WebAuthnException::INVALID_CHALLENGE );
		$pem = $this->process_create( $auth )->credentialPublicKey;
		$this->assert_rejected(
			function () use ( $auth, $pem ): void {
				$this->process_get( $auth, $pem, [ 'challenge' => SoftAuthenticator::b64url( random_bytes( 32 ) ) ] );
			},
			WebAuthnException::INVALID_CHALLENGE
		);
	}

	public function test_cross_origin_string_true_and_top_origin_accepted(): void {
		// Audit row 13: only crossOrigin === true is rejected; W3 requires
		// crossOrigin absent or false and topOrigin absent.
		$auth = new SoftAuthenticator( 'ES256' );
		$this->process_create( $auth, [ 'crossOrigin' => 'true' ] );
		$this->process_create( $auth, [ 'topOrigin' => 'https://evil.example' ] );
		$pem = $this->process_create( $auth, [ 'crossOrigin' => 1 ] )->credentialPublicKey;
		$this->assertTrue( $this->process_get( $auth, $pem, [ 'crossOrigin' => 'true' ] ) );
		$this->assertTrue(
			$this->process_get(
				$auth,
				$pem,
				[
					'crossOrigin' => false,
					'topOrigin'   => 'https://evil.example',
				]
			)
		);

		$this->assert_create_rejected( $auth, [ 'crossOrigin' => true ], WebAuthnException::INVALID_ORIGIN );
		$this->assert_rejected(
			function () use ( $auth, $pem ): void {
				$this->process_get( $auth, $pem, [ 'crossOrigin' => true ] );
			},
			WebAuthnException::INVALID_ORIGIN
		);
	}

	public function test_client_data_type_and_shape_checks(): void {
		$auth = new SoftAuthenticator( 'ES256' );
		$this->assert_create_rejected( $auth, [ 'type' => 'webauthn.get' ], WebAuthnException::INVALID_TYPE );
		$this->assert_create_rejected( $auth, [ 'clientData' => [ 'type' => SoftAuthenticator::OMIT ] ], WebAuthnException::INVALID_TYPE );
		$this->assert_create_rejected( $auth, [ 'clientData' => [ 'challenge' => SoftAuthenticator::OMIT ] ], WebAuthnException::INVALID_CHALLENGE );
		$this->assert_create_rejected( $auth, [ 'clientData' => [ 'origin' => SoftAuthenticator::OMIT ] ], WebAuthnException::INVALID_ORIGIN );
		$this->assert_create_rejected( $auth, [ 'clientDataJSON' => '["webauthn.create"]' ], WebAuthnException::INVALID_DATA );
		$this->assert_create_rejected( $auth, [ 'clientDataJSON' => 'not json' ], WebAuthnException::INVALID_DATA );
		$this->assert_create_rejected( $auth, [ 'clientDataJSON' => str_repeat( '[', 100000 ) . str_repeat( ']', 100000 ) ], WebAuthnException::INVALID_DATA );
		$this->assert_create_rejected( $auth, [ 'bom' => true ], WebAuthnException::INVALID_DATA );
		$this->assert_create_rejected( $auth, [ 'clientData' => [ 'tokenBinding' => [ 'status' => 'present' ] ] ], WebAuthnException::INVALID_DATA );

		$pem = $this->process_create( $auth )->credentialPublicKey;
		$this->assert_rejected(
			function () use ( $auth, $pem ): void {
				$this->process_get( $auth, $pem, [ 'type' => 'webauthn.create' ] );
			},
			WebAuthnException::INVALID_TYPE
		);
	}

	// ------------------------------------------------------------------
	// Audit 3 rows 14 to 17: counter, UV/UP, BE/BS (W5, W7).
	// ------------------------------------------------------------------

	/** @return array<string,array{mixed,int,bool}> */
	public static function counters(): array {
		return [
			'stored "0" string, new 0 (audit row 14)' => [ '0', 0, false ],
			'stored int 0, new 0'                     => [ 0, 0, true ],
			'stored "0" string, new 5'                => [ '0', 5, true ],
			'5 vs 5 (audit row 15)'                   => [ 5, 5, false ],
			'stored 4, new 0 (audit row 15)'          => [ 4, 0, false ],
			'stored 4, new 5 (audit row 15)'          => [ 4, 5, true ],
			'stored 6, new 5'                         => [ 6, 5, false ],
			'prev null, new 0'                        => [ null, 0, true ],
			'prev null, new 3'                        => [ null, 3, true ],
		];
	}

	/**
	 * @dataProvider counters
	 * @param mixed $stored
	 */
	public function test_counter_policy( $stored, int $new, bool $accepted ): void {
		$auth = new SoftAuthenticator( 'ES256' );
		$pem  = $this->process_create( $auth )->credentialPublicKey;
		if ( $accepted ) {
			$this->assertTrue( $this->process_get( $auth, $pem, [ 'sign_count' => $new ], $stored ) );
			return;
		}
		$this->assert_rejected(
			function () use ( $auth, $pem, $new, $stored ): void {
				$this->process_get( $auth, $pem, [ 'sign_count' => $new ], $stored );
			},
			WebAuthnException::SIGNATURE_COUNTER
		);
	}

	public function test_counter_is_readable_from_authenticator_data(): void {
		// W7 reads the counter here (getSignatureCounter() keeps stale state).
		$auth = new SoftAuthenticator( 'ES256' );
		$json = $auth->assert( self::request( random_bytes( 32 ) ), self::ORIGIN, [ 'sign_count' => 4294967295 ] );
		$ad   = new AuthenticatorData( SoftAuthenticator::b64url_decode( $json['response']['authenticatorData'] ) );
		$this->assertSame( 4294967295, $ad->getSignCount() );
	}

	public function test_user_verification_needs_the_caller_to_ask(): void {
		// Audit row 16: UV is only checked when required (W5 always passes true).
		$auth = new SoftAuthenticator( 'ES256', [ 'uv' => false ] );
		$data = $this->process_create( $auth, [], false );
		$this->assertFalse( $data->userVerified );
		$this->assert_create_rejected( $auth, [], WebAuthnException::USER_VERIFICATED );

		$this->assertTrue( $this->process_get( $auth, $data->credentialPublicKey, [], null, false ) );
		$this->assert_rejected(
			function () use ( $auth, $data ): void {
				$this->process_get( $auth, $data->credentialPublicKey );
			},
			WebAuthnException::USER_VERIFICATED
		);
	}

	public function test_user_presence_required(): void {
		$auth = new SoftAuthenticator( 'ES256', [ 'up' => false ] );
		$this->assert_create_rejected( $auth, [], WebAuthnException::USER_PRESENT );
		$pem = $this->process_create( new SoftAuthenticator( 'ES256' ) )->credentialPublicKey;
		$this->assert_rejected(
			function () use ( $auth, $pem ): void {
				$this->process_get( $auth, $pem );
			},
			WebAuthnException::USER_PRESENT
		);
	}

	public function test_backup_eligibility_flip_is_not_seen_by_the_library(): void {
		// Audit row 17: processGet() hides the flags; W7 parses AuthenticatorData.
		$auth = new SoftAuthenticator( 'ES256', [ 'be' => true ] );
		$data = $this->process_create( $auth );
		$this->assertTrue( $data->isBackupEligible );

		$json = $auth->assert( self::request( random_bytes( 32 ) ), self::ORIGIN, [ 'flags' => self::FLAGS_UP_UV ] );
		$this->assertTrue( $this->process_get( $auth, $data->credentialPublicKey, [ 'flags' => self::FLAGS_UP_UV ] ) );
		$ad = new AuthenticatorData( SoftAuthenticator::b64url_decode( $json['response']['authenticatorData'] ) );
		$this->assertFalse( $ad->getIsBackupEligible() );
		$this->assertFalse( $ad->getIsBackup() );
		$this->assertTrue( $ad->getUserVerified() );
	}

	public function test_backup_state_without_eligibility_rejected(): void {
		$flags = self::FLAGS_UP_UV | SoftAuthenticator::FLAG_BS;
		$this->assert_create_rejected( new SoftAuthenticator( 'ES256' ), [ 'flags' => $flags | SoftAuthenticator::FLAG_AT ], WebAuthnException::INVALID_DATA );
		$auth = new SoftAuthenticator( 'ES256' );
		$pem  = $this->process_create( $auth )->credentialPublicKey;
		$this->assert_rejected(
			function () use ( $auth, $pem, $flags ): void {
				$this->process_get( $auth, $pem, [ 'flags' => $flags ] );
			},
			WebAuthnException::INVALID_DATA
		);
	}

	public function test_rp_id_hash_mismatch_rejected(): void {
		$auth = new SoftAuthenticator( 'ES256' );
		$this->assert_create_rejected( $auth, [ 'rpId' => 'example' ], WebAuthnException::INVALID_RELYING_PARTY );
		$pem = $this->process_create( $auth )->credentialPublicKey;
		$this->assert_rejected(
			function () use ( $auth, $pem ): void {
				$this->process_get( $auth, $pem, [ 'rpId' => 'evil.academy.example' ] );
			},
			WebAuthnException::INVALID_RELYING_PARTY
		);
	}

	/** @return array<string,array{int,bool}> */
	public static function credential_id_lengths(): array {
		return [
			'15 bytes'   => [ 15, false ],
			'16 bytes'   => [ 16, true ],
			'1023 bytes' => [ 1023, true ],
			'1024 bytes' => [ 1024, false ],
		];
	}

	/** @dataProvider credential_id_lengths */
	public function test_credential_id_length( int $length, bool $accepted ): void {
		$auth = new SoftAuthenticator( 'ES256', [ 'credential_id' => random_bytes( $length ) ] );
		if ( $accepted ) {
			$this->assertSame( $length, strlen( $this->process_create( $auth )->credentialId ) );
			return;
		}
		$this->assert_create_rejected( $auth, [], WebAuthnException::INVALID_DATA );
	}

	public function test_credential_id_length_beyond_the_buffer_rejected(): void {
		$auth = new SoftAuthenticator( 'ES256' );
		$ad   = hash( 'sha256', self::RP_ID, true ) . chr( self::FLAGS_UP_UV | SoftAuthenticator::FLAG_AT ) . pack( 'N', 0 )
			. str_repeat( "\0", 16 ) . pack( 'n', 600 ) . random_bytes( 100 );
		$this->assert_create_rejected( $auth, [ 'authData' => $ad ], WebAuthnException::INVALID_DATA );
	}

	public function test_attested_data_flag_missing_rejected(): void {
		$this->assert_create_rejected( new SoftAuthenticator( 'ES256' ), [ 'flags' => self::FLAGS_UP_UV ] );
	}

	// ------------------------------------------------------------------
	// Audit 3 row 18: Ed25519 signature length (H2).
	// ------------------------------------------------------------------

	public function test_h2_ed25519_63_byte_signature_is_a_webauthn_exception(): void {
		// The sodium branch on PHP < 8.4, the OpenSSL branch on 8.4+; both
		// end in WebAuthnException. The sodium branch on 8.4+ is the
		// separate-process case below.
		$this->require_alg( 'EdDSA' );
		$auth = new SoftAuthenticator( 'EdDSA' );
		$pem  = $this->process_create( $auth )->credentialPublicKey;
		foreach ( [ 63, 65, 0 ] as $length ) {
			$this->assert_rejected(
				function () use ( $auth, $pem, $length ): void {
					$this->process_get( $auth, $pem, [ 'signature' => substr( $auth->sign( 'x' ) . 'pad', 0, $length ) ] );
				},
				WebAuthnException::INVALID_SIGNATURE
			);
		}
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_h2_sodium_branch_forced(): void {
		if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
			$this->markTestSkipped( 'ext-sodium missing' );
		}
		require dirname( __DIR__ ) . '/Support/force-sodium-path.php';
		$this->assertFalse( \MagicAuth\ThirdParty\Passkeys\defined( 'OPENSSL_KEYTYPE_ED25519' ) );

		$auth = new SoftAuthenticator( 'EdDSA' );
		$pem  = $this->process_create( $auth )->credentialPublicKey;
		$this->assertTrue( $this->process_get( $auth, $pem ) );
		foreach ( [ 63, 65, 0 ] as $length ) {
			$this->assert_rejected(
				function () use ( $auth, $pem, $length ): void {
					$this->process_get( $auth, $pem, [ 'signature' => substr( $auth->sign( 'x' ) . 'pad', 0, $length ) ] );
				},
				WebAuthnException::INVALID_SIGNATURE
			);
		}
		$this->assert_rejected(
			function () use ( $auth, $pem ): void {
				$this->process_get( $auth, $pem, [ 'signature' => random_bytes( 64 ) ] );
			},
			WebAuthnException::INVALID_SIGNATURE
		);

		// R3 on the same branch.
		$this->assertSame( -8, $this->process_create( $auth, [ 'self_attest' => true ] )->credentialAlg );
		$this->assert_create_rejected( $auth, [ 'self_attest' => true, 'attStmt' => [ 'sig' => Cbor::bytes( random_bytes( 64 ) ) ] ] );
		$this->assert_create_rejected( $auth, [ 'self_attest' => true, 'attStmt' => [ 'sig' => Cbor::bytes( random_bytes( 63 ) ) ] ] );
	}

	// ------------------------------------------------------------------
	// Audit 3 rows 19 to 23: CBOR decoder limits (R2).
	// ------------------------------------------------------------------

	/**
	 * Audit row 19: this payload segfaulted PHP 8.5 before R2. Runs in its own
	 * process, so a regression fails this test instead of killing the suite.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_r2_assertion_extension_depth_bomb_rejected(): void {
		$auth = new SoftAuthenticator( 'ES256' );
		$pem  = $this->process_create( $auth )->credentialPublicKey;
		$bomb = hash( 'sha256', self::RP_ID, true ) . chr( self::FLAGS_UP_UV | SoftAuthenticator::FLAG_ED ) . pack( 'N', 0 )
			. Cbor::nested_array( 100000 );
		$this->assertGreaterThan( 100000, strlen( $bomb ) );
		$this->assert_rejected(
			function () use ( $auth, $pem, $bomb ): void {
				$this->process_get( $auth, $pem, [ 'authData' => $bomb ] );
			},
			WebAuthnException::CBOR
		);
	}

	public function test_r2_attestation_depth_bomb_rejected(): void {
		// 15 KB of nesting in the COSE key position (under the 16 KB cap of W1).
		$this->assert_create_rejected(
			new SoftAuthenticator( 'ES256' ),
			[
				'cose' => static function () {
					return Cbor::raw( Cbor::nested_array( 15000 ) );
				},
			],
			WebAuthnException::CBOR
		);
	}

	public function test_r2_depth_limit_is_16(): void {
		$this->assertIsArray( CborDecoder::decode( Cbor::nested_array( 16 ) ) );
		$this->assert_cbor_rejected( Cbor::nested_array( 17 ) );

		$this->assertIsArray( CborDecoder::decode( str_repeat( "\xa1\x00", 16 ) . "\xa0" ) );
		$this->assert_cbor_rejected( str_repeat( "\xa1\x00", 17 ) . "\xa0" );

		$this->assertSame( 0, CborDecoder::decode( str_repeat( "\xc6", 16 ) . "\x00" ) );
		$this->assert_cbor_rejected( str_repeat( "\xc6", 17 ) . "\x00" );

		// Mixed nesting: arrays inside maps inside tags.
		$this->assert_cbor_rejected( str_repeat( "\xc6\xa1\x00\x81", 6 ) . "\x80" );

		// The limit is per path, not a total: wide structures are fine.
		$this->assertCount( 3, CborDecoder::decode( "\x83" . Cbor::nested_array( 15 ) . Cbor::nested_array( 15 ) . Cbor::nested_array( 15 ) ) );

		// decodeInPlace() starts at depth 0 too.
		$end = 0;
		$this->assertIsArray( CborDecoder::decodeInPlace( "\x00\x00" . Cbor::nested_array( 16 ) . "\x00", 2, $end ) );
		$this->assertSame( 2 + 17, $end );
	}

	/**
	 * Audit row 20: before R2 this exhausted the call stack (an Error, not
	 * WebAuthnException). Own process, as above.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_r2_200k_nested_tags_rejected(): void {
		$this->assert_cbor_rejected( str_repeat( "\xc6", 200000 ) . "\x00" );
	}

	/** @return array<string,array{string}> */
	public static function bad_lengths(): array {
		return [
			'array of 2^32-1 items, 4 present' => [ "\x9a\xff\xff\xff\xff" . "\x00\x00\x00\x00" ],
			'byte string of 2^63-1 bytes'      => [ "\x5b\x7f\xff\xff\xff\xff\xff\xff\xff" . 'abc' ],
			'uint64 over PHP_INT_MAX'          => [ "\x1b\xff\xff\xff\xff\xff\xff\xff\xff" ],
			'map of 2^64-1 entries'            => [ "\xbb\xff\xff\xff\xff\xff\xff\xff\xff" ],
			'indefinite array'                 => [ "\x9f\x00\xff" ],
			'indefinite byte string'           => [ "\x5f\x41\x00\xff" ],
			'reserved length'                  => [ "\x1c" ],
			'simple value 23 (undefined)'      => [ "\xf7" ],
			'truncated'                        => [ "\x58\x10\x00" ],
			'empty input'                      => [ '' ],
			'trailing bytes'                   => [ "\x00\x00" ],
		];
	}

	/** @dataProvider bad_lengths */
	public function test_r2_declared_lengths_and_reserved_values_rejected( string $cbor ): void {
		// Audit row 21: rejected cleanly, nothing allocated from a declared length.
		$this->assert_rejected(
			static function () use ( $cbor ): void {
				CborDecoder::decode( $cbor );
			}
		);
	}

	public function test_r2_wide_array_of_empty_arrays(): void {
		// Audit row 22: 300k empty arrays in one array. The decoder walks
		// them without error (depth 1); in an assertion the extension data is
		// signed, so the library rejects only an unsigned copy. W1 caps
		// assertion authData at 1 KB before any decoding.
		$wide = "\x9a" . pack( 'N', 300000 ) . str_repeat( "\x80", 300000 );
		$this->assertSame( 300000, count( CborDecoder::decode( $wide ) ) ); // not assertCount(): PHPUnit would export the array

		$auth = new SoftAuthenticator( 'ES256' );
		$pem  = $this->process_create( $auth )->credentialPublicKey;
		$ad   = hash( 'sha256', self::RP_ID, true ) . chr( self::FLAGS_UP_UV | SoftAuthenticator::FLAG_ED ) . pack( 'N', 0 ) . $wide;
		$this->assert_rejected(
			function () use ( $auth, $pem, $ad ): void {
				$this->process_get(
					$auth,
					$pem,
					[
						'authData'  => $ad,
						'signature' => $auth->sign( 'not the authenticator data' ),
					]
				);
			},
			WebAuthnException::INVALID_SIGNATURE
		);
	}

	public function test_auth_data_shorter_than_37_bytes_rejected(): void {
		// Audit row 23.
		foreach ( [ '', str_repeat( "\0", 36 ) ] as $short ) {
			$this->assert_rejected(
				static function () use ( $short ): void {
					new AuthenticatorData( $short );
				},
				WebAuthnException::INVALID_DATA
			);
		}
		$auth = new SoftAuthenticator( 'ES256' );
		$pem  = $this->process_create( $auth )->credentialPublicKey;
		$this->assert_rejected(
			function () use ( $auth, $pem ): void {
				$this->process_get( $auth, $pem, [ 'authData' => str_repeat( "\0", 36 ) ] );
			},
			WebAuthnException::INVALID_DATA
		);
	}

	public function test_r2_duplicate_and_numeric_text_map_keys(): void {
		$this->assert_cbor_rejected( Cbor::map_with_duplicate_key( 1, 2, 2 ) );
		$this->assert_cbor_rejected( Cbor::map_with_duplicate_key( -3, 2, 5 ) );
		$this->assert_cbor_rejected( Cbor::map_with_duplicate_key( 'fmt', 'none', 'packed' ) );
		$this->assert_cbor_rejected( "\xa1" . Cbor::encode( '3' ) . Cbor::encode( 1 ) );
		$this->assert_cbor_rejected( "\xa1" . Cbor::encode( '-1' ) . Cbor::encode( 1 ) );
		$this->assert_cbor_rejected( "\xa1" . Cbor::encode( '0' ) . Cbor::encode( 1 ) );
		// Text "3" next to integer 3 would collide too.
		$this->assert_cbor_rejected( "\xa2" . Cbor::encode( 3 ) . Cbor::encode( 1 ) . Cbor::encode( '3' ) . Cbor::encode( 2 ) );

		// Text keys PHP keeps as strings stay valid.
		$this->assertSame(
			[
				'03'  => 1,
				'3.0' => 2,
				' 3'  => 3,
				'-0'  => 4,
			],
			CborDecoder::decode( "\xa4" . Cbor::encode( '03' ) . "\x01" . Cbor::encode( '3.0' ) . "\x02" . Cbor::encode( ' 3' ) . "\x03" . Cbor::encode( '-0' ) . "\x04" )
		);
		// Byte string keys were and are rejected.
		$this->assert_cbor_rejected( "\xa1" . Cbor::encode( Cbor::bytes( 'k' ) ) . "\x01" );
	}

	// ------------------------------------------------------------------
	// R4, H1, R0: static properties of the vendored files.
	// ------------------------------------------------------------------

	public function test_r4_every_exception_message_is_a_static_string(): void {
		$found = 0;
		foreach ( self::PHP_FILES as $file ) {
			$tokens = array_values(
				array_filter(
					token_get_all( (string) file_get_contents( self::DIR . $file ) ),
					static function ( $t ): bool {
						return ! is_array( $t ) || ! in_array( $t[0], [ T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ], true );
					}
				)
			);
			foreach ( $tokens as $i => $token ) {
				if ( ! is_array( $token ) || T_NEW !== $token[0] ) {
					continue;
				}
				$name = $tokens[ $i + 1 ];
				if ( ! is_array( $name ) || 'WebAuthnException' !== substr( $name[1], -17 ) ) {
					continue;
				}
				++$found;
				$where = $file . ':' . $token[2];
				$this->assertSame( '(', $tokens[ $i + 2 ], $where );
				$message = $tokens[ $i + 3 ];
				$this->assertTrue( is_array( $message ) && T_CONSTANT_ENCAPSED_STRING === $message[0], $where . ': message is not a literal' );
				$this->assertContains( $tokens[ $i + 4 ], [ ',', ')' ], $where . ': message is an expression' );
				$this->assertStringStartsWith( "'", $message[1], $where . ': message is not single-quoted' );
			}
		}
		$this->assertGreaterThan( 50, $found );
	}

	public function test_r4_messages_carry_no_input(): void {
		$fmt = '<script>alert(1)</script> fmt';
		$e   = $this->assert_create_rejected( new SoftAuthenticator( 'ES256' ), [ 'fmt' => $fmt ], WebAuthnException::INVALID_DATA );
		$this->assertStringNotContainsString( 'script', $e->getMessage() );

		$e = $this->assert_rejected(
			static function (): void {
				CborDecoder::decode( "\xf7" );
			},
			WebAuthnException::CBOR
		);
		$this->assertStringNotContainsString( '23', $e->getMessage() );

		$e = $this->assert_rejected(
			static function (): void {
				( new ByteBuffer( '{"a":' ) )->getJson();
			},
			WebAuthnException::BYTEBUFFER
		);
		$this->assertStringNotContainsString( 'Syntax', $e->getMessage() );
	}

	public function test_h1_byte_buffer_has_no_serialization_sink(): void {
		$class = new \ReflectionClass( ByteBuffer::class );
		$this->assertFalse( $class->implementsInterface( \Serializable::class ) );
		foreach ( [ 'serialize', 'unserialize', '__serialize', '__unserialize' ] as $method ) {
			$this->assertFalse( $class->hasMethod( $method ), $method );
		}
		foreach ( self::PHP_FILES as $file ) {
			foreach ( token_get_all( (string) file_get_contents( self::DIR . $file ) ) as $token ) {
				if ( is_array( $token ) && T_STRING === $token[0] ) {
					$this->assertNotContains( strtolower( $token[1] ), [ 'unserialize', 'serialize' ], $file );
				}
			}
		}
		// JSON encoding is unchanged (the WebAuthn constructor sets base64url).
		new WebAuthn( self::RP_ID, self::RP_ID, true );
		$this->assertSame( '"' . SoftAuthenticator::b64url( 'ab?' ) . '"', json_encode( new ByteBuffer( 'ab?' ) ) );
	}

	public function test_r0_namespace_guard_and_no_includes(): void {
		foreach ( self::PHP_FILES as $file ) {
			$src = (string) file_get_contents( self::DIR . $file );
			$this->assertMatchesRegularExpression( '/^<\?php\s+namespace MagicAuth\\\\ThirdParty\\\\Passkeys(\\\\[A-Za-z]+)?;\ndefined\( \'ABSPATH\' \) \|\| exit;\n/', $src, $file );
			$this->assertStringNotContainsString( 'ReportUri', $src, $file );
			$this->assertDoesNotMatchRegularExpression( '/^\s*(require|include)(_once)?\b/m', $src, $file );
			$this->assertDoesNotMatchRegularExpression( '/declare\s*\(\s*strict_types/', $src, $file );
		}
		$this->assertFileExists( self::DIR . 'LICENSE' );
		$this->assertStringContainsString( 'MIT License', (string) file_get_contents( self::DIR . 'LICENSE' ) );
		$this->assertFileExists( self::DIR . 'NOTICE.md' );
	}

	public function test_r0_files_exit_without_abspath(): void {
		foreach ( self::PHP_FILES as $file ) {
			$out = shell_exec( escapeshellarg( PHP_BINARY ) . ' -n -r ' . escapeshellarg( 'require $argv[1]; echo "LOADED";' ) . ' ' . escapeshellarg( self::DIR . $file ) . ' 2>&1' );
			$this->assertSame( '', (string) $out, $file );
		}
	}

	public function test_vendored_md_matches_the_pin_and_the_files(): void {
		$md       = (string) file_get_contents( self::DIR . 'VENDORED.md' );
		$upstream = (string) file_get_contents( MAGICAUTH_DIR . 'tools/passkeys-php/UPSTREAM' );
		foreach ( [ 'COMMIT', 'TREE', 'TAG', 'URL' ] as $key ) {
			$this->assertSame( 1, preg_match( '/^' . $key . '=(\S+)$/m', $upstream, $m ), $key );
			$this->assertStringContainsString( $m[1], $md, $key );
		}
		$this->assertStringContainsString( 'f8cddbfe00f9ecff1eebeb6bcae18b111f6bc468', $upstream );
		$this->assertStringContainsString( 'a61b2aae6718db5addc2d51e7f33900a5b9d4e7c', $upstream );

		foreach ( self::PATCHES as $patch ) {
			$this->assertFileExists( MAGICAUTH_DIR . 'tools/passkeys-php/patches/' . $patch );
			$this->assertStringContainsString( '`' . $patch . '`', $md );
		}
		$this->assertSame( self::PATCHES, array_map( 'basename', (array) glob( MAGICAUTH_DIR . 'tools/passkeys-php/patches/*.patch' ) ) );

		// sha256 table: every shipped file, and nothing else.
		preg_match_all( '/^\| `([^`]+)` \| `([0-9a-f]{64})` \|$/m', $md, $rows, PREG_SET_ORDER );
		$listed = [];
		foreach ( $rows as $row ) {
			$listed[ $row[1] ] = $row[2];
		}
		$files = [];
		$iter  = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( self::DIR, \FilesystemIterator::SKIP_DOTS ) );
		foreach ( $iter as $info ) {
			$rel = substr( $info->getPathname(), strlen( self::DIR ) );
			if ( 'VENDORED.md' === $rel || '.DS_Store' === $info->getFilename() ) {
				continue;
			}
			$files[ $rel ] = hash_file( 'sha256', $info->getPathname() );
		}
		ksort( $files );
		ksort( $listed );
		$this->assertSame( $files, $listed, 'VENDORED.md sha256 table does not match the tree: never edit it by hand, rerun vendor.sh' );
		$this->assertCount( 8, $files );
	}

	// ------------------------------------------------------------------
	// W3C L3 section 16 vectors through the raw library.
	// ------------------------------------------------------------------

	public function test_w3c_vectors(): void {
		$rp = Fixtures::RP_ID;
		foreach ( [ '16.2', '16.6' ] as $id ) {
			$data = ( new WebAuthn( $rp, $rp, true ) )->processCreate(
				Fixtures::bin( $id, 'registration', 'clientDataJSON' ),
				Fixtures::bin( $id, 'registration', 'attestationObject' ),
				Fixtures::bin( $id, 'registration', 'challenge' ),
				false,
				true
			);
			$this->assertSame( Fixtures::bin( $id, 'registration', 'credential_id' ), $data->credentialId, $id );
			$this->assertSame( -7, $data->credentialAlg, $id );
			$this->assertFalse( $data->userVerified, $id . ': the vectors do not set UV' );
		}

		// 16.4 crossOrigin true: the library's own check.
		$this->assert_rejected(
			static function () use ( $rp ): void {
				( new WebAuthn( $rp, $rp, true ) )->processCreate(
					Fixtures::bin( '16.4', 'registration', 'clientDataJSON' ),
					Fixtures::bin( '16.4', 'registration', 'attestationObject' ),
					Fixtures::bin( '16.4', 'registration', 'challenge' ),
					false,
					true
				);
			},
			WebAuthnException::INVALID_ORIGIN
		);

		// 16.11: packed with x5c (full attestation) is rejected (R3). 16.10
		// fails earlier: its RSA modulus is 436 bytes and the library takes
		// 2048-bit keys only (audit 4.3 and 11.4).
		foreach ( [ '16.10' => WebAuthnException::INVALID_PUBLIC_KEY, '16.11' => WebAuthnException::INVALID_DATA ] as $id => $code ) {
			$this->assert_rejected(
				static function () use ( $rp, $id ): void {
					( new WebAuthn( $rp, $rp, true ) )->processCreate(
						Fixtures::bin( $id, 'registration', 'clientDataJSON' ),
						Fixtures::bin( $id, 'registration', 'attestationObject' ),
						Fixtures::bin( $id, 'registration', 'challenge' ),
						false,
						true
					);
				},
				$code
			);
		}

		// Authentication halves: every signature verifies with the key from
		// the registration authData; 16.4 and 16.5 (crossOrigin true with a
		// topOrigin) fail on the library's crossOrigin check. 16.10's key
		// cannot be parsed (above).
		$expected = [
			'16.2'  => true,
			'16.4'  => false,
			'16.5'  => false,
			'16.6'  => true,
			'16.11' => true,
		];
		foreach ( $expected as $id => $ok ) {
			if ( '16.11' === $id && ! self::eddsa_available() ) {
				continue;
			}
			$att = CborDecoder::decode( Fixtures::bin( $id, 'registration', 'attestationObject' ) );
			$pem = ( new AuthenticatorData( $att['authData']->getBinaryString() ) )->getPublicKeyPem();
			$run = static function () use ( $rp, $id, $pem ): bool {
				return ( new WebAuthn( $rp, $rp, true ) )->processGet(
					Fixtures::bin( $id, 'authentication', 'clientDataJSON' ),
					Fixtures::bin( $id, 'authentication', 'authenticatorData' ),
					Fixtures::bin( $id, 'authentication', 'signature' ),
					$pem,
					Fixtures::bin( $id, 'authentication', 'challenge' ),
					null,
					false,
					true
				);
			};
			if ( $ok ) {
				$this->assertTrue( $run(), $id );
			} else {
				$this->assert_rejected( $run, WebAuthnException::INVALID_ORIGIN );
			}
		}
	}

	// ------------------------------------------------------------------
	// Helpers.
	// ------------------------------------------------------------------

	/** @return array<string,mixed> */
	private static function options( string $challenge ): array {
		return [
			'challenge'        => SoftAuthenticator::b64url( $challenge ),
			'rp'               => [
				'id'   => self::RP_ID,
				'name' => self::RP_ID,
			],
			'user'             => [
				'id'          => SoftAuthenticator::b64url( random_bytes( 32 ) ),
				'name'        => 'learner@academy.example',
				'displayName' => '',
			],
			'pubKeyCredParams' => [
				[
					'type' => 'public-key',
					'alg'  => -8,
				],
				[
					'type' => 'public-key',
					'alg'  => -7,
				],
				[
					'type' => 'public-key',
					'alg'  => -257,
				],
			],
		];
	}

	/** @return array<string,mixed> */
	private static function request( string $challenge ): array {
		return [
			'challenge' => SoftAuthenticator::b64url( $challenge ),
			'rpId'      => self::RP_ID,
		];
	}

	/** @param array<string,mixed> $o */
	private function process_create( SoftAuthenticator $auth, array $o = [], bool $uv = true ): \stdClass {
		$challenge = random_bytes( 32 );
		$json      = $auth->register( self::options( $challenge ), self::ORIGIN, $o );
		$data      = ( new WebAuthn( self::RP_ID, self::RP_ID, true ) )->processCreate(
			SoftAuthenticator::b64url_decode( $json['response']['clientDataJSON'] ),
			SoftAuthenticator::b64url_decode( $json['response']['attestationObject'] ),
			$challenge,
			$uv,
			true
		);
		$this->assertInstanceOf( \stdClass::class, $data );
		return $data;
	}

	/**
	 * @param array<string,mixed> $o
	 * @param mixed               $prev
	 */
	private function process_get( SoftAuthenticator $auth, string $pem, array $o = [], $prev = null, bool $uv = true ): bool {
		$challenge = random_bytes( 32 );
		$json      = $auth->assert( self::request( $challenge ), self::ORIGIN, $o );
		$result    = ( new WebAuthn( self::RP_ID, self::RP_ID, true ) )->processGet(
			SoftAuthenticator::b64url_decode( $json['response']['clientDataJSON'] ),
			SoftAuthenticator::b64url_decode( $json['response']['authenticatorData'] ),
			SoftAuthenticator::b64url_decode( $json['response']['signature'] ),
			$pem,
			$challenge,
			$prev,
			$uv,
			true
		);
		$this->assertTrue( $result, 'processGet() returns true or throws, never false' );
		return $result;
	}

	/** @param array<string,mixed> $o */
	private function assert_create_rejected( SoftAuthenticator $auth, array $o, ?int $code = null ): WebAuthnException {
		return $this->assert_rejected(
			function () use ( $auth, $o ): void {
				$this->process_create( $auth, $o );
			},
			$code
		);
	}

	private function assert_cbor_rejected( string $cbor ): void {
		$this->assert_rejected(
			static function () use ( $cbor ): void {
				CborDecoder::decode( $cbor );
			},
			WebAuthnException::CBOR
		);
	}

	/** Runs $fn and requires a WebAuthnException (with $code, when given); any other Throwable fails. */
	private function assert_rejected( callable $fn, ?int $code = null ): WebAuthnException {
		try {
			$fn();
		} catch ( WebAuthnException $e ) {
			$this->addToAssertionCount( 1 );
			if ( null !== $code ) {
				$this->assertSame( $code, $e->getCode(), 'code ' . $e->getCode() . ': ' . $e->getMessage() );
			}
			return $e;
		}
		$this->fail( 'accepted, expected WebAuthnException' . ( null !== $code ? ' code ' . $code : '' ) );
	}

	private function require_alg( string $alg ): void {
		if ( 'EdDSA' === $alg && ! self::eddsa_available() ) {
			$this->markTestSkipped( 'no Ed25519 verifier (ext-sodium or OpenSSL with Ed25519)' );
		}
	}

	private static function eddsa_available(): bool {
		return function_exists( 'sodium_crypto_sign_verify_detached' ) || defined( 'OPENSSL_KEYTYPE_ED25519' );
	}

	private static function pem_to_der( string $pem ): string {
		return (string) base64_decode( (string) preg_replace( '/-----[^-]+-----|\s+/', '', $pem ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
	}

	/** ECDSA DER signature to raw r || s (32 bytes each). */
	private static function der_to_raw( string $der ): string {
		$offset = 2;
		$parts  = [];
		for ( $i = 0; $i < 2; $i++ ) {
			$len      = ord( $der[ $offset + 1 ] );
			$parts[]  = str_pad( ltrim( substr( $der, $offset + 2, $len ), "\0" ), 32, "\0", STR_PAD_LEFT );
			$offset  += 2 + $len;
		}
		return $parts[0] . $parts[1];
	}
}
