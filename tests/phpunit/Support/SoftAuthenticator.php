<?php
/**
 * Software WebAuthn authenticator plus client for PHPUnit (SPEC 14.1).
 * Produces toJSON-shaped PublicKeyCredential arrays for registration and
 * assertion, signed with real keys: ES256 (openssl prime256v1, DER signature),
 * RS256 (openssl 2048-bit, PKCS#1 v1.5) or EdDSA (sodium Ed25519).
 * Test support only; never shipped.
 *
 * Constructor $opts: be, bs, uv, up (bool), sign_count (int), aaguid (16 raw
 * bytes, default all zero), credential_id (raw, default 32 random bytes),
 * transports (list), user_handle (raw, for assert() without a register()).
 *
 * Per-call overrides $o (register and assert unless noted):
 * - clientData: array merged into the client data (a value of self::OMIT
 *   removes the key) or a raw JSON string; type, challenge, origin,
 *   crossOrigin, topOrigin: single members; bom: prefix a UTF-8 BOM;
 *   clientDataJSON: raw bytes, used verbatim.
 * - rpId (for rpIdHash), flags (whole flags byte), sign_count, authData (raw,
 *   replaces the built authenticator data), append_authdata (bytes appended).
 * - register only: fmt, attStmt (array, encoded as a map), self_attest (packed
 *   {alg, sig} signed with the credential key), cose (array merged into the
 *   COSE key map, OMIT removes a label, or a callable mapping the map to a new
 *   map or to a Raw), alg_label (response.publicKeyAlgorithm), credProps_rk
 *   (null omits credProps), transports, attestationObject (raw, verbatim).
 * - assert only: signature (raw), userHandle (raw bytes, or null to omit).
 * - rawId, id: final JSON string values.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Support;

final class SoftAuthenticator {

	/** Override value that removes a key (client data member or COSE label). */
	public const OMIT = "\0omit";

	public const FLAG_UP = 0x01;
	public const FLAG_UV = 0x04;
	public const FLAG_BE = 0x08;
	public const FLAG_BS = 0x10;
	public const FLAG_AT = 0x40;
	public const FLAG_ED = 0x80;

	private const COSE_ALGS = [
		'ES256' => -7,
		'RS256' => -257,
		'EdDSA' => -8,
	];

	private string $alg;

	/** @var array<string,mixed> */
	private array $opts;

	/** @var \OpenSSLAsymmetricKey|string openssl key, or the sodium secret key for EdDSA */
	private $private_key;

	private string $public_raw = '';

	/** @var array<string,string> ec x/y, rsa n/e */
	private array $public_parts = [];

	private string $credential_id;

	private ?string $user_handle;

	private int $sign_count;

	/** @param array<string,mixed> $opts */
	public function __construct( string $alg = 'ES256', array $opts = [] ) {
		if ( ! isset( self::COSE_ALGS[ $alg ] ) ) {
			throw new \InvalidArgumentException( 'SoftAuthenticator: unsupported alg ' . $alg );
		}
		$this->alg  = $alg;
		$this->opts = $opts + [
			'be'         => true,
			'bs'         => true,
			'uv'         => true,
			'up'         => true,
			'sign_count' => 0,
			'aaguid'     => str_repeat( "\0", 16 ),
			'transports' => [ 'internal', 'hybrid' ],
		];
		$this->credential_id = isset( $opts['credential_id'] ) ? (string) $opts['credential_id'] : random_bytes( 32 );
		$this->user_handle   = isset( $opts['user_handle'] ) ? (string) $opts['user_handle'] : null;
		$this->sign_count    = (int) $this->opts['sign_count'];
		$this->generate_key();
	}

	public function credentialId(): string {
		return $this->credential_id;
	}

	public function userHandle(): ?string {
		return $this->user_handle;
	}

	public function coseAlg(): int {
		return self::COSE_ALGS[ $this->alg ];
	}

	public function signCount(): int {
		return $this->sign_count;
	}

	/** SubjectPublicKeyInfo DER of the credential public key. */
	public function publicKeyDer(): string {
		if ( 'EdDSA' === $this->alg ) {
			return hex2bin( '302a300506032b6570032100' ) . $this->public_raw;
		}
		$details = openssl_pkey_get_details( $this->private_key );
		$pem     = (string) $details['key'];
		return (string) base64_decode( (string) preg_replace( '/-----[^-]+-----|\s+/', '', $pem ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
	}

	/**
	 * COSE_Key map for the credential (int labels).
	 *
	 * @return array<int,mixed>
	 */
	public function coseKey(): array {
		switch ( $this->alg ) {
			case 'ES256':
				return [
					1  => 2,
					3  => -7,
					-1 => 1,
					-2 => Cbor::bytes( $this->public_parts['x'] ),
					-3 => Cbor::bytes( $this->public_parts['y'] ),
				];
			case 'RS256':
				return [
					1  => 3,
					3  => -257,
					-1 => Cbor::bytes( $this->public_parts['n'] ),
					-2 => Cbor::bytes( $this->public_parts['e'] ),
				];
			default:
				return [
					1  => 1,
					3  => -8,
					-1 => 6,
					-2 => Cbor::bytes( $this->public_raw ),
				];
		}
	}

	/** Sign $data with the credential key: DER for ES256, PKCS#1 v1.5 for RS256, 64 bytes for EdDSA. */
	public function sign( string $data ): string {
		if ( 'EdDSA' === $this->alg ) {
			return sodium_crypto_sign_detached( $data, (string) $this->private_key );
		}
		$signature = '';
		if ( ! openssl_sign( $data, $signature, $this->private_key, OPENSSL_ALGO_SHA256 ) ) {
			throw new \RuntimeException( 'SoftAuthenticator: openssl_sign failed' );
		}
		return $signature;
	}

	/**
	 * navigator.credentials.create() followed by toJSON().
	 *
	 * @param array<string,mixed> $creationOptionsJson PublicKeyCredentialCreationOptionsJSON.
	 * @param array<string,mixed> $o                   Overrides (class docblock).
	 * @return array<string,mixed>
	 */
	public function register( array $creationOptionsJson, string $origin, array $o = [] ): array {
		if ( isset( $creationOptionsJson['user']['id'] ) && is_string( $creationOptionsJson['user']['id'] ) ) {
			$this->user_handle = self::b64url_decode( $creationOptionsJson['user']['id'] );
		}
		if ( array_key_exists( 'sign_count', $o ) ) {
			$this->sign_count = (int) $o['sign_count'];
		}

		$rp_id            = (string) ( $o['rpId'] ?? ( $creationOptionsJson['rp']['id'] ?? '' ) );
		$client_data_json = $this->client_data( 'webauthn.create', (string) ( $creationOptionsJson['challenge'] ?? '' ), $origin, $o );

		$cose = $this->coseKey();
		if ( isset( $o['cose'] ) ) {
			$cose = is_callable( $o['cose'] ) ? ( $o['cose'] )( $cose ) : self::merge_omit( $cose, (array) $o['cose'] );
		}
		$cose_bytes = $cose instanceof Raw ? $cose->bytes : Cbor::encode( Cbor::map( $cose ) );

		if ( isset( $o['authData'] ) ) {
			$auth_data = (string) $o['authData'];
		} else {
			$flags     = $o['flags'] ?? ( $this->flags() | self::FLAG_AT );
			$auth_data = hash( 'sha256', $rp_id, true )
				. chr( (int) $flags )
				. pack( 'N', $this->sign_count )
				. (string) $this->opts['aaguid']
				. pack( 'n', strlen( $this->credential_id ) )
				. $this->credential_id
				. $cose_bytes
				. (string) ( $o['append_authdata'] ?? '' );
		}

		if ( isset( $o['attestationObject'] ) ) {
			$attestation_object = (string) $o['attestationObject'];
		} else {
			$fmt      = (string) ( $o['fmt'] ?? 'none' );
			$att_stmt = isset( $o['attStmt'] ) ? (array) $o['attStmt'] : [];
			if ( ! empty( $o['self_attest'] ) ) {
				$fmt      = (string) ( $o['fmt'] ?? 'packed' );
				$att_stmt = ( isset( $o['attStmt'] ) ? (array) $o['attStmt'] : [] ) + [
					'alg' => $this->coseAlg(),
					'sig' => Cbor::bytes( $this->sign( $auth_data . hash( 'sha256', $client_data_json, true ) ) ),
				];
			}
			$attestation_object = Cbor::encode(
				Cbor::map(
					[
						'fmt'      => $fmt,
						'attStmt'  => Cbor::map( $att_stmt ),
						'authData' => Cbor::bytes( $auth_data ),
					]
				)
			);
		}

		$raw_id     = self::b64url( $this->credential_id );
		$extensions = [];
		$rk         = array_key_exists( 'credProps_rk', $o ) ? $o['credProps_rk'] : true;
		if ( null !== $rk ) {
			$extensions['credProps'] = [ 'rk' => $rk ];
		}

		return [
			'id'                      => (string) ( $o['id'] ?? $raw_id ),
			'rawId'                   => (string) ( $o['rawId'] ?? $raw_id ),
			'type'                    => 'public-key',
			'response'                => [
				'clientDataJSON'     => self::b64url( $client_data_json ),
				'attestationObject'  => self::b64url( $attestation_object ),
				'authenticatorData'  => self::b64url( $auth_data ),
				'transports'         => $o['transports'] ?? $this->opts['transports'],
				'publicKey'          => self::b64url( $this->publicKeyDer() ),
				'publicKeyAlgorithm' => $o['alg_label'] ?? $this->coseAlg(),
			],
			'authenticatorAttachment' => 'platform',
			'clientExtensionResults'  => (object) $extensions,
		];
	}

	/**
	 * navigator.credentials.get() followed by toJSON().
	 *
	 * @param array<string,mixed> $requestOptionsJson PublicKeyCredentialRequestOptionsJSON.
	 * @param array<string,mixed> $o                  Overrides (class docblock).
	 * @return array<string,mixed>
	 */
	public function assert( array $requestOptionsJson, string $origin, array $o = [] ): array {
		if ( array_key_exists( 'sign_count', $o ) ) {
			$this->sign_count = (int) $o['sign_count'];
		} elseif ( $this->sign_count > 0 ) {
			++$this->sign_count;
		}

		$rp_id            = (string) ( $o['rpId'] ?? ( $requestOptionsJson['rpId'] ?? '' ) );
		$client_data_json = $this->client_data( 'webauthn.get', (string) ( $requestOptionsJson['challenge'] ?? '' ), $origin, $o );

		if ( isset( $o['authData'] ) ) {
			$auth_data = (string) $o['authData'];
		} else {
			$auth_data = hash( 'sha256', $rp_id, true )
				. chr( (int) ( $o['flags'] ?? $this->flags() ) )
				. pack( 'N', $this->sign_count )
				. (string) ( $o['append_authdata'] ?? '' );
		}

		$signature = array_key_exists( 'signature', $o )
			? (string) $o['signature']
			: $this->sign( $auth_data . hash( 'sha256', $client_data_json, true ) );

		$response = [
			'clientDataJSON'    => self::b64url( $client_data_json ),
			'authenticatorData' => self::b64url( $auth_data ),
			'signature'         => self::b64url( $signature ),
		];
		$handle   = array_key_exists( 'userHandle', $o ) ? $o['userHandle'] : $this->user_handle;
		if ( null !== $handle ) {
			$response['userHandle'] = self::b64url( (string) $handle );
		}

		$raw_id = self::b64url( $this->credential_id );
		return [
			'id'                      => (string) ( $o['id'] ?? $raw_id ),
			'rawId'                   => (string) ( $o['rawId'] ?? $raw_id ),
			'type'                    => 'public-key',
			'response'                => $response,
			'authenticatorAttachment' => 'platform',
			'clientExtensionResults'  => (object) [],
		];
	}

	public static function b64url( string $bytes ): string {
		return rtrim( strtr( base64_encode( $bytes ), '+/', '-_' ), '=' );
	}

	public static function b64url_decode( string $text ): string {
		$padded = strtr( $text, '-_', '+/' );
		$padded .= str_repeat( '=', ( 4 - strlen( $padded ) % 4 ) % 4 );
		$out     = base64_decode( $padded, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		if ( false === $out ) {
			throw new \InvalidArgumentException( 'SoftAuthenticator: invalid base64url' );
		}
		return $out;
	}

	private function flags(): int {
		$flags = 0;
		if ( $this->opts['up'] ) {
			$flags |= self::FLAG_UP;
		}
		if ( $this->opts['uv'] ) {
			$flags |= self::FLAG_UV;
		}
		if ( $this->opts['be'] ) {
			$flags |= self::FLAG_BE;
		}
		if ( $this->opts['bs'] ) {
			$flags |= self::FLAG_BS;
		}
		return $flags;
	}

	/** @param array<string,mixed> $o */
	private function client_data( string $type, string $challenge, string $origin, array $o ): string {
		if ( isset( $o['clientDataJSON'] ) ) {
			return (string) $o['clientDataJSON'];
		}
		if ( isset( $o['clientData'] ) && is_string( $o['clientData'] ) ) {
			$json = $o['clientData'];
		} else {
			$data = [
				'type'        => $o['type'] ?? $type,
				'challenge'   => $o['challenge'] ?? $challenge,
				'origin'      => $o['origin'] ?? $origin,
				'crossOrigin' => array_key_exists( 'crossOrigin', $o ) ? $o['crossOrigin'] : false,
			];
			if ( array_key_exists( 'topOrigin', $o ) ) {
				$data['topOrigin'] = $o['topOrigin'];
			}
			$data = self::merge_omit( $data, isset( $o['clientData'] ) ? (array) $o['clientData'] : [] );
			$json = (string) json_encode( $data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode
		}
		return ( ! empty( $o['bom'] ) ? "\xEF\xBB\xBF" : '' ) . $json;
	}

	/**
	 * @param array<int|string,mixed> $base
	 * @param array<int|string,mixed> $changes
	 * @return array<int|string,mixed>
	 */
	private static function merge_omit( array $base, array $changes ): array {
		foreach ( $changes as $key => $value ) {
			if ( self::OMIT === $value ) {
				unset( $base[ $key ] );
				continue;
			}
			$base[ $key ] = $value;
		}
		return $base;
	}

	private function generate_key(): void {
		if ( 'EdDSA' === $this->alg ) {
			$pair              = sodium_crypto_sign_keypair();
			$this->private_key = sodium_crypto_sign_secretkey( $pair );
			$this->public_raw  = sodium_crypto_sign_publickey( $pair );
			return;
		}

		$config = 'ES256' === $this->alg
			? [
				'private_key_type' => OPENSSL_KEYTYPE_EC,
				'curve_name'       => 'prime256v1',
			]
			: [
				'private_key_type' => OPENSSL_KEYTYPE_RSA,
				'private_key_bits' => 2048,
			];
		$key = openssl_pkey_new( $config );
		if ( false === $key ) {
			throw new \RuntimeException( 'SoftAuthenticator: openssl_pkey_new failed: ' . (string) openssl_error_string() );
		}
		$this->private_key = $key;
		$details           = openssl_pkey_get_details( $key );
		if ( 'ES256' === $this->alg ) {
			$this->public_parts = [
				'x' => str_pad( (string) $details['ec']['x'], 32, "\0", STR_PAD_LEFT ),
				'y' => str_pad( (string) $details['ec']['y'], 32, "\0", STR_PAD_LEFT ),
			];
		} else {
			$this->public_parts = [
				'n' => ltrim( (string) $details['rsa']['n'], "\0" ),
				'e' => ltrim( (string) $details['rsa']['e'], "\0" ),
			];
		}
	}
}
