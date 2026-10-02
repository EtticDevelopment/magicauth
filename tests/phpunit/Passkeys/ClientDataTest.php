<?php
/**
 * T-CD (SPEC 7.3 R-4, 7.4 A-2, W3): Verifier::client_data(), our own parse of
 * clientDataJSON before the library sees it.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Passkeys\Base64Url;
use MagicAuth\Passkeys\Verifier;
use PHPUnit\Framework\TestCase;

final class ClientDataTest extends TestCase {

	private const ORIGIN = 'https://academy.example.com';

	private static string $challenge = '';

	protected function setUp(): void {
		global $magicauth_test_state;
		magicauth_test_reset_state();
		$magicauth_test_state['home'] = self::ORIGIN;
		self::$challenge             = str_repeat( "\xab", 32 );
	}

	protected function tearDown(): void {
		magicauth_test_reset_state();
	}

	/** @param array<string,mixed> $changes */
	private static function json( array $changes = [], string $type = 'webauthn.create' ): string {
		$data = array_merge(
			[
				'type'        => $type,
				'challenge'   => Base64Url::encode( str_repeat( "\xab", 32 ) ),
				'origin'      => self::ORIGIN,
				'crossOrigin' => false,
			],
			$changes
		);
		foreach ( $data as $key => $value ) {
			if ( '__omit' === $value ) {
				unset( $data[ $key ] );
			}
		}
		return (string) json_encode( $data, JSON_UNESCAPED_SLASHES ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode
	}

	public function test_accepts_valid_client_data(): void {
		$this->assertSame(
			[
				'challenge' => self::$challenge,
				'origin'    => self::ORIGIN,
			],
			Verifier::client_data( self::json(), 'webauthn.create' )
		);
		$this->assertNotNull( Verifier::client_data( self::json( [], 'webauthn.get' ), 'webauthn.get' ) );
		$this->assertNotNull( Verifier::client_data( self::json( [ 'crossOrigin' => '__omit' ] ), 'webauthn.create' ), 'crossOrigin absent' );
	}

	public function test_accepts_chromes_extra_member(): void {
		$json = self::json( [ 'other_keys_can_be_added_here' => 'do not compare clientDataJSON against a template. See https://goo.gl/yabPex' ] );
		$this->assertNotNull( Verifier::client_data( $json, 'webauthn.create' ) );
		$this->assertNotNull( Verifier::client_data( self::json( [ 'tokenBinding' => [ 'status' => 'supported' ] ] ), 'webauthn.create' ), 'depth 3 is fine' );
	}

	/** @return array<string,array{string}> */
	public static function rejected(): array {
		$challenge = Base64Url::encode( str_repeat( "\xab", 32 ) );
		return [
			'empty'                         => [ '' ],
			'not JSON'                      => [ 'webauthn.create' ],
			'JSON array'                    => [ '["webauthn.create"]' ],
			'JSON string'                   => [ '"webauthn.create"' ],
			'BOM'                           => [ "\xEF\xBB\xBF" . self::json() ],
			'invalid UTF-8'                 => [ str_replace( '"crossOrigin"', "\"x\":\"\xc3\x28\",\"crossOrigin\"", self::json() ) ],
			'depth 5'                       => [ self::json( [ 'x' => [ [ [ [ 1 ] ] ] ] ] ) ],
			'type missing'                  => [ self::json( [ 'type' => '__omit' ] ) ],
			'type wrong'                    => [ self::json( [ 'type' => 'webauthn.get' ] ) ],
			'type not a string'             => [ self::json( [ 'type' => [ 'webauthn.create' ] ] ) ],
			'challenge missing'             => [ self::json( [ 'challenge' => '__omit' ] ) ],
			'challenge not a string'        => [ self::json( [ 'challenge' => 42 ] ) ],
			'challenge junk characters'     => [ self::json( [ 'challenge' => '!!' . $challenge . '**' ] ) ],
			'challenge standard base64'     => [ self::json( [ 'challenge' => base64_encode( str_repeat( "\xab", 32 ) ) ] ) ], // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
			'challenge 31 bytes'            => [ self::json( [ 'challenge' => Base64Url::encode( str_repeat( "\xab", 31 ) ) ] ) ],
			'challenge 33 bytes'            => [ self::json( [ 'challenge' => Base64Url::encode( str_repeat( "\xab", 33 ) ) ] ) ],
			'origin missing'                => [ self::json( [ 'origin' => '__omit' ] ) ],
			'origin array'                  => [ self::json( [ 'origin' => [ self::ORIGIN ] ] ) ],
			'origin not allowed'            => [ self::json( [ 'origin' => 'https://evil.example' ] ) ],
			'origin subdomain'              => [ self::json( [ 'origin' => 'https://www.academy.example.com' ] ) ],
			'origin with path'              => [ self::json( [ 'origin' => self::ORIGIN . '/' ] ) ],
			'origin default port spelt out' => [ self::json( [ 'origin' => self::ORIGIN . ':443' ] ) ],
			'origin http'                   => [ self::json( [ 'origin' => 'http://academy.example.com' ] ) ],
			'crossOrigin true'              => [ self::json( [ 'crossOrigin' => true ] ) ],
			'crossOrigin "true"'            => [ self::json( [ 'crossOrigin' => 'true' ] ) ],
			'crossOrigin 1'                 => [ self::json( [ 'crossOrigin' => 1 ] ) ],
			'crossOrigin 0'                 => [ self::json( [ 'crossOrigin' => 0 ] ) ],
			'crossOrigin null'              => [ self::json( [ 'crossOrigin' => null ] ) ],
			'topOrigin, crossOrigin false'  => [ self::json( [ 'topOrigin' => self::ORIGIN ] ) ],
			'topOrigin null'                => [ self::json( [ 'topOrigin' => null ] ) ],
			'over 4096 bytes'               => [ self::json( [ 'pad' => str_repeat( 'p', 4096 ) ] ) ],
		];
	}

	/** @dataProvider rejected */
	public function test_rejects( string $json ): void {
		$this->assertNull( Verifier::client_data( $json, 'webauthn.create' ) );
	}

	public function test_an_unconfigured_site_allows_no_origin(): void {
		global $magicauth_test_state;
		$magicauth_test_state['home'] = 'not a url';
		$this->assertNull( Verifier::client_data( self::json( [ 'origin' => '' ] ), 'webauthn.create' ) );
	}
}
