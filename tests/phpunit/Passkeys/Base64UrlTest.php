<?php
/**
 * T-B64 (SPEC 8.2, 14.1): strict canonical base64url.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Passkeys\Base64Url;
use PHPUnit\Framework\TestCase;

final class Base64UrlTest extends TestCase {

	public function test_round_trip_for_every_length_0_to_199(): void {
		for ( $len = 0; $len < 200; $len++ ) {
			$raw = $len > 0 ? random_bytes( $len ) : '';
			$enc = Base64Url::encode( $raw );
			$this->assertMatchesRegularExpression( '/^[A-Za-z0-9_-]*$/', $enc, "length {$len}" );
			$this->assertSame( $raw, Base64Url::decode( $enc, 0, 199 ), "length {$len}" );
		}
	}

	public function test_known_values(): void {
		$this->assertSame( '', Base64Url::encode( '' ) );
		$this->assertSame( 'AA', Base64Url::encode( "\x00" ) );
		$this->assertSame( '-_8', Base64Url::encode( "\xfb\xff" ) );
		$this->assertSame( "\xfb\xff", Base64Url::decode( '-_8', 0, 10 ) );
		$this->assertSame( '', Base64Url::decode( '', 0, 10 ) );
	}

	/** @return array<string,array{0:string}> */
	public static function rejected(): array {
		return [
			'one char (length % 4 == 1)' => [ 'a' ],
			'five chars'                 => [ 'AAAAA' ],
			'padding'                    => [ 'ab=' ],
			'padding, full quantum'      => [ 'AA==' ],
			'plus'                       => [ 'a+b' ],
			'slash'                      => [ 'a/b' ],
			'stars'                      => [ '****' ],
			'non-zero trailing bits'     => [ 'AB' ],
			'trailing bits, 2 bytes'     => [ '-_9' ],
			'space'                      => [ 'AA AA' ],
			'newline'                    => [ "AAAA\n" ],
			'dot'                        => [ 'AA.A' ],
			'multibyte'                  => [ 'AAÄA' ],
			'null byte'                  => [ "AA\0A" ],
		];
	}

	/** @dataProvider rejected */
	public function test_rejects_non_canonical_or_foreign_input( string $input ): void {
		$this->assertNull( Base64Url::decode( $input, 0, 1000 ) );
	}

	public function test_aa_is_the_canonical_form_of_a_zero_byte(): void {
		$this->assertSame( "\x00", Base64Url::decode( 'AA', 1, 1 ) );
		$this->assertNull( Base64Url::decode( 'AB', 1, 1 ), 'same byte, non-zero trailing bits' );
	}

	public function test_length_limits_are_inclusive(): void {
		$enc32 = Base64Url::encode( str_repeat( "\x01", 32 ) );
		$this->assertNotNull( Base64Url::decode( $enc32, 32, 32 ) );
		$this->assertNull( Base64Url::decode( $enc32, 33, 64 ), 'below the minimum' );
		$this->assertNull( Base64Url::decode( $enc32, 0, 31 ), 'above the maximum' );

		$enc16 = Base64Url::encode( str_repeat( "\x02", 16 ) );
		$enc15 = Base64Url::encode( str_repeat( "\x02", 15 ) );
		$enc1024 = Base64Url::encode( str_repeat( "\x02", 1024 ) );
		$enc1023 = Base64Url::encode( str_repeat( "\x02", 1023 ) );
		$this->assertNotNull( Base64Url::decode( $enc16, 16, 1023 ) );
		$this->assertNotNull( Base64Url::decode( $enc1023, 16, 1023 ) );
		$this->assertNull( Base64Url::decode( $enc15, 16, 1023 ) );
		$this->assertNull( Base64Url::decode( $enc1024, 16, 1023 ) );
		$this->assertNull( Base64Url::decode( '', 1, 10 ), 'empty is 0 bytes' );
	}

	public function test_64_byte_handle_is_86_chars(): void {
		$this->assertSame( 86, strlen( Base64Url::encode( random_bytes( 64 ) ) ) );
		$this->assertSame( 43, strlen( Base64Url::encode( random_bytes( 32 ) ) ) );
	}
}
