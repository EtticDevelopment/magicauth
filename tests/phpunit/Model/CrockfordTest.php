<?php
/**
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Model;

use MagicAuth\Auth\Crockford;
use PHPUnit\Framework\TestCase;

final class CrockfordTest extends TestCase {

	public function test_encode_returns_canonical_alphabet_chars_only(): void {
		for ( $i = 0; $i < 200; $i++ ) {
			$code = Crockford::encode_bytes( random_bytes( 5 ), 6 );
			$this->assertSame( 6, strlen( $code ), 'Code length always 6' );
			$this->assertMatchesRegularExpression( '/^[0-9A-HJKMNPQRSTVWXYZ]{6}$/', $code );
		}
	}

	public function test_encode_zero_bytes_yields_zero_string(): void {
		$this->assertSame( '000000', Crockford::encode_bytes( str_repeat( "\x00", 5 ), 6 ) );
	}

	public function test_encode_all_ones_yields_z_string(): void {
		$this->assertSame( 'ZZZZZZ', Crockford::encode_bytes( str_repeat( "\xff", 5 ), 6 ) );
	}

	public function test_normalize_folds_lookalikes(): void {
		$this->assertSame( '0011', Crockford::normalize( 'OoIl' ) );
		$this->assertSame( 'V', Crockford::normalize( 'u' ) );
	}

	public function test_normalize_strips_dashes_and_spaces_and_uppercases(): void {
		$this->assertSame( 'ABCDEF', Crockford::normalize( ' ab-cd ef ' ) );
		$this->assertSame( 'ABCDEF', Crockford::normalize( 'ABC-DEF' ) );
	}

	public function test_normalize_drops_unknown_chars(): void {
		$this->assertSame( 'ABC', Crockford::normalize( 'A!B@C#' ) );
	}

	public function test_looks_valid_requires_six_normalized_chars(): void {
		$this->assertTrue( Crockford::looks_valid( 'ABC-DEF' ) );
		$this->assertTrue( Crockford::looks_valid( 'abcdef' ) );
		$this->assertFalse( Crockford::looks_valid( '' ) );
		$this->assertFalse( Crockford::looks_valid( 'ABCDE' ) );
		$this->assertFalse( Crockford::looks_valid( 'ABCDEFG' ) );
	}

	public function test_format_for_display_inserts_hyphen_at_three(): void {
		$this->assertSame( 'ABC-DEF', Crockford::format_for_display( 'ABCDEF' ) );
	}
}
