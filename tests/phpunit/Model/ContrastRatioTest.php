<?php
/**
 * magicauth_contrast_ratio() / magicauth_contrast_evaluate() — WCAG 2.1 math.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Model;

use PHPUnit\Framework\TestCase;

final class ContrastRatioTest extends TestCase {

	public function test_black_on_white_is_21(): void {
		$this->assertEqualsWithDelta( 21.0, magicauth_contrast_ratio( '#000', '#ffffff' ), 0.01 );
	}

	public function test_identical_colors_yield_1(): void {
		$this->assertEqualsWithDelta( 1.0, magicauth_contrast_ratio( '#abcdef', '#abcdef' ), 0.001 );
	}

	public function test_wp_blue_on_white_is_aa_normal(): void {
		$r = magicauth_contrast_ratio( '#2271b1', '#ffffff' );
		$this->assertGreaterThanOrEqual( 4.5, $r );
		$this->assertLessThan( 7.0, $r );
	}

	public function test_three_digit_hex_normalizes_like_six(): void {
		$this->assertEqualsWithDelta(
			magicauth_contrast_ratio( '#abc', '#ffffff' ),
			magicauth_contrast_ratio( '#aabbcc', '#ffffff' ),
			0.01
		);
	}

	public function test_symmetric(): void {
		$a = magicauth_contrast_ratio( '#123456', '#abcdef' );
		$b = magicauth_contrast_ratio( '#abcdef', '#123456' );
		$this->assertEqualsWithDelta( $a, $b, 0.001 );
	}

	public function test_garbage_input_returns_1(): void {
		$this->assertSame( 1.0, magicauth_contrast_ratio( 'pirate', '#ffffff' ) );
	}

	public function test_alpha_hex_rejected(): void {
		// 8-char form is not a valid 3/6-digit hex → 1.0 sentinel.
		$this->assertSame( 1.0, magicauth_contrast_ratio( '#ff000080', '#ffffff' ) );
	}

	public function test_evaluate_thresholds(): void {
		$this->assertSame( 'fail', magicauth_contrast_evaluate( 2.0, 'normal' ) );
		$this->assertSame( 'warn', magicauth_contrast_evaluate( 4.0, 'normal' ) );
		$this->assertSame( 'pass', magicauth_contrast_evaluate( 5.0, 'normal' ) );
		$this->assertSame( 'pass', magicauth_contrast_evaluate( 3.5, 'ui' ) );
		$this->assertSame( 'pass', magicauth_contrast_evaluate( 3.5, 'large' ) );
	}
}
