<?php
/**
 * Admin\Settings::sanitize() — bounds and allowlist for v1.1 branding tokens.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Model;

use MagicAuth\Admin\Settings;
use MagicAuth\Installer;
use PHPUnit\Framework\TestCase;

final class SettingsSanitizeTest extends TestCase {

	protected function setUp(): void {
		magicauth_test_reset_state();
		update_option( 'magicauth_settings', Installer::default_settings() );
	}

	private function sanitize( array $input ): array {
		return Settings::sanitize( $input );
	}

	public function test_page_color_accepts_valid_hex(): void {
		$out = $this->sanitize( [ 'page_color' => '#abcdef' ] );
		$this->assertSame( '#abcdef', $out['page_color'] );
	}

	public function test_page_color_falls_back_on_garbage(): void {
		$out = $this->sanitize( [ 'page_color' => 'not a color' ] );
		$this->assertSame( '#eeeeee', $out['page_color'] );
	}

	public function test_page_color_array_input_is_ignored(): void {
		$out = $this->sanitize( [ 'page_color' => [ '#ff0000' ] ] );
		// is_scalar guard short-circuits; current default survives.
		$this->assertSame( '#eeeeee', $out['page_color'] );
	}

	public function test_card_radius_clamps_above_max(): void {
		$out = $this->sanitize( [ 'card_radius' => 9999 ] );
		$this->assertSame( 32, $out['card_radius'] );
	}

	public function test_card_radius_accepts_bounds(): void {
		$lo = $this->sanitize( [ 'card_radius' => 0 ] );
		$hi = $this->sanitize( [ 'card_radius' => 32 ] );
		$this->assertSame( 0, $lo['card_radius'] );
		$this->assertSame( 32, $hi['card_radius'] );
	}

	public function test_card_radius_garbage_yields_zero(): void {
		$out = $this->sanitize( [ 'card_radius' => 'foo' ] );
		$this->assertSame( 0, $out['card_radius'] );
	}

	public function test_card_width_clamps_below_min(): void {
		$out = $this->sanitize( [ 'card_width' => 100 ] );
		$this->assertSame( 360, $out['card_width'] );
	}

	public function test_card_width_clamps_above_max(): void {
		$out = $this->sanitize( [ 'card_width' => 9999 ] );
		$this->assertSame( 640, $out['card_width'] );
	}

	public function test_card_width_accepts_bounds(): void {
		$lo = $this->sanitize( [ 'card_width' => 360 ] );
		$hi = $this->sanitize( [ 'card_width' => 640 ] );
		$this->assertSame( 360, $lo['card_width'] );
		$this->assertSame( 640, $hi['card_width'] );
	}

	public function test_font_stack_round_trips_allowlist(): void {
		foreach ( [ 'system', 'sans-modern', 'serif', 'mono', 'rounded' ] as $key ) {
			$out = $this->sanitize( [ 'font_stack' => $key ] );
			$this->assertSame( $key, $out['font_stack'], "key '{$key}' should round-trip" );
		}
	}

	public function test_font_stack_rejects_unknown_key(): void {
		$out = $this->sanitize( [ 'font_stack' => 'pirate' ] );
		$this->assertSame( 'system', $out['font_stack'] );
	}

	public function test_font_stack_rejects_array_input(): void {
		// is_scalar guard rejects array entirely; default survives.
		$out = $this->sanitize( [ 'font_stack' => [ 'rounded' ] ] );
		$this->assertSame( 'system', $out['font_stack'] );
	}

	public function test_defaults_returned_for_missing_keys(): void {
		// Simulates v1.0 -> v1.1 upgrade: stored option has no new keys.
		update_option( 'magicauth_settings', [ 'ttl_minutes' => 10 ] );
		$settings = magicauth_get_settings();
		$this->assertSame( '#eeeeee', $settings['page_color'] );
		$this->assertSame( 6, $settings['card_radius'] );
		$this->assertSame( 480, $settings['card_width'] );
		$this->assertSame( 'system', $settings['font_stack'] );
	}

	public function test_font_stacks_in_shell_template_contain_no_html_meta_chars(): void {
		// HTML parsers treat '</style>' as a block-terminator regardless of CSS
		// quoting. Pin a static assertion so a future maintainer adding e.g.
		// 'fancy' => 'Helvetica<Neue>' cannot silently break the <style> emit.
		$shell = file_get_contents( MAGICAUTH_DIR . 'templates/login-shell.php' );
		$this->assertNotFalse( $shell, 'login-shell.php should be readable' );

		// Extract the $shell_font_stacks array literal.
		$ok = preg_match( '/\$shell_font_stacks\s*=\s*\[(.*?)\];/s', $shell, $m );
		$this->assertSame( 1, $ok, '$shell_font_stacks map should be defined in login-shell.php' );

		// Each quoted CSS value (the right-hand side of `=>`) must be free of `<` and `>`.
		$matched = preg_match_all( "/=>\s*'([^']+)'/", $m[1], $values );
		$this->assertGreaterThan( 0, $matched, 'expected at least one font-stack value' );
		foreach ( $values[1] as $value ) {
			$this->assertStringNotContainsString( '<', $value, "font stack value '{$value}' must not contain '<'" );
			$this->assertStringNotContainsString( '>', $value, "font stack value '{$value}' must not contain '>'" );
		}
	}
}
