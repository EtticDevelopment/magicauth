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

	public function test_link_color_accepts_empty(): void {
		$out = $this->sanitize( [ 'link_color' => '' ] );
		$this->assertSame( '', $out['link_color'] );
		$this->assertEmpty( $this->settings_error_codes(), 'empty link_color should produce no notice' );
	}

	public function test_link_color_accepts_high_contrast_hex(): void {
		$out = $this->sanitize( [ 'link_color' => '#0044aa' ] );
		$this->assertSame( '#0044aa', $out['link_color'] );
		$this->assertEmpty( $this->settings_error_codes(), 'AA+ link_color should be silent' );
	}

	public function test_link_color_rejects_invalid_hex(): void {
		$out = $this->sanitize( [ 'link_color' => 'pirate' ] );
		// Default link_color is empty; invalid input restores previous value.
		$this->assertSame( '', $out['link_color'] );
		$this->assertContains( 'magicauth_link_color_invalid', $this->settings_error_codes() );
	}

	public function test_link_color_rejects_unreadable_below_floor(): void {
		// #bbbbbb on #ffffff ≈ 1.9:1 — well under the 2.5 hard floor.
		$out = $this->sanitize( [ 'link_color' => '#bbbbbb' ] );
		$this->assertSame( '', $out['link_color'], 'fail verdict must restore previous (empty default)' );
		$this->assertContains( 'magicauth_link_color_unreadable', $this->settings_error_codes() );
	}

	public function test_link_color_saves_with_warning_in_warn_band(): void {
		// #888888 on #ffffff ≈ 3.5:1 — between the 2.5 floor and AA 4.5.
		$out = $this->sanitize( [ 'link_color' => '#888888' ] );
		$this->assertSame( '#888888', $out['link_color'], 'warn verdict must still save' );
		$this->assertContains( 'magicauth_link_color_low_contrast', $this->settings_error_codes() );
	}

	public function test_link_color_array_input_is_ignored(): void {
		$out = $this->sanitize( [ 'link_color' => [ '#ff0000' ] ] );
		$this->assertSame( '', $out['link_color'] );
	}

	public function test_color_mode_round_trips_allowlist(): void {
		foreach ( [ 'light', 'dark', 'auto' ] as $mode ) {
			$out = $this->sanitize( [ 'color_mode' => $mode ] );
			$this->assertSame( $mode, $out['color_mode'], "mode '{$mode}' should round-trip" );
		}
	}

	public function test_color_mode_rejects_unknown(): void {
		$out = $this->sanitize( [ 'color_mode' => 'midnight' ] );
		$this->assertSame( 'light', $out['color_mode'] );
	}

	public function test_color_mode_rejects_array_input(): void {
		$out = $this->sanitize( [ 'color_mode' => [ 'dark' ] ] );
		// Default survives via is_scalar guard.
		$this->assertSame( 'light', $out['color_mode'] );
	}

	public function test_brand_dark_contrast_warning_fires_for_low_contrast(): void {
		$out = $this->sanitize( [
			'brand_color' => '#444444',
			'color_mode'  => 'dark',
		] );
		$this->assertSame( '#444444', $out['brand_color'] );
		$this->assertSame( 'dark', $out['color_mode'] );
		$this->assertContains( 'magicauth_brand_dark_contrast', $this->settings_error_codes() );
	}

	public function test_brand_dark_contrast_silent_in_light_mode(): void {
		// Same low-contrast brand, but light mode — no dark-surface check applies.
		$out = $this->sanitize( [
			'brand_color' => '#444444',
			'color_mode'  => 'light',
		] );
		$this->assertNotContains( 'magicauth_brand_dark_contrast', $this->settings_error_codes() );
	}

	public function test_background_id_zero_clears(): void {
		$out = $this->sanitize( [ 'background_attachment_id' => 0 ] );
		$this->assertSame( 0, $out['background_attachment_id'] );
		$this->assertEmpty( $this->settings_error_codes(), 'zero should be silent' );
	}

	public function test_background_id_rejects_non_image_attachment(): void {
		$path = $this->make_temp_file( '.png', $this->one_pixel_png_bytes() );
		try {
			magicauth_test_register_attachment_file( 42, $path, false /* is_image = false */ );
			$out = $this->sanitize( [ 'background_attachment_id' => 42 ] );
			$this->assertSame( 0, $out['background_attachment_id'] );
			$this->assertContains( 'magicauth_bg_not_image', $this->settings_error_codes() );
		} finally {
			@unlink( $path );
		}
	}

	public function test_background_id_accepts_valid_png(): void {
		$path = $this->make_temp_file( '.png', $this->one_pixel_png_bytes() );
		try {
			magicauth_test_register_attachment_file( 7, $path, true );
			$out = $this->sanitize( [ 'background_attachment_id' => 7 ] );
			$this->assertSame( 7, $out['background_attachment_id'] );
			$this->assertEmpty( $this->settings_error_codes(), 'valid PNG should be silent' );
		} finally {
			@unlink( $path );
		}
	}

	public function test_background_id_rejects_svg(): void {
		$path = $this->make_temp_file( '.svg', '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>' );
		try {
			magicauth_test_register_attachment_file( 11, $path, true );
			$out = $this->sanitize( [ 'background_attachment_id' => 11 ] );
			$this->assertSame( 0, $out['background_attachment_id'] );
			$this->assertContains( 'magicauth_bg_bad_ext', $this->settings_error_codes() );
		} finally {
			@unlink( $path );
		}
	}

	public function test_background_id_returns_zero_when_path_missing(): void {
		// Image flag set but no path registered → get_attached_file() returns false.
		global $magicauth_test_state;
		$magicauth_test_state['attachment_is_image'][ 99 ] = true;
		$out = $this->sanitize( [ 'background_attachment_id' => 99 ] );
		$this->assertSame( 0, $out['background_attachment_id'] );
	}

	private function make_temp_file( string $extension, string $bytes ): string {
		$path = sys_get_temp_dir() . '/magicauth-bg-test-' . uniqid( '', true ) . $extension;
		file_put_contents( $path, $bytes );
		return $path;
	}

	private function one_pixel_png_bytes(): string {
		// Minimal 1×1 transparent PNG — finfo identifies as image/png.
		return base64_decode(
			'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
			true
		) ?: '';
	}

	/** @return list<string> */
	private function settings_error_codes(): array {
		$errors = $GLOBALS['magicauth_test_state']['settings_errors'] ?? [];
		return array_map( static fn ( $e ) => (string) ( $e['code'] ?? '' ), $errors );
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
