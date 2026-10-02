<?php
/**
 * K5: the harness esc_url() stub keeps javascript: URLs (core drops any
 * scheme outside wp_allowed_protocols() and returns ''). The helper's
 * redirect_to (Assets::signin_markup) therefore cannot be tested for a
 * script URL. Fails until the stub filters protocols like core.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Review;

use MagicAuth\Passkeys\Assets;
use PHPUnit\Framework\TestCase;

final class K5Test extends TestCase {

	protected function setUp(): void {
		magicauth_test_reset_state();
	}

	protected function tearDown(): void {
		magicauth_test_reset_state();
	}

	public function test_stub_esc_url_drops_disallowed_protocols_like_core(): void {
		$this->assertSame( '', esc_url( 'javascript:alert(1)' ), 'core esc_url() returns empty for javascript:' );
		$this->assertSame( '', esc_url( 'data:text/html,<script>alert(1)</script>' ), 'core esc_url() returns empty for data:' );
	}

	public function test_signin_markup_omits_script_redirect_to(): void {
		$html = Assets::signin_markup( [ 'redirect_to' => 'javascript:alert(document.cookie)' ] );

		$this->assertStringNotContainsString( 'data-magicauth-redirect-to', $html, 'a script URL must not reach the root attribute' );
		$this->assertStringNotContainsString( 'javascript:', $html );
	}

	public function test_signin_markup_keeps_a_safe_redirect_to(): void {
		$dest = home_url( '/courses/intro/' );
		$html = Assets::signin_markup( [ 'redirect_to' => $dest ] );

		$this->assertStringContainsString( 'data-magicauth-redirect-to="' . esc_attr( esc_url( $dest ) ) . '"', $html );
	}
}
