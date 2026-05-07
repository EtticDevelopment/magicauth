<?php
/**
 * Toast dispatcher behaviour. Validates the magicauth_blocked branch added in
 * v1.3.6 and confirms the link-invalid > blocked > error > sent priority order
 * holds.
 *
 * Renders are captured via output buffering — the dispatcher echoes markup,
 * doesn't return it. We assert against the rendered HTML.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Model;

use MagicAuth\Frontend\Toast;
use PHPUnit\Framework\TestCase;

final class ToastTest extends TestCase {

	protected function setUp(): void {
		magicauth_test_reset_state();
		$_GET = [];
	}

	protected function tearDown(): void {
		$_GET = [];
	}

	private function render( string $state ): string {
		ob_start();
		Toast::maybe_render( $state );
		return (string) ob_get_clean();
	}

	public function test_renders_blocked_email_cooldown_with_seconds(): void {
		$_GET['magicauth_blocked']    = 'email_cooldown';
		$_GET['magicauth_block_secs'] = '47';

		$out = $this->render( 'a' );

		$this->assertStringContainsString( 'magicauth-toast--warning', $out );
		$this->assertStringContainsString( 'Please wait 47 seconds', $out );
	}

	public function test_renders_blocked_email_cooldown_without_seconds_falls_back(): void {
		$_GET['magicauth_blocked'] = 'email_cooldown';

		$out = $this->render( 'a' );

		$this->assertStringContainsString( 'magicauth-toast--warning', $out );
		$this->assertStringContainsString( 'Please wait a moment', $out );
	}

	public function test_renders_blocked_ip_link(): void {
		$_GET['magicauth_blocked'] = 'ip_link';

		$out = $this->render( 'a' );

		$this->assertStringContainsString( 'magicauth-toast--warning', $out );
		$this->assertStringContainsString( 'Too many sign-in requests from your network', $out );
	}

	public function test_renders_blocked_ip_code(): void {
		$_GET['magicauth_blocked'] = 'ip_code';

		$out = $this->render( 'b' );

		$this->assertStringContainsString( 'magicauth-toast--warning', $out );
		$this->assertStringContainsString( 'Too many code attempts', $out );
	}

	public function test_renders_blocked_ip_password(): void {
		$_GET['magicauth_blocked'] = 'ip_password';

		$out = $this->render( 'c' );

		$this->assertStringContainsString( 'magicauth-toast--warning', $out );
		$this->assertStringContainsString( 'Too many sign-in attempts', $out );
	}

	public function test_renders_blocked_ip_password_reset(): void {
		$_GET['magicauth_blocked'] = 'ip_password_reset';

		$out = $this->render( 'd' );

		$this->assertStringContainsString( 'magicauth-toast--warning', $out );
		$this->assertStringContainsString( 'Too many password-reset requests', $out );
	}

	public function test_unknown_blocked_reason_renders_nothing(): void {
		$_GET['magicauth_blocked'] = 'made-up-reason';

		$out = $this->render( 'a' );

		$this->assertSame( '', trim( $out ) );
	}

	public function test_priority_link_invalid_beats_blocked(): void {
		// link_invalid is the most actionable signal — must always win.
		$_GET['magicauth_link_invalid'] = '1';
		$_GET['magicauth_blocked']      = 'email_cooldown';

		$out = $this->render( 'a' );

		$this->assertStringContainsString( 'sign-in link has expired', $out );
		$this->assertStringNotContainsString( 'Please wait', $out );
		$this->assertStringContainsString( 'magicauth-toast--error', $out );
		$this->assertStringNotContainsString( 'magicauth-toast--warning', $out );
	}

	public function test_priority_blocked_beats_error(): void {
		// blocked carries a more specific message than the generic error envelope.
		$_GET['magicauth_blocked'] = 'ip_code';
		$_GET['magicauth_error']   = '1';

		$out = $this->render( 'b' );

		$this->assertStringContainsString( 'Too many code attempts', $out );
		$this->assertStringContainsString( 'magicauth-toast--warning', $out );
		$this->assertStringNotContainsString( 'magicauth-toast--error', $out );
	}

	public function test_priority_blocked_beats_sent(): void {
		$_GET['magicauth_blocked'] = 'email_cooldown';
		$_GET['magicauth_sent']    = '1';

		$out = $this->render( 'b' );

		$this->assertStringContainsString( 'Please wait a moment', $out );
		$this->assertStringContainsString( 'magicauth-toast--warning', $out );
		$this->assertStringNotContainsString( 'Email sent', $out );
	}

	public function test_warning_uses_assertive_aria_live(): void {
		$_GET['magicauth_blocked'] = 'email_cooldown';

		$out = $this->render( 'a' );

		$this->assertStringContainsString( 'role="alert"', $out );
		$this->assertStringContainsString( 'aria-live="assertive"', $out );
	}
}
