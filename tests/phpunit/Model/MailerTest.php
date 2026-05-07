<?php
/**
 * Mailer template + multipart behaviour: T18, T19, T22, T23.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Model;

use MagicAuth\Email\Mailer;
use PHPUnit\Framework\TestCase;

final class MailerTest extends TestCase {

	private const USER_ID = 7;
	private const EMAIL   = 'recipient@example.test';

	protected function setUp(): void {
		magicauth_test_reset_state();
		magicauth_test_register_user( self::USER_ID, self::EMAIL );
	}

	public function test_T18_alt_body_handler_registered_and_removed_after_send(): void {
		global $magicauth_test_state;
		$result = Mailer::send_magic_link( self::USER_ID, 'https://example.test/verify', 'ABCDEF', '2026-05-02 12:00:00' );
		$this->assertTrue( $result );

		// Handler must have been deregistered after send.
		$this->assertEmpty(
			$magicauth_test_state['actions']['phpmailer_init'] ?? [],
			'phpmailer_init handler is removed after wp_mail completes'
		);
	}

	public function test_T19_plaintext_renders_from_template_not_strip_tags(): void {
		// Render the templates directly with controlled args.
		$args = [
			'user'           => magicauth_test_register_user( self::USER_ID, self::EMAIL ),
			'link'           => 'https://example.test/verify?s=aaa&v=bbb',
			'code'           => 'ABCDEF',
			'code_display'   => 'ABC-DEF',
			'expires_at'     => '2026-05-02 12:00:00',
			'expiry_minutes' => 10,
			'brand_color'    => '#2271b1',
			'brand_text'     => '#ffffff',
			'company_name'   => 'Test Site',
			'site_name'      => 'Test Site',
			'is_test'        => false,
		];

		$html  = Mailer::render( 'email-magic-link.php', $args );
		$plain = Mailer::render( 'email-magic-link-plain.php', $args );

		$this->assertNotSame( '', $plain );
		$this->assertNotSame( strip_tags( $html ), $plain, 'Plaintext is its own template, not strip_tags(HTML)' );

		// The plaintext template explicitly mentions both the code and link.
		$this->assertStringContainsString( 'ABC-DEF', $plain );
		$this->assertStringContainsString( 'https://example.test/verify', $plain );

		// And it does NOT contain HTML artefacts that strip_tags would leak.
		$this->assertStringNotContainsString( 'doctype', strtolower( $plain ) );
		$this->assertStringNotContainsString( '<table', strtolower( $plain ) );
	}

	public function test_T22_html_weight_under_gmail_clip_threshold(): void {
		$args = [
			'user'           => magicauth_test_register_user( self::USER_ID, self::EMAIL ),
			'link'           => 'https://example.test/verify?s=' . str_repeat( 'a', 16 ) . '&v=' . str_repeat( 'b', 64 ),
			'code'           => 'ABCDEF',
			'code_display'   => 'ABC-DEF',
			'expires_at'     => '2026-05-02 12:00:00',
			'expiry_minutes' => 10,
			'brand_color'    => '#2271b1',
			'brand_text'     => '#ffffff',
			'company_name'   => 'Test Site With A Long Name For Stress Test',
			'site_name'      => 'Test Site With A Long Name For Stress Test',
			'is_test'        => false,
		];

		$html = Mailer::render( 'email-magic-link.php', $args );
		$this->assertLessThan( 102 * 1024, strlen( $html ), 'HTML body fits inside Gmail 102KB clip' );
	}

	public function test_T23_wp_mail_failure_returns_false_but_does_not_throw(): void {
		global $magicauth_test_state;
		$magicauth_test_state['wp_mail_return'] = false;

		$result = Mailer::send_magic_link( self::USER_ID, 'https://example.test/verify', 'ABCDEF', '2026-05-02 12:00:00' );
		$this->assertFalse( $result );

		// Mailer surfaces the failure to its caller; the *caller* (Controller)
		// is responsible for keeping the user-facing flow opaque.
	}

	public function test_template_resolver_finds_plugin_default(): void {
		$path = Mailer::locate_template( 'email-magic-link.php' );
		$this->assertNotSame( '', $path );
		$this->assertStringEndsWith( '/templates/email-magic-link.php', $path );
	}

	public function test_template_args_filter_can_override_brand_color(): void {
		add_filter(
			'magicauth_email_template_args',
			static function ( $args ) {
				$args['brand_color'] = '#ff00ff';
				return $args;
			}
		);

		Mailer::send_magic_link( self::USER_ID, 'https://example.test/v', 'ABCDEF', '2026-05-02 12:00:00' );

		global $magicauth_test_state;
		$this->assertNotEmpty( $magicauth_test_state['mail'] );
		$this->assertStringContainsString( '#ff00ff', $magicauth_test_state['mail'][0]['message'] );
	}

	public function test_email_subject_filter_overrides(): void {
		add_filter(
			'magicauth_email_subject',
			static function ( $subject ) {
				return 'Custom: ' . $subject;
			}
		);

		Mailer::send_magic_link( self::USER_ID, 'https://example.test/v', 'ABCDEF', '2026-05-02 12:00:00' );

		global $magicauth_test_state;
		$this->assertStringStartsWith( 'Custom:', (string) $magicauth_test_state['mail'][0]['subject'] );
	}

	public function test_email_send_filter_short_circuits_wp_mail(): void {
		add_filter(
			'magicauth_email_send',
			static function ( $value ) {
				unset( $value );
				return true;
			}
		);

		$result = Mailer::send_magic_link( self::USER_ID, 'https://example.test/v', 'ABCDEF', '2026-05-02 12:00:00' );
		$this->assertTrue( $result );

		global $magicauth_test_state;
		$this->assertEmpty( $magicauth_test_state['mail'] ?? [], 'wp_mail not called when filter short-circuits' );
	}
}
