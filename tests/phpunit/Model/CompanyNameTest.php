<?php
/**
 * magicauth_get_company_name(): admin override + bloginfo fallback.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Model;

use MagicAuth\Email\Mailer;
use PHPUnit\Framework\TestCase;

final class CompanyNameTest extends TestCase {

	private const USER_ID = 31;
	private const EMAIL   = 'cn@example.test';

	protected function setUp(): void {
		magicauth_test_reset_state();
		magicauth_test_register_user( self::USER_ID, self::EMAIL );
	}

	public function test_falls_back_to_bloginfo_when_setting_blank(): void {
		update_option( 'magicauth_settings', [ 'company_name' => '' ] );
		$this->assertSame( 'Test Site', magicauth_get_company_name() );
	}

	public function test_treats_whitespace_only_as_blank(): void {
		update_option( 'magicauth_settings', [ 'company_name' => '   ' ] );
		$this->assertSame( 'Test Site', magicauth_get_company_name() );
	}

	public function test_returns_admin_setting_when_present(): void {
		update_option( 'magicauth_settings', [ 'company_name' => 'Acme Co' ] );
		$this->assertSame( 'Acme Co', magicauth_get_company_name() );
	}

	public function test_subject_line_uses_company_name(): void {
		update_option( 'magicauth_settings', [ 'company_name' => 'Acme Co' ] );

		Mailer::send_magic_link( self::USER_ID, 'https://example.test/v', 'ABCDEF', '2026-05-04 12:00:00' );

		global $magicauth_test_state;
		$this->assertNotEmpty( $magicauth_test_state['mail'] );
		$this->assertSame( 'ABC-DEF is your Acme Co-code', $magicauth_test_state['mail'][0]['subject'] );
	}

	public function test_subject_line_falls_back_to_site_name(): void {
		update_option( 'magicauth_settings', [ 'company_name' => '' ] );

		Mailer::send_magic_link( self::USER_ID, 'https://example.test/v', 'ABCDEF', '2026-05-04 12:00:00' );

		global $magicauth_test_state;
		$this->assertSame( 'ABC-DEF is your Test Site-code', $magicauth_test_state['mail'][0]['subject'] );
	}
}
