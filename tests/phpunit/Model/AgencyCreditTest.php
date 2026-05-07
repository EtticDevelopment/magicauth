<?php
/**
 * Agency-credit feature: helper resolver + template render.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Model;

use PHPUnit\Framework\TestCase;

final class AgencyCreditTest extends TestCase {

	private const ICON_ID  = 991;
	private const ICON_URL = 'https://cdn.example.test/agency-icon.png';

	protected function setUp(): void {
		magicauth_test_reset_state();
		magicauth_test_register_attachment( self::ICON_ID, self::ICON_URL );
	}

	public function test_returns_null_when_name_blank(): void {
		update_option(
			'magicauth_settings',
			[
				'agency_credit_name'    => '',
				'agency_credit_url'     => 'https://acme.example',
				'agency_credit_icon_id' => self::ICON_ID,
			]
		);
		$this->assertNull( magicauth_get_agency_credit() );
	}

	public function test_returns_null_when_url_blank(): void {
		update_option(
			'magicauth_settings',
			[
				'agency_credit_name'    => 'Acme Studio',
				'agency_credit_url'     => '',
				'agency_credit_icon_id' => self::ICON_ID,
			]
		);
		$this->assertNull( magicauth_get_agency_credit() );
	}

	public function test_returns_null_when_icon_missing(): void {
		update_option(
			'magicauth_settings',
			[
				'agency_credit_name'    => 'Acme Studio',
				'agency_credit_url'     => 'https://acme.example',
				'agency_credit_icon_id' => 0,
			]
		);
		$this->assertNull( magicauth_get_agency_credit() );
	}

	public function test_returns_null_when_attachment_id_does_not_resolve(): void {
		update_option(
			'magicauth_settings',
			[
				'agency_credit_name'    => 'Acme Studio',
				'agency_credit_url'     => 'https://acme.example',
				'agency_credit_icon_id' => 9999,
			]
		);
		$this->assertNull( magicauth_get_agency_credit() );
	}

	public function test_returns_array_when_all_fields_present(): void {
		update_option(
			'magicauth_settings',
			[
				'agency_credit_name'    => 'Acme Studio',
				'agency_credit_url'     => 'https://acme.example',
				'agency_credit_icon_id' => self::ICON_ID,
			]
		);

		$credit = magicauth_get_agency_credit();
		$this->assertIsArray( $credit );
		$this->assertSame( 'Acme Studio', $credit['name'] );
		$this->assertSame( 'https://acme.example', $credit['url'] );
		$this->assertSame( self::ICON_URL, $credit['icon_url'] );
		$this->assertSame( 'Acme Studio', $credit['icon_alt'] );
	}

	public function test_template_renders_with_required_attributes(): void {
		$credit = [
			'name'     => 'Acme Studio',
			'url'      => 'https://acme.example',
			'icon_url' => self::ICON_URL,
			'icon_alt' => 'Acme Studio',
		];

		ob_start();
		include MAGICAUTH_DIR . 'templates/agency-credit.php';
		$html = (string) ob_get_clean();

		$this->assertStringContainsString( 'magicauth-credit', $html );
		$this->assertStringContainsString( 'href="https://acme.example"', $html );
		$this->assertStringContainsString( 'target="_blank"', $html );
		$this->assertStringContainsString( 'rel="noopener noreferrer"', $html );
		$this->assertStringContainsString( 'Built by', $html );
		$this->assertStringContainsString( '<span class="magicauth-credit__brand">Acme Studio</span>', $html );
		$this->assertStringContainsString( self::ICON_URL, $html );
	}

	public function test_template_emits_nothing_when_credit_incomplete(): void {
		$credit = [
			'name'     => 'Acme Studio',
			'url'      => '',
			'icon_url' => self::ICON_URL,
			'icon_alt' => 'Acme Studio',
		];

		ob_start();
		include MAGICAUTH_DIR . 'templates/agency-credit.php';
		$html = (string) ob_get_clean();

		$this->assertSame( '', trim( $html ) );
	}
}
