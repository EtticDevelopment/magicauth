<?php
/**
 * hide_language_switcher: default plumbing, two-array sync, and merge for
 * existing installs that predate the key.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Model;

use MagicAuth\Installer;
use PHPUnit\Framework\TestCase;

final class LanguageSwitcherSettingTest extends TestCase {

	protected function setUp(): void {
		magicauth_test_reset_state();
	}

	public function test_defaults_to_false(): void {
		$this->assertFalse( magicauth_get_setting( 'hide_language_switcher', null ) );
	}

	public function test_installer_default_includes_key(): void {
		$defaults = Installer::default_settings();
		$this->assertArrayHasKey( 'hide_language_switcher', $defaults );
		$this->assertFalse( $defaults['hide_language_switcher'] );
	}

	/** Installer + helpers defaults must agree, or upgrades and seeds diverge. */
	public function test_installer_and_runtime_defaults_agree(): void {
		$installer = Installer::default_settings();
		$runtime   = magicauth_get_settings();
		$this->assertSame(
			$installer['hide_language_switcher'],
			$runtime['hide_language_switcher']
		);
	}

	public function test_saved_true_is_returned(): void {
		update_option( 'magicauth_settings', [ 'hide_language_switcher' => true ] );
		$this->assertTrue( magicauth_get_setting( 'hide_language_switcher', false ) );
	}

	/** Existing installs whose saved option predates the key still resolve to the default. */
	public function test_existing_install_without_key_gets_default(): void {
		update_option( 'magicauth_settings', [ 'company_name' => 'Acme Co' ] );
		$this->assertFalse( magicauth_get_setting( 'hide_language_switcher', null ) );
	}
}
