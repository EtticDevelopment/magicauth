<?php
/**
 * magicauth_locale_short_code(): uppercase language-subtag badge.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Model;

use PHPUnit\Framework\TestCase;

final class LocaleShortCodeTest extends TestCase {

	public function test_extracts_uppercase_language_subtag(): void {
		$this->assertSame( 'NL', magicauth_locale_short_code( 'nl_NL' ) );
		$this->assertSame( 'EN', magicauth_locale_short_code( 'en_US' ) );
		$this->assertSame( 'PT', magicauth_locale_short_code( 'pt_BR' ) );
		$this->assertSame( 'DE', magicauth_locale_short_code( 'de' ) );
	}

	public function test_handles_hyphen_separator(): void {
		$this->assertSame( 'FR', magicauth_locale_short_code( 'fr-FR' ) );
	}

	public function test_blank_returns_empty(): void {
		$this->assertSame( '', magicauth_locale_short_code( '' ) );
		$this->assertSame( '', magicauth_locale_short_code( '   ' ) );
	}
}
