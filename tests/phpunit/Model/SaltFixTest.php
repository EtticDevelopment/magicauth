<?php
/**
 * Salt-fix wizard: pure salt generation, detection, and config rewriting.
 *
 * Covers the file-I/O-free core of the "Fix WordPress salts" feature. The
 * WP_Filesystem write path is exercised manually, not unit-tested here.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Model;

use MagicAuth\Installer;
use PHPUnit\Framework\TestCase;

final class SaltFixTest extends TestCase {

	private const CONSTANTS = [
		'AUTH_KEY',
		'SECURE_AUTH_KEY',
		'LOGGED_IN_KEY',
		'NONCE_KEY',
		'AUTH_SALT',
		'SECURE_AUTH_SALT',
		'LOGGED_IN_SALT',
		'NONCE_SALT',
	];

	/** A full set of strong salt values keyed by constant name (no network). */
	private function strong_values(): array {
		$values = [];
		foreach ( self::CONSTANTS as $name ) {
			$values[ $name ] = Installer::generate_salt_value();
		}
		return $values;
	}

	/** A wp-config slice carrying all eight placeholder defines plus unrelated lines. */
	private function placeholder_config(): string {
		$lines = [ '<?php', "define( 'DB_NAME', 'wordpress' );" ];
		foreach ( self::CONSTANTS as $name ) {
			$lines[] = "define( '" . $name . "', 'put your unique phrase here' );";
		}
		$lines[] = "\$table_prefix = 'wp_';";
		$lines[] = "/* That's all, stop editing! */";
		return implode( "\n", $lines );
	}

	public function test_generated_value_is_strong_and_quote_safe(): void {
		$value = Installer::generate_salt_value();
		// base64 of 48 bytes is 64 characters.
		$this->assertSame( 64, strlen( $value ) );
		// Must be embeddable inside a single-quoted PHP literal.
		$this->assertStringNotContainsString( "'", $value );
		$this->assertStringNotContainsString( '\\', $value );
		$this->assertNotSame( $value, Installer::generate_salt_value(), 'Values must be random per call.' );
	}

	public function test_salt_block_defines_all_eight_constants(): void {
		$block = Installer::generate_salt_block();
		foreach ( self::CONSTANTS as $name ) {
			$this->assertStringContainsString( "define( '" . $name . "',", $block );
		}
		$this->assertSame( 8, substr_count( $block, 'define(' ) );
		$this->assertFalse( Installer::config_has_weak_salts( $block ), 'A freshly generated block is not weak.' );
	}

	public function test_placeholder_config_reads_as_weak(): void {
		$this->assertTrue( Installer::config_has_weak_salts( $this->placeholder_config() ) );
	}

	public function test_empty_value_reads_as_weak(): void {
		$config = "<?php\ndefine( 'AUTH_KEY', '' );";
		$this->assertTrue( Installer::config_has_weak_salts( $config ) );
	}

	public function test_missing_define_reads_as_weak(): void {
		// AUTH_KEY present and strong, the other seven absent.
		$config = "<?php\ndefine( 'AUTH_KEY', '" . Installer::generate_salt_value() . "' );";
		$this->assertTrue( Installer::config_has_weak_salts( $config ) );
	}

	public function test_rewrite_replaces_placeholders_with_strong_salts(): void {
		$original = $this->placeholder_config();
		$updated  = Installer::rewrite_salt_defines( $original, $this->strong_values() );

		$this->assertIsString( $updated );
		$this->assertFalse( Installer::config_has_weak_salts( $updated ) );
		$this->assertStringNotContainsString( 'put your unique phrase here', $updated );
		// Unrelated lines survive untouched.
		$this->assertStringContainsString( "define( 'DB_NAME', 'wordpress' );", $updated );
		$this->assertStringContainsString( "\$table_prefix = 'wp_';", $updated );
		// Still eight defines for the salt constants.
		foreach ( self::CONSTANTS as $name ) {
			$this->assertStringContainsString( "define( '" . $name . "',", $updated );
		}
	}

	public function test_rewrite_returns_null_when_a_define_is_missing(): void {
		$config = "<?php\ndefine( 'AUTH_KEY', 'put your unique phrase here' );";
		$this->assertNull( Installer::rewrite_salt_defines( $config, $this->strong_values() ) );
	}

	public function test_rewrite_and_detection_ignore_commented_define_lines(): void {
		// A commented example sits above the real (placeholder) define. The first
		// match must be the active define, not the comment.
		$lines = [ '<?php', "// define( 'AUTH_KEY', 'commented-old-value' );" ];
		foreach ( self::CONSTANTS as $name ) {
			$lines[] = "define( '" . $name . "', 'put your unique phrase here' );";
		}
		$config = implode( "\n", $lines );

		// Detection sees the active defines as weak, not the strong-looking comment.
		$this->assertTrue( Installer::config_has_weak_salts( $config ) );

		$updated = Installer::rewrite_salt_defines( $config, $this->strong_values() );
		$this->assertIsString( $updated );
		$this->assertFalse( Installer::config_has_weak_salts( $updated ) );
		// The commented line is left verbatim; the active define is what changed.
		$this->assertStringContainsString( "// define( 'AUTH_KEY', 'commented-old-value' );", $updated );
		$this->assertStringNotContainsString( 'put your unique phrase here', $updated );
	}

	public function test_rewrite_handles_double_quotes_and_tight_spacing(): void {
		$lines = [ '<?php' ];
		foreach ( self::CONSTANTS as $name ) {
			$lines[] = 'define("' . $name . '","put your unique phrase here");';
		}
		$updated = Installer::rewrite_salt_defines( implode( "\n", $lines ), $this->strong_values() );
		$this->assertIsString( $updated );
		$this->assertFalse( Installer::config_has_weak_salts( $updated ) );
	}
}
