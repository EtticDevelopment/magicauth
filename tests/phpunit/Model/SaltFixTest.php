<?php
/**
 * Salt-fix helper: pure salt generation and detection.
 *
 * Covers the file-I/O-free core of the "Fix WordPress salts" feature: local
 * salt generation, the ready-to-paste block, and weak-salt detection. MagicAuth
 * no longer writes wp-config.php, so there is no write path to exercise.
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

	public function test_generated_block_is_locally_random(): void {
		// Local generation only: two blocks must differ (no fixed or remote source).
		$this->assertNotSame( Installer::generate_salt_block(), Installer::generate_salt_block() );
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

	public function test_strong_config_reads_as_clean(): void {
		$lines = [ '<?php' ];
		foreach ( self::CONSTANTS as $name ) {
			$lines[] = "define( '" . $name . "', '" . Installer::generate_salt_value() . "' );";
		}
		$this->assertFalse( Installer::config_has_weak_salts( implode( "\n", $lines ) ) );
	}

	public function test_detection_ignores_commented_define_lines(): void {
		// A commented, strong-looking define sits above the active placeholder
		// defines. Detection must read the active defines (weak), not the comment.
		$lines = [ '<?php', "// define( 'AUTH_KEY', 'commented-old-value' );" ];
		foreach ( self::CONSTANTS as $name ) {
			$lines[] = "define( '" . $name . "', 'put your unique phrase here' );";
		}
		$this->assertTrue( Installer::config_has_weak_salts( implode( "\n", $lines ) ) );
	}

	public function test_detection_handles_double_quoted_defines(): void {
		$weak   = [ '<?php' ];
		$strong = [ '<?php' ];
		foreach ( self::CONSTANTS as $name ) {
			$weak[]   = 'define("' . $name . '","put your unique phrase here");';
			$strong[] = 'define("' . $name . '","' . Installer::generate_salt_value() . '");';
		}
		$this->assertTrue( Installer::config_has_weak_salts( implode( "\n", $weak ) ) );
		$this->assertFalse( Installer::config_has_weak_salts( implode( "\n", $strong ) ) );
	}
}
