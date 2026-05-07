<?php
/**
 * Self-contained PHPUnit bootstrap for MagicAuth model-layer tests.
 *
 * No real WordPress required. Provides:
 * - Minimal WP function shims used by the model layer.
 * - A $wpdb shim backed by SQLite (PDO) so atomic UPDATE-with-WHERE semantics
 *   are real, not mocked.
 * - The plugin class autoloader (PSR-4) and procedural helpers.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}
if ( ! defined( 'MAGICAUTH_TESTING' ) ) {
	define( 'MAGICAUTH_TESTING', true );
}
if ( ! defined( 'MAGICAUTH_VERSION' ) ) {
	define( 'MAGICAUTH_VERSION', '1.0.0-test' );
}
if ( ! defined( 'MAGICAUTH_DB_VERSION' ) ) {
	define( 'MAGICAUTH_DB_VERSION', 1 );
}
if ( ! defined( 'MAGICAUTH_DIR' ) ) {
	define( 'MAGICAUTH_DIR', dirname( __DIR__, 2 ) . '/' );
}
if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
	define( 'MINUTE_IN_SECONDS', 60 );
}
if ( ! defined( 'HOUR_IN_SECONDS' ) ) {
	define( 'HOUR_IN_SECONDS', 3600 );
}
if ( ! defined( 'DAY_IN_SECONDS' ) ) {
	define( 'DAY_IN_SECONDS', 86400 );
}
if ( ! defined( 'WEEK_IN_SECONDS' ) ) {
	define( 'WEEK_IN_SECONDS', 604800 );
}

require_once __DIR__ . '/stubs/wp-functions.php';
require_once __DIR__ . '/stubs/wp-error.php';
require_once __DIR__ . '/stubs/wp-user.php';
require_once __DIR__ . '/stubs/wpdb-sqlite.php';

// PSR-4 autoloader for plugin classes (mirrors the production autoloader in
// magicauth.php so we don't rely on composer's autoloader-dump in tests).
spl_autoload_register(
	static function ( string $class ): void {
		if ( 0 !== strpos( $class, 'MagicAuth\\' ) ) {
			return;
		}
		if ( 0 === strpos( $class, 'MagicAuth\\Tests\\' ) ) {
			return;
		}
		$relative = str_replace( '\\', '/', substr( $class, strlen( 'MagicAuth\\' ) ) );
		$file     = MAGICAUTH_DIR . 'includes/' . $relative . '.php';
		if ( is_readable( $file ) ) {
			require_once $file;
		}
	}
);

require_once MAGICAUTH_DIR . 'includes/helpers.php';

// Boot the SQLite-backed $wpdb shim and create the magicauth_requests table.
global $wpdb;
$wpdb = new MagicAuth\Tests\Stubs\WPDBSqlite( 'wp_' );
$wpdb->install_magicauth_schema();
