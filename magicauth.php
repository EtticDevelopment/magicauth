<?php
/**
 * Plugin Name:       MagicAuth
 * Plugin URI:        https://github.com/EtticDevelopment/magicauth
 * Description:       Passwordless WordPress sign-in via email magic link or 6-character code.
 * Version:           1.0.4
 * Requires at least: 6.4
 * Requires PHP:      8.0
 * Author:            Ettic
 * Author URI:        https://ettic.nl
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       magicauth
 * Domain Path:       /languages
 *
 * @package MagicAuth
 */

declare( strict_types=1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( defined( 'MAGICAUTH_VERSION' ) ) {
	return;
}

define( 'MAGICAUTH_VERSION', '1.0.4' );
define( 'MAGICAUTH_DB_VERSION', 1 );
define( 'MAGICAUTH_FILE', __FILE__ );
define( 'MAGICAUTH_DIR', plugin_dir_path( __FILE__ ) );
define( 'MAGICAUTH_URL', plugin_dir_url( __FILE__ ) );

$magicauth_autoload = MAGICAUTH_DIR . 'vendor/autoload.php';
if ( is_readable( $magicauth_autoload ) ) {
	require_once $magicauth_autoload;
} else {
	spl_autoload_register(
		static function ( string $class ): void {
			if ( 0 !== strpos( $class, 'MagicAuth\\' ) ) {
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
}
unset( $magicauth_autoload );

register_activation_hook( __FILE__, [ MagicAuth\Installer::class, 'activate' ] );
register_deactivation_hook( __FILE__, [ MagicAuth\Installer::class, 'deactivate' ] );

add_action(
	'plugins_loaded',
	static function (): void {
		if ( defined( 'MAGICAUTH_DISABLE' ) && MAGICAUTH_DISABLE ) {
			return;
		}
		MagicAuth\Plugin::instance()->boot();
	},
	10
);
