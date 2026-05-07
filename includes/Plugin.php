<?php
/**
 * Plugin bootstrap.
 *
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth;

defined( 'ABSPATH' ) || exit;

/** Singleton wiring; boot() is the entry-point. */
final class Plugin {

	/** @var ?Plugin */
	private static ?Plugin $instance = null;

	/** @var bool */
	private bool $booted = false;

	private function __construct() {}

	public static function instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/** Wire every module. Idempotent. */
	public function boot(): void {
		if ( $this->booted ) {
			return;
		}
		$this->booted = true;

		// Privacy hooks live here so they wire even when admin/frontend modules don't load.
		add_filter( 'wp_privacy_personal_data_exporters', [ $this, 'register_exporter' ] );
		add_filter( 'wp_privacy_personal_data_erasers', [ $this, 'register_eraser' ] );

		add_action( 'magicauth_daily_cleanup', [ Installer::class, 'daily_cleanup' ] );

		add_action( 'admin_notices', [ Installer::class, 'render_salt_notice' ] );
		add_action( 'admin_notices', [ Installer::class, 'render_fpm_notice' ] );

		Auth\Controller::setup();
		Frontend\Shortcode::setup();
		Frontend\LoginScreen::setup();

		if ( is_admin() ) {
			Admin\Settings::setup();
			Admin\UserProfile::setup();
		}

		do_action( 'magicauth_booted' );
	}

	/**
	 * Privacy exporter registration. Callback lives in Auth\TokenManager.
	 *
	 * @param array<string,array<string,mixed>> $exporters
	 * @return array<string,array<string,mixed>>
	 */
	public function register_exporter( array $exporters ): array {
		$exporters['magicauth'] = [
			'exporter_friendly_name' => __( 'MagicAuth login activity', 'magicauth' ),
			'callback'               => [ Auth\TokenManager::class, 'export' ],
		];
		return $exporters;
	}

	/**
	 * Privacy eraser registration. TokenManager::erase deletes user rows and resets throttle counters.
	 *
	 * @param array<string,array<string,mixed>> $erasers
	 * @return array<string,array<string,mixed>>
	 */
	public function register_eraser( array $erasers ): array {
		$erasers['magicauth'] = [
			'eraser_friendly_name' => __( 'MagicAuth login activity', 'magicauth' ),
			'callback'             => [ Auth\TokenManager::class, 'erase' ],
		];
		return $erasers;
	}
}
