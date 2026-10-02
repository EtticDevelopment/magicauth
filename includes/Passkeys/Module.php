<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Passkeys;

defined( 'ABSPATH' ) || exit;

use WP_Error;
use WP_User;

/**
 * The passkeys module (SPEC 4.5, 4.6): toggle, availability, hook
 * registration, management URL.
 *
 * setup() runs from Plugin::boot() (plugins_loaded) and registers the data
 * hooks that must work whatever the toggle says, plus register() on init 0.
 * register() decides enabled() once, after a theme's functions.php has added
 * its filters, and registers the module hooks only then. Nothing is cached
 * before init (4.1).
 */
final class Module {

	/** Default for max_per_user(). */
	public const MAX_PER_USER = 10;

	private const MAX_PER_USER_CAP = 25;

	/** Schema version the module needs (S8f). */
	private const DB_VERSION = 2;

	/** @var bool|null Test override for the OpenSSL check (S8c). */
	private static $openssl_for_tests = null;

	/** @var bool|null enabled() for this request, set once init has fired. */
	private static $enabled = null;

	/**
	 * Always-on hooks (4.6 first and third tables): user deletion and an
	 * email change clean passkey data even with the module off (data may
	 * exist from an earlier "on" period); in wp-admin the profile section and
	 * the admin removal endpoints keep stored passkeys removable.
	 * CredentialStore::on_delete_user() also deletes the magicauth_requests
	 * rows (B10).
	 */
	public static function setup(): void {
		add_action( 'delete_user', [ CredentialStore::class, 'on_delete_user' ] );
		add_action( 'wpmu_delete_user', [ CredentialStore::class, 'on_wpmu_delete_user' ] );
		add_action( 'profile_update', [ AccountEvents::class, 'on_profile_update' ], 10, 3 );
		add_action( 'init', [ self::class, 'register' ], 0 );
		// Always: with the module off it renders '' instead of the literal shortcode text.
		add_shortcode( ManageShortcode::TAG, [ ManageShortcode::class, 'render' ] );

		// Admin removal works with the module off: stored passkeys stay removable.
		if ( is_admin() ) {
			add_action( 'wp_ajax_magicauth_admin_passkey_delete', [ AdminEndpoints::class, 'delete' ] );
			add_action( 'wp_ajax_magicauth_admin_passkey_revoke_all', [ AdminEndpoints::class, 'revoke_all' ] );
			add_action( 'show_user_profile', [ ProfileSection::class, 'render' ], 9 );
			add_action( 'edit_user_profile', [ ProfileSection::class, 'render' ], 9 );
			add_action( 'admin_footer', [ ProfileSection::class, 'render_dialogs' ], 20 );
			add_action( 'admin_enqueue_scripts', [ Assets::class, 'enqueue_admin' ], 20 );
		}
	}

	/**
	 * init 0: evaluates enabled() (cached from here on) and, when enabled,
	 * registers the module hooks. admin-ajax dispatches wp_ajax_* after init,
	 * so the endpoints are in time.
	 */
	public static function register(): void {
		if ( ! self::enabled() ) {
			return;
		}
		foreach ( self::module_hooks() as $hook ) {
			add_action( $hook[0], $hook[1], $hook[2], $hook[3] );
		}
	}

	/**
	 * Setting passkeys_enabled on and available() true. Cached for the
	 * request once init has fired; before init computed without caching, so
	 * a filter a theme adds later still counts.
	 */
	public static function enabled(): bool {
		if ( null !== self::$enabled ) {
			return self::$enabled;
		}
		$on = ! empty( magicauth_get_setting( 'passkeys_enabled', false ) ) && true === self::available();
		if ( did_action( 'init' ) > 0 ) {
			self::$enabled = $on;
		}
		return $on;
	}

	/**
	 * Whether this site can run the module: true, or WP_Error with the first
	 * matching reason in the fixed order S8c, S8a, S8d, S8b, S8g, S8e, S8f.
	 * Message is the S8x text (S8 wraps it in the settings error).
	 *
	 * @return true|WP_Error
	 */
	public static function available() {
		if ( ! self::openssl_available() ) {
			return new WP_Error( 'magicauth_pk_no_openssl', __( 'the PHP OpenSSL extension is missing.', 'magicauth' ) );
		}

		$home   = home_url();
		$host   = RelyingParty::host();
		$scheme = wp_parse_url( $home, PHP_URL_SCHEME );
		$scheme = is_string( $scheme ) ? strtolower( $scheme ) : '';

		if ( '' !== $host && ( false !== strpos( $host, '[' ) || false !== filter_var( $host, FILTER_VALIDATE_IP ) ) ) {
			return new WP_Error( 'magicauth_pk_ip_host', __( 'the site address is an IP address.', 'magicauth' ) );
		}
		if ( 'https' !== $scheme && 'localhost' !== $host ) {
			return new WP_Error( 'magicauth_pk_not_https', __( 'the site is not served over HTTPS.', 'magicauth' ) );
		}
		$home_origin = RelyingParty::normalise_origin( $home );
		if ( null === $home_origin || RelyingParty::normalise_origin( site_url() ) !== $home_origin ) {
			return new WP_Error( 'magicauth_pk_origin_mismatch', __( 'the home and site addresses differ (scheme, host or port).', 'magicauth' ) );
		}
		$rp_error = RelyingParty::config_error();
		if ( null !== $rp_error ) {
			return $rp_error;
		}
		if ( self::shares_host() ) {
			return new WP_Error( 'magicauth_pk_shared_host', __( 'another WordPress site shares this address (subfolder install or subdirectory multisite).', 'magicauth' ) );
		}
		// A failed schema check never bumps the version (5.4), so this covers it.
		if ( (int) get_option( 'magicauth_db_version', 0 ) < self::DB_VERSION ) {
			return new WP_Error( 'magicauth_pk_schema', __( 'the database tables are missing. Reload this page to retry the upgrade.', 'magicauth' ) );
		}
		return true;
	}

	/** Filter magicauth_passkey_max_per_user, clamped to [1, 25]. */
	public static function max_per_user(): int {
		$max = apply_filters( 'magicauth_passkey_max_per_user', self::MAX_PER_USER );
		$max = is_numeric( $max ) ? (int) $max : self::MAX_PER_USER;
		return max( 1, min( self::MAX_PER_USER_CAP, $max ) );
	}

	/**
	 * Offered COSE algorithms in preference order: -7, -8 when Ed25519 can be
	 * verified (the library's own condition), -257.
	 *
	 * @return array<int,int>
	 */
	public static function supported_algs(): array {
		$eddsa = function_exists( 'sodium_crypto_sign_verify_detached' ) || defined( 'OPENSSL_KEYTYPE_ED25519' );
		return $eddsa ? [ -7, -8, -257 ] : [ -7, -257 ];
	}

	/**
	 * Where the user manages passkeys: the published management page
	 * (passkeys_manage_page_id); else their wp-admin profile when they can
	 * edit posts; else ''. Filter magicauth_passkey_manage_url.
	 *
	 * @param WP_User $user The account the URL is for.
	 */
	public static function manage_url( WP_User $user ): string {
		$url     = '';
		$page_id = self::manage_page_id();
		if ( $page_id > 0 ) {
			$link = get_permalink( $page_id );
			$url  = is_string( $link ) ? $link : '';
		}
		if ( '' === $url && user_can( $user, 'edit_posts' ) ) {
			$url = admin_url( 'profile.php#magicauth-passkeys' );
		}
		$url = apply_filters( 'magicauth_passkey_manage_url', $url, $user );
		return is_string( $url ) ? $url : '';
	}

	/**
	 * manage_url() in words for emails (10.2), plain text, never a link:
	 * "Title (/path/)" for the management page, M37 for the wp-admin profile,
	 * the URL path for a filtered URL, '' when there is none.
	 *
	 * @param WP_User $user The account the location is for.
	 */
	public static function manage_location( WP_User $user ): string {
		$url = self::manage_url( $user );
		if ( '' === $url ) {
			return '';
		}
		if ( admin_url( 'profile.php#magicauth-passkeys' ) === $url ) {
			return __( 'your profile in the dashboard', 'magicauth' );
		}
		$path = wp_parse_url( $url, PHP_URL_PATH );
		$path = is_string( $path ) && '' !== $path ? $path : '/';

		$page_id = self::manage_page_id();
		if ( $page_id > 0 && get_permalink( $page_id ) === $url ) {
			$title = trim( wp_strip_all_tags( html_entity_decode( (string) get_the_title( $page_id ), ENT_QUOTES, 'UTF-8' ) ) );
			if ( '' !== $title ) {
				return sprintf( '%1$s (%2$s)', $title, $path );
			}
		}
		return $path;
	}

	/** Test-only: forget the per-request enabled() value. No-op outside MAGICAUTH_TESTING. */
	public static function reset_for_tests(): void {
		if ( defined( 'MAGICAUTH_TESTING' ) && MAGICAUTH_TESTING ) {
			self::$enabled           = null;
			self::$openssl_for_tests = null;
		}
	}

	/**
	 * Test seam for S8c (no-op outside MAGICAUTH_TESTING); null restores the
	 * real check.
	 */
	public static function set_openssl_for_tests( ?bool $available ): void {
		if ( defined( 'MAGICAUTH_TESTING' ) && MAGICAUTH_TESTING ) {
			self::$openssl_for_tests = $available;
		}
	}

	/** passkeys_manage_page_id when it is a published page, else 0. */
	private static function manage_page_id(): int {
		$page_id = absint( magicauth_get_setting( 'passkeys_manage_page_id', 0 ) );
		if ( $page_id <= 0 || 'publish' !== get_post_status( $page_id ) || 'page' !== get_post_type( $page_id ) ) {
			return 0;
		}
		return $page_id;
	}

	/**
	 * Module hooks (4.6 second table) as [ hook, callback, priority,
	 * accepted_args ]. Sign-in endpoints answer logged-out and logged-in
	 * browsers (nopriv and priv); account endpoints are wp_ajax_ only, never
	 * nopriv (2.6 rows 10 to 12 and 14). The shortcode is registered by
	 * setup(). Prompt::prepare_front also sends the management-page headers.
	 *
	 * @return array<int,array{0:string,1:callable,2:int,3:int}>
	 */
	private static function module_hooks(): array {
		return [
			[ 'wp_ajax_magicauth_passkey_rename', [ AccountEndpoints::class, 'rename' ], 10, 0 ],
			[ 'wp_ajax_magicauth_passkey_delete', [ AccountEndpoints::class, 'delete' ], 10, 0 ],
			[ 'wp_ajax_magicauth_passkey_signout_others', [ AccountEndpoints::class, 'signout_others' ], 10, 0 ],
			[ 'wp_ajax_magicauth_passkey_prompt', [ AccountEndpoints::class, 'prompt_choice' ], 10, 0 ],
			[ 'template_redirect', [ Prompt::class, 'prepare_front' ], PHP_INT_MAX, 0 ],
			[ 'wp_footer', [ Prompt::class, 'render_footer' ], 20, 0 ],
			[ 'current_screen', [ Prompt::class, 'prepare_admin' ], 10, 1 ],
			[ 'admin_footer', [ Prompt::class, 'render_footer' ], 20, 0 ],
			[ 'wp_ajax_nopriv_magicauth_passkey_signin_options', [ SignInEndpoints::class, 'options' ], 10, 0 ],
			[ 'wp_ajax_magicauth_passkey_signin_options', [ SignInEndpoints::class, 'options' ], 10, 0 ],
			[ 'wp_ajax_nopriv_magicauth_passkey_signin', [ SignInEndpoints::class, 'verify' ], 10, 0 ],
			[ 'wp_ajax_magicauth_passkey_signin', [ SignInEndpoints::class, 'verify' ], 10, 0 ],
			[ 'wp_ajax_nopriv_magicauth_passkey_complete', [ SignInEndpoints::class, 'complete' ], 10, 0 ],
			[ 'wp_ajax_magicauth_passkey_complete', [ SignInEndpoints::class, 'complete' ], 10, 0 ],
			[ 'wp_enqueue_scripts', [ Assets::class, 'enqueue_front' ], 20, 0 ],
			[ 'login_enqueue_scripts', [ Assets::class, 'enqueue_login_screen' ], 20, 0 ],
			[ 'wp_ajax_magicauth_passkey_register_options', [ AccountEndpoints::class, 'register_options' ], 10, 0 ],
			[ 'wp_ajax_magicauth_passkey_register', [ AccountEndpoints::class, 'register' ], 10, 0 ],
			[ 'wp_ajax_magicauth_passkey_reauth_email', [ AccountEndpoints::class, 'reauth_email' ], 10, 0 ],
			[ 'wp_ajax_magicauth_passkey_reauth_code', [ AccountEndpoints::class, 'reauth_code' ], 10, 0 ],
			[ 'wp_ajax_magicauth_passkey_reauth_options', [ AccountEndpoints::class, 'reauth_options' ], 10, 0 ],
			[ 'wp_ajax_magicauth_passkey_reauth_passkey', [ AccountEndpoints::class, 'reauth_passkey' ], 10, 0 ],
		];
	}

	private static function openssl_available(): bool {
		if ( null !== self::$openssl_for_tests && defined( 'MAGICAUTH_TESTING' ) && MAGICAUTH_TESTING ) {
			return self::$openssl_for_tests;
		}
		return function_exists( 'openssl_verify' );
	}

	/**
	 * S8e: the RP ID has no path, so a subfolder install or a subdirectory
	 * multisite would share credentials, handles and signals with another site.
	 * On a network MAGICAUTH_PASSKEY_RP_ID may not widen the RP ID beyond the
	 * site host: every subsite would get the same rp.id while the user handle
	 * is network-wide and the credential table per site.
	 */
	private static function shares_host(): bool {
		$path = wp_parse_url( home_url(), PHP_URL_PATH );
		if ( is_string( $path ) && '' !== $path && '/' !== $path ) {
			return true;
		}
		if ( is_multisite() && RelyingParty::id() !== RelyingParty::host() ) {
			return true;
		}
		if ( is_multisite() && ! is_subdomain_install() ) {
			$count = get_sites(
				[
					'domain' => RelyingParty::host(),
					'count'  => true,
				]
			);
			return is_numeric( $count ) && (int) $count > 1;
		}
		return false;
	}
}
