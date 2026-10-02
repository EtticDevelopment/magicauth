<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Passkeys;

defined( 'ABSPATH' ) || exit;

use MagicAuth\Frontend\LoginScreen;
use MagicAuth\Frontend\Shortcode;

/**
 * Passkey asset loading (SPEC 8.1, 8.11) and the sign-in block markup (8.5,
 * 8.9). The front-end and login hooks are registered by Module::register()
 * only while the module is enabled; enqueue_admin() is registered inside
 * is_admin() whatever the toggle says, for the profile section's removal UI.
 *
 * The login assets (core and login scripts, their config and
 * magicauth-passkeys-login.css) load only for a logged-out visitor on a login
 * form in state A, decided by the same state functions the templates use.
 * The login config carries no per-user data and nothing about creating a
 * passkey (2.6 row 1, invariant 6). The account assets (core and account
 * scripts, the account config, magicauth-passkeys.css) load only for a
 * signed-in user: management page, shortcode render, own or other profile,
 * prompt page. A signals-only page view gets the core script alone.
 */
final class Assets {

	public const CORE_HANDLE = 'magicauth-passkeys-core';

	public const LOGIN_HANDLE = 'magicauth-passkeys-login';

	public const LOGIN_STYLE = 'magicauth-passkeys-login';

	/** Config flags: no </script>, quotes or ampersands survive into the inline script (8.1). */
	private const JSON_FLAGS = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES;

	public const ACCOUNT_HANDLE = 'magicauth-passkeys-account';

	public const ACCOUNT_STYLE = 'magicauth-passkeys';

	/** @var bool The account config is added once per request (shortcode and early detection may both ask). */
	private static bool $account_done = false;

	/** @var bool A config with a signals payload was enqueued in this request (Prompt commits signals_at). */
	private static bool $signals_sent = false;

	/** @var bool The signals-only core script and inline call were enqueued (a late account enqueue still runs). */
	private static bool $signals_only = false;

	/** @var string This request's render key (render_key()), '' until first asked. */
	private static string $render_key = '';

	/**
	 * Signals-only page views (8.7, 8.11): after the deferred core script ran,
	 * signalAllAcceptedCredentials then signalCurrentUserDetails with the
	 * reduced config captured here; an empty list drops this account's
	 * haslocal and keeps promptfail (5.3, 2.1 gate). ES5, every rejection
	 * swallowed by the wrapper.
	 */
	private const SIGNALS_CALL = '(function(c){function run(){var P=window.MagicAuthPasskeys,s=c&&c.signals;'
		. 'if(!P||!s||!s.rpId||!s.userId||!Array.isArray(s.allAccepted)){return;}'
		. 'P.signal("signalAllAcceptedCredentials",{rpId:s.rpId,userId:s.userId,allAcceptedCredentialIds:s.allAccepted})'
		. '.then(function(){return P.signal("signalCurrentUserDetails",{rpId:s.rpId,userId:s.userId,name:s.name,displayName:s.displayName});});'
		. 'if(!s.allAccepted.length&&c.account&&c.account.key){try{var k=c.account.key,m=JSON.parse(window.localStorage.getItem("magicauth:pk:acct")||"{}")||{},e=m[k];'
		. 'if(e&&typeof e==="object"&&typeof e.promptfail==="number"){m[k]={promptfail:e.promptfail};}else{delete m[k];}'
		. 'window.localStorage.setItem("magicauth:pk:acct",JSON.stringify(m));}catch(x){}}}'
		. 'if(document.readyState==="loading"){document.addEventListener("DOMContentLoaded",run);}else{run();}}(window.magicauthPasskeysConfig));';

	/**
	 * wp_enqueue_scripts 20, after Shortcode::enqueue (10). Signed in: the
	 * account assets on a management page (8.11). Logged out: the login
	 * assets on the shortcode page or a theme wall with
	 * magicauth_force_frontend_assets, state A.
	 */
	public static function enqueue_front(): void {
		if ( is_admin() || ! Module::enabled() ) {
			return;
		}
		if ( is_user_logged_in() ) {
			if ( ManageShortcode::is_management_page() ) {
				$user = wp_get_current_user();
				self::enqueue_account( $user, AccountEndpoints::items( $user, true ) );
			}
			return;
		}
		if ( ! Shortcode::wants_assets() || 'a' !== Shortcode::current_state() ) {
			return;
		}
		self::enqueue_login();
	}

	/** login_enqueue_scripts 20: wp-login.php?action=magicauth in state A. */
	public static function enqueue_login_screen(): void {
		if ( ! Module::enabled() || is_user_logged_in() ) {
			return;
		}
		$action = isset( $_GET['action'] ) && is_string( $_GET['action'] ) ? sanitize_key( wp_unslash( $_GET['action'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only routing, as LoginScreen::enqueue().
		if ( 'magicauth' !== $action ) {
			return;
		}
		$step = isset( $_GET['magicauth_step'] ) && is_string( $_GET['magicauth_step'] ) ? sanitize_key( wp_unslash( $_GET['magicauth_step'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only routing.
		if ( 'a' !== LoginScreen::resolve_state( $step ) ) {
			return;
		}
		self::enqueue_login();
	}

	/**
	 * The login config, exactly (8.1): two sign-in actions plus the
	 * completion, strings L1 to L11 and L3b. Cache-safe: the same for every
	 * visitor.
	 *
	 * @return array{ajaxUrl:string,rpId:string,homeUrl:string,actions:array{signinOptions:string,signin:string,complete:string},i18n:array<string,string>}
	 */
	public static function login_config(): array {
		return [
			'ajaxUrl' => admin_url( 'admin-ajax.php' ),
			'rpId'    => RelyingParty::id(),
			'homeUrl' => home_url( '/' ),
			'actions' => [
				'signinOptions' => 'magicauth_passkey_signin_options',
				'signin'        => 'magicauth_passkey_signin',
				'complete'      => 'magicauth_passkey_complete',
			],
			'i18n'    => SignInEndpoints::strings(),
		];
	}

	/**
	 * The default sign-in block (8.5 item 3): hidden until the login script
	 * finds WebAuthn (G1); the status and alert regions are always rendered.
	 * Sign-in only. Every value is escaped here.
	 *
	 * @param array<string,mixed> $args redirect_to: data-magicauth-redirect-to on the root (8.9).
	 */
	public static function signin_markup( array $args = [] ): string {
		$strings  = SignInEndpoints::strings();
		$redirect = isset( $args['redirect_to'] ) && is_string( $args['redirect_to'] ) ? esc_url( $args['redirect_to'] ) : '';
		$target   = '' !== $redirect ? ' data-magicauth-redirect-to="' . esc_attr( $redirect ) . '"' : '';

		return '<div class="magicauth-passkey" data-magicauth-passkey-root' . $target . ' hidden>'
			. '<p class="magicauth-divider" aria-hidden="true"><span>' . esc_html( $strings['L9'] ) . '</span></p>'
			. '<button type="button" class="magicauth-button magicauth-button--secondary" data-magicauth-passkey-signin hidden>'
			. '<span class="magicauth-button__label">' . esc_html( $strings['L1'] ) . '</span>'
			. '<span class="magicauth-button__spinner" aria-hidden="true"></span>'
			. '</button>'
			. '<p class="magicauth-passkey__status magicauth-pk-sr-only" data-magicauth-passkey-status role="status"></p>'
			. '<p class="magicauth-passkey__error" data-magicauth-passkey-error role="alert"></p>'
			. '</div>';
	}

	/**
	 * admin_enqueue_scripts 20 (inside is_admin(), whatever the toggle):
	 * profile.php and user-edit.php when ProfileSection shows a section for
	 * the target. Own profile with the module on: the full account config;
	 * otherwise the removal config only (admin endpoints, no nonce for the
	 * account endpoints, no signals).
	 *
	 * @param string $hook_suffix Admin page.
	 */
	public static function enqueue_admin( $hook_suffix = '' ): void {
		if ( ! in_array( $hook_suffix, [ 'profile.php', 'user-edit.php' ], true ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only routing, as core's user-edit.php.
		$tid    = 'user-edit.php' === $hook_suffix && isset( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : get_current_user_id();
		$target = $tid > 0 ? get_userdata( $tid ) : false;
		if ( ! $target instanceof \WP_User ) {
			return;
		}
		$view = ProfileSection::view( $target );
		if ( null === $view ) {
			return;
		}
		if ( 'manage' === $view['mode'] ) {
			self::enqueue_account( $target, $view['items'] );
			return;
		}
		self::enqueue_account_files(
			[
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'actions' => self::actions(),
				'i18n'    => ManageShortcode::strings(),
				'render'  => self::render_key(),
			]
		);
	}

	/**
	 * Core and account scripts, the account config and the passkeys
	 * stylesheet for the signed-in owner (8.1, 8.11). Once per request; true
	 * when the assets are enqueued (now or earlier in the request).
	 *
	 * @param \WP_User                            $user    The signed-in user.
	 * @param array<int,array<string,mixed>>|null $items   Their Items, null when unreadable.
	 * @param bool                                $prompt  The prompt dialog is printed (prompt.show).
	 * @param bool                                $signals Carry the signals payload (prompt pages: only when due).
	 */
	public static function enqueue_account( \WP_User $user, ?array $items, bool $prompt = false, bool $signals = true ): bool {
		if ( self::$account_done ) {
			return true;
		}
		// After a signals-only enqueue (a shortcode early detection missed, 8.11): the inline call sends them.
		if ( self::$signals_only ) {
			$signals = false;
		}
		return self::enqueue_account_files( self::account_config( $user, $items, $prompt, $signals ) );
	}

	/**
	 * Signals-only page view (8.7, 8.11): the core script alone, with the
	 * reduced config { ajaxUrl, account: { key }, signals } and the inline
	 * call, both before it (an 'after' inline script would cost the defer
	 * strategy). Nothing when the account assets or this call are already
	 * there, or the payload is null (an incomplete list is never sent,
	 * invariant 7). A later enqueue_account() still adds the account assets,
	 * with signals null.
	 *
	 * @param \WP_User $user The signed-in user.
	 */
	public static function enqueue_signals( \WP_User $user ): bool {
		if ( self::$account_done || self::$signals_only ) {
			return false;
		}
		$payload = Signals::payload( $user );
		if ( null === $payload ) {
			return false;
		}
		$json = wp_json_encode(
			[
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'account' => [ 'key' => self::account_key( $user ) ],
				'signals' => $payload,
			],
			self::JSON_FLAGS
		);
		if ( ! is_string( $json ) ) {
			return false;
		}
		self::$signals_only = true;
		self::$signals_sent = true;
		wp_enqueue_script(
			self::CORE_HANDLE,
			MAGICAUTH_URL . 'assets/js/magicauth-passkeys-core.js',
			[],
			MAGICAUTH_VERSION,
			[
				'in_footer' => true,
				'strategy'  => 'defer',
			]
		);
		wp_add_inline_script( self::CORE_HANDLE, 'window.magicauthPasskeysConfig = ' . $json . ';' . self::SIGNALS_CALL, 'before' );
		return true;
	}

	/** A config of this request carried a signals payload (Prompt::render_footer() commits signals_at). */
	public static function signals_delivered(): bool {
		return self::$signals_sent;
	}

	/**
	 * The account config (8.1): { ajaxUrl, rpId, nonce, manageUrl, account: {
	 * key }, prompt: { show, hasPasskeys }, signals, passkeys, reauth: {
	 * methods }, actions, i18n, render }. Per user: only on no-store pages. On a
	 * prompt page i18n adds the prompt strings and signals is null unless
	 * they are due (8.7). prompt.hasPasskeys counts the current RP ID only,
	 * as check 10 and the P1b heading do.
	 *
	 * @param \WP_User                            $user    The signed-in user.
	 * @param array<int,array<string,mixed>>|null $items   Their Items.
	 * @param bool                                $prompt  prompt.show.
	 * @param bool                                $signals Include the signals payload.
	 * @return array<string,mixed>
	 */
	public static function account_config( \WP_User $user, ?array $items, bool $prompt = false, bool $signals = true ): array {
		$i18n = ManageShortcode::strings();
		if ( $prompt ) {
			$i18n = array_merge( $i18n, Prompt::strings( $user ) );
		}
		return [
			'ajaxUrl'   => admin_url( 'admin-ajax.php' ),
			'rpId'      => RelyingParty::id(),
			'nonce'     => wp_create_nonce( AccountEndpoints::NONCE ),
			'manageUrl' => Module::manage_url( $user ),
			'account'   => [ 'key' => self::account_key( $user ) ],
			'prompt'    => [
				'show'        => $prompt,
				'hasPasskeys' => self::has_usable( $items ),
			],
			'signals'   => $signals ? Signals::payload( $user ) : null,
			// Null when the list could not be read: the script then never
			// treats the account as holding no passkey (forget(), 5.3).
			'passkeys'  => $items,
			'reauth'    => [ 'methods' => (array) AccountEndpoints::reauth_methods( $user ) ],
			'actions'   => self::actions(),
			'i18n'      => $i18n,
			'render'    => self::render_key(),
		];
	}

	/**
	 * Per-request random key that the management section, its dialogs and the
	 * prompt carry as data-magicauth-pk-render and the account config as
	 * render. The account script binds only to roots with this key, so markup
	 * with the same data attributes in post content (kses keeps data-*) is
	 * never bound to the viewer's nonce.
	 */
	public static function render_key(): string {
		if ( '' === self::$render_key ) {
			self::$render_key = bin2hex( random_bytes( 16 ) );
		}
		return self::$render_key;
	}

	/**
	 * Per-account browser storage key (2.1, 5.3): the first 16 hex characters
	 * of SHA-256 of the user handle, '' without a handle. Identifies nothing
	 * outside this browser profile.
	 *
	 * @param \WP_User $user The signed-in user.
	 */
	public static function account_key( \WP_User $user ): string {
		$handle = CredentialStore::user_handle( (int) $user->ID, false );
		return null !== $handle ? substr( hash( 'sha256', $handle ), 0, 16 ) : '';
	}

	/**
	 * Any Item for the current RP ID (usable_here).
	 *
	 * @param array<int,array<string,mixed>>|null $items Items, null when unreadable.
	 */
	private static function has_usable( ?array $items ): bool {
		foreach ( (array) $items as $item ) {
			if ( ! empty( $item['usable_here'] ) ) {
				return true;
			}
		}
		return false;
	}

	/** Test-only: forget the once-per-request guard. No-op outside MAGICAUTH_TESTING. */
	public static function reset_for_tests(): void {
		if ( defined( 'MAGICAUTH_TESTING' ) && MAGICAUTH_TESTING ) {
			self::$account_done = false;
			self::$signals_sent = false;
			self::$signals_only = false;
			self::$render_key   = '';
		}
	}

	/**
	 * Account and admin action names for the account script.
	 *
	 * @return array<string,string>
	 */
	private static function actions(): array {
		return [
			'registerOptions' => 'magicauth_passkey_register_options',
			'register'        => 'magicauth_passkey_register',
			'rename'          => 'magicauth_passkey_rename',
			'delete'          => 'magicauth_passkey_delete',
			'signoutOthers'   => 'magicauth_passkey_signout_others',
			'reauthEmail'     => 'magicauth_passkey_reauth_email',
			'reauthCode'      => 'magicauth_passkey_reauth_code',
			'reauthOptions'   => 'magicauth_passkey_reauth_options',
			'reauthPasskey'   => 'magicauth_passkey_reauth_passkey',
			'promptChoice'    => 'magicauth_passkey_prompt',
			'adminDelete'     => 'magicauth_admin_passkey_delete',
			'adminRevokeAll'  => 'magicauth_admin_passkey_revoke_all',
		];
	}

	/**
	 * Core and account scripts (deferred, footer), the inline config, the
	 * passkeys stylesheet unless magicauth_passkeys_enqueue_style is false.
	 *
	 * @param array<string,mixed> $config The config object.
	 */
	private static function enqueue_account_files( array $config ): bool {
		if ( self::$account_done ) {
			return true;
		}
		$json = wp_json_encode( $config, self::JSON_FLAGS );
		if ( ! is_string( $json ) ) {
			return false;
		}
		self::$account_done = true;
		if ( isset( $config['signals'] ) ) {
			self::$signals_sent = true;
		}
		$args = [
			'in_footer' => true,
			'strategy'  => 'defer',
		];
		wp_enqueue_script( self::CORE_HANDLE, MAGICAUTH_URL . 'assets/js/magicauth-passkeys-core.js', [], MAGICAUTH_VERSION, $args );
		wp_enqueue_script( self::ACCOUNT_HANDLE, MAGICAUTH_URL . 'assets/js/magicauth-passkeys-account.js', [ self::CORE_HANDLE ], MAGICAUTH_VERSION, $args );
		wp_add_inline_script( self::ACCOUNT_HANDLE, 'window.magicauthPasskeysConfig = ' . $json . ';', 'before' );

		if ( (bool) apply_filters( 'magicauth_passkeys_enqueue_style', true ) ) {
			wp_enqueue_style( self::ACCOUNT_STYLE, MAGICAUTH_URL . 'assets/css/magicauth-passkeys.css', [], MAGICAUTH_VERSION );
		}
		return true;
	}

	/** Core and login scripts (deferred, footer), the inline config, the login stylesheet. */
	private static function enqueue_login(): void {
		$config = wp_json_encode( self::login_config(), self::JSON_FLAGS );
		if ( ! is_string( $config ) ) {
			return;
		}
		$args = [
			'in_footer' => true,
			'strategy'  => 'defer',
		];
		wp_enqueue_script( self::CORE_HANDLE, MAGICAUTH_URL . 'assets/js/magicauth-passkeys-core.js', [], MAGICAUTH_VERSION, $args );
		wp_enqueue_script( self::LOGIN_HANDLE, MAGICAUTH_URL . 'assets/js/magicauth-passkeys-login.js', [ self::CORE_HANDLE ], MAGICAUTH_VERSION, $args );
		wp_add_inline_script( self::LOGIN_HANDLE, 'window.magicauthPasskeysConfig = ' . $config . ';', 'before' );

		if ( (bool) apply_filters( 'magicauth_passkeys_enqueue_style', true ) ) {
			wp_enqueue_style( self::LOGIN_STYLE, MAGICAUTH_URL . 'assets/css/magicauth-passkeys-login.css', [], MAGICAUTH_VERSION );
		}
	}
}
