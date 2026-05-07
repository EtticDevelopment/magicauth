<?php
/**
 * Controller: WP-route adapter for the auth model. Owns `?magicauth=verify`,
 * the request POST handler, and the §5.5 hygiene gates.
 *
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Auth;

defined( 'ABSPATH' ) || exit;

use MagicAuth\Email\Mailer;
use WP_Error;
use WP_User;

final class Controller {

	/** Humans don't type an email in under 2s; instant POSTs trip this. */
	private const MIN_FILL_SECONDS = 2;

	/** State A→B browser session token. */
	private const SESSION_COOKIE = 'magicauth_session';

	/** Long enough for a code email to arrive and get typed. */
	private const SESSION_TTL = 30 * MINUTE_IN_SECONDS;

	/** Hook registration. Called from Plugin::boot. */
	public static function setup(): void {
		add_action( 'init', [ self::class, 'maybe_handle_verify_get' ], 1 );
		add_action( 'admin_post_magicauth_request', [ self::class, 'handle_request_post' ] );
		add_action( 'admin_post_nopriv_magicauth_request', [ self::class, 'handle_request_post' ] );
		add_action( 'admin_post_magicauth_password', [ self::class, 'handle_password_post' ] );
		add_action( 'admin_post_nopriv_magicauth_password', [ self::class, 'handle_password_post' ] );
		add_action( 'admin_post_magicauth_lostpassword', [ self::class, 'handle_lostpassword_post' ] );
		add_action( 'admin_post_nopriv_magicauth_lostpassword', [ self::class, 'handle_lostpassword_post' ] );
		add_action( 'admin_post_magicauth_resetpass', [ self::class, 'handle_resetpass_post' ] );
		add_action( 'admin_post_nopriv_magicauth_resetpass', [ self::class, 'handle_resetpass_post' ] );
	}

	/**
	 * Pre-throttle hygiene gates. False = caller takes the generic-error branch;
	 * identical envelope to throttle/miss paths so gates are invisible to probing.
	 *
	 * @param array<string,mixed> $post
	 * @param array<string,mixed> $server
	 */
	public static function pre_throttle_gates( array $post, array $server ): bool {
		// Honeypot.
		$honeypot = isset( $post['magicauth_website'] ) ? (string) $post['magicauth_website'] : '';
		if ( '' !== trim( $honeypot ) ) {
			magicauth_debug_log( 'gate: honeypot tripped' );
			return false;
		}

		// Time-to-fill: rendered ts must be ≥ MIN_FILL_SECONDS in the past.
		$ts_raw = isset( $post['magicauth_ts'] ) ? (string) $post['magicauth_ts'] : '';
		if ( '' === $ts_raw || ! ctype_digit( $ts_raw ) ) {
			magicauth_debug_log( 'gate: time-to-fill missing/non-numeric' );
			return false;
		}
		$ts    = (int) $ts_raw;
		$delta = time() - $ts;
		if ( $delta < self::MIN_FILL_SECONDS ) {
			magicauth_debug_log( 'gate: time-to-fill below floor (delta=' . $delta . ')' );
			return false;
		}

		// Origin/Referer: both absent = reject (CSRF heuristic). Host mismatch = reject.
		$origin  = isset( $server['HTTP_ORIGIN'] ) ? (string) $server['HTTP_ORIGIN'] : '';
		$referer = isset( $server['HTTP_REFERER'] ) ? (string) $server['HTTP_REFERER'] : '';
		$source  = '' !== $origin ? $origin : $referer;
		if ( '' === $source ) {
			magicauth_debug_log( 'gate: origin/referer absent' );
			return false;
		}

		$source_host = wp_parse_url( $source, PHP_URL_HOST );
		$home_host   = function_exists( 'home_url' ) ? wp_parse_url( home_url(), PHP_URL_HOST ) : '';

		if ( ! is_string( $source_host ) || ! is_string( $home_host ) || '' === $source_host || '' === $home_host ) {
			magicauth_debug_log( 'gate: origin host parse failure' );
			return false;
		}

		if ( strcasecmp( $source_host, $home_host ) !== 0 ) {
			magicauth_debug_log( 'gate: origin host mismatch (' . $source_host . ' vs ' . $home_host . ')' );
			return false;
		}

		return true;
	}

	/**
	 * Link-click entry: `?magicauth=verify&s=<sel>&v=<verifier>`.
	 * Wired on init priority 1 so we can emit nocache headers and short-circuit.
	 */
	public static function maybe_handle_verify_get(): void {
		if ( empty( $_GET['magicauth'] ) || 'verify' !== $_GET['magicauth'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}

		nocache_headers();
		header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
		header( 'X-Content-Type-Options: nosniff' );

		$selector    = isset( $_GET['s'] ) ? (string) wp_unslash( (string) $_GET['s'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$verifier    = isset( $_GET['v'] ) ? (string) wp_unslash( (string) $_GET['v'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$redirect_to = isset( $_GET['redirect_to'] ) ? self::sanitize_redirect( (string) wp_unslash( (string) $_GET['redirect_to'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		// Already-logged-in branches (plan §6.D).
		if ( is_user_logged_in() ) {
			self::handle_link_click_logged_in( $selector, $verifier, $redirect_to );
			return;
		}

		$result = TokenManager::validate_link( $selector, $verifier );
		magicauth_jitter();

		if ( $result instanceof WP_Error ) {
			// Bounce to styled login + toast instead of theme-wrapped terminal notice.
			self::redirect_safe(
				add_query_arg(
					[
						'action'                 => 'magicauth',
						'magicauth_link_invalid' => '1',
					],
					wp_login_url()
				)
			);
			return;
		}

		self::set_auth_cookie_or_retry( $result, self::current_request_url() );
		self::redirect_after_login( $result, $redirect_to );
	}

	/**
	 * POST handler for state A (email) and state B (code). Branch by field present.
	 * Identical envelope on every miss: silent, jittered, redirect-back-to-state-B.
	 */
	public static function handle_request_post(): void {
		$nonce_ok = isset( $_POST['magicauth_nonce'] )
			&& wp_verify_nonce( sanitize_key( wp_unslash( (string) $_POST['magicauth_nonce'] ) ), 'magicauth_request' );

		$gates_ok = self::pre_throttle_gates( (array) $_POST, (array) $_SERVER );

		$redirect_to = self::sanitize_redirect( isset( $_POST['redirect_to'] ) ? (string) wp_unslash( $_POST['redirect_to'] ) : '' );

		if ( ! $nonce_ok || ! $gates_ok ) {
			self::end_with_generic_envelope( $redirect_to, 'b' );
			return;
		}

		$ip_hmac    = magicauth_hash_ip( magicauth_client_ip() );
		$session_id = isset( $_POST['magicauth_sid'] ) ? sanitize_key( wp_unslash( (string) $_POST['magicauth_sid'] ) ) : '';

		if ( isset( $_POST['magicauth_code'] ) ) {
			self::handle_code_submit( (string) wp_unslash( $_POST['magicauth_code'] ), $redirect_to, $ip_hmac, $session_id );
			return;
		}

		$email_raw = isset( $_POST['magicauth_email'] ) ? sanitize_email( wp_unslash( (string) $_POST['magicauth_email'] ) ) : '';
		self::handle_email_request( $email_raw, $redirect_to, $ip_hmac );
	}

	/**
	 * Email-request flow (state A → B). Public so tests can hit it without nonce.
	 *
	 * @internal
	 */
	public static function handle_email_request( string $email, string $redirect_to, string $ip_hmac ): void {
		// IP throttle increments unconditionally; malformed emails still pin the
		// counter so nonsense-POST botnets burn through the cap fast.
		if ( ! Throttle::allow_link_request_ip( $ip_hmac ) ) {
			self::end_with_generic_envelope( $redirect_to, 'b', false, '', 'ip_link' );
			return;
		}

		if ( '' === $email || ! is_email( $email ) ) {
			self::end_with_generic_envelope( $redirect_to, 'b' );
			return;
		}

		$email_hmac = magicauth_hash_email( $email );

		// Per-email 60s cooldown (v1.3.6, replaced 3/15min hard cap). Surface
		// remaining seconds in the toast. Second call inside window is denied
		// without re-stamping — no DoS extension.
		if ( ! Throttle::allow_link_request_email( $email_hmac ) ) {
			$secs = Throttle::email_cooldown_remaining( $email_hmac );
			self::end_with_generic_envelope( $redirect_to, 'b', false, '', 'email_cooldown', $secs );
			return;
		}

		$user     = get_user_by( 'email', $email );
		$selector = '';
		if ( $user instanceof WP_User ) {
			$issued = TokenManager::issue( (int) $user->ID, $email );
			if ( is_array( $issued ) ) {
				// Defer wp_mail until after response flush — SMTP latency leaks
				// into response time (2026-05-04 study: ~61ms Happy−Unknown delta
				// from synchronous mailer). magicauth_dispatch_after_response uses
				// register_shutdown_function + fastcgi_finish_request, no cron.
				$link_url       = (string) $issued['link_url'];
				$code_plaintext = (string) $issued['code_plaintext'];
				$expires_at     = (string) $issued['expires_at'];
				$selector       = (string) $issued['selector'];
				$user_id        = (int) $user->ID;
				magicauth_dispatch_after_response(
					static function () use ( $user_id, $link_url, $code_plaintext, $expires_at ): void {
						Mailer::send_magic_link( $user_id, $link_url, $code_plaintext, $expires_at );
					}
				);
			} elseif ( $issued instanceof WP_Error && 'magicauth_user_disabled' === $issued->get_error_code() ) {
				// Backend-only — UI envelope stays generic. 1/24h per email so the
				// form can't be weaponized to flood a disabled user's inbox.
				if ( Throttle::allow_disabled_notice( $email_hmac ) ) {
					$user_id = (int) $user->ID;
					magicauth_dispatch_after_response(
						static function () use ( $user_id ): void {
							Mailer::send_disabled_notice( $user_id );
						}
					);
				}
			}
		}

		// Always start session round-trip so state B works for happy path AND
		// doesn't distinguish unknown-email visitors. Selector binds wrong-code
		// attempts to this session — see start_session_for_email().
		$session_id = self::start_session_for_email( $email, $selector );

		self::end_with_generic_envelope( $redirect_to, 'b', false, $session_id );
	}

	/**
	 * Code-submit flow (state B → authenticated). Public for unit tests.
	 *
	 * @internal
	 */
	public static function handle_code_submit( string $code_raw, string $redirect_to, string $ip_hmac, string $session_id = '' ): void {
		// Every code-submit miss emits the envelope with $with_error=true:
		// throttle, missing session, wrong-code all look identical to a bot,
		// but the legit user gets the inline retry notice.
		if ( ! Throttle::allow_code_submit_ip( $ip_hmac ) ) {
			self::end_with_generic_envelope( $redirect_to, 'b', true, $session_id, 'ip_code' );
			return;
		}

		// Fall back to the cookie sid so validate_code's session lookup uses
		// the same key as session_email() resolves below.
		if ( '' === $session_id && ! empty( $_COOKIE[ self::SESSION_COOKIE ] ) ) {
			$session_id = sanitize_key( wp_unslash( (string) $_COOKIE[ self::SESSION_COOKIE ] ) );
		}

		$session_email = self::session_email( $session_id );
		if ( '' === $session_email ) {
			// State B reached without A — kick back to A. No error flag: user
			// hasn't requested a code yet.
			self::end_with_generic_envelope( $redirect_to, 'a', false );
			return;
		}

		$result = TokenManager::validate_code( $session_email, $code_raw, $session_id );
		if ( $result instanceof WP_Error ) {
			self::end_with_generic_envelope( $redirect_to, 'b', true, $session_id );
			return;
		}

		self::set_auth_cookie_or_retry( $result, $redirect_to );
		self::redirect_after_login( $result, $redirect_to );
	}

	/**
	 * Password-submit POST (state C). Same envelope rules as link/code.
	 * Uses wp_authenticate (not wp_signon) so we keep our try/catch around
	 * wp_set_auth_cookie. We fire wp_login_failed manually so Limit Login
	 * Attempts / Wordfence still see misses.
	 */
	public static function handle_password_post(): void {
		$nonce_ok = isset( $_POST['magicauth_nonce'] )
			&& wp_verify_nonce( sanitize_key( wp_unslash( (string) $_POST['magicauth_nonce'] ) ), 'magicauth_password' );

		$gates_ok    = self::pre_throttle_gates( (array) $_POST, (array) $_SERVER );
		$redirect_to = self::sanitize_redirect( isset( $_POST['redirect_to'] ) ? (string) wp_unslash( $_POST['redirect_to'] ) : '' );

		// Defense in depth: form hides the link when disabled, but crafted POST could still arrive.
		$pw_enabled = (bool) magicauth_get_setting( 'allow_password_login', true );

		if ( ! $nonce_ok || ! $gates_ok || ! $pw_enabled ) {
			self::end_with_generic_envelope( $redirect_to, 'c', true );
			return;
		}

		$ip_hmac = magicauth_hash_ip( magicauth_client_ip() );
		if ( ! Throttle::allow_password_submit_ip( $ip_hmac ) ) {
			self::end_with_generic_envelope( $redirect_to, 'c', true, '', 'ip_password' );
			return;
		}

		$username = isset( $_POST['log'] ) ? trim( (string) wp_unslash( $_POST['log'] ) ) : '';
		// Password not sanitized — wp_authenticate handles it.
		$password = isset( $_POST['pwd'] ) ? (string) wp_unslash( $_POST['pwd'] ) : '';

		if ( '' === $username || '' === $password ) {
			self::end_with_generic_envelope( $redirect_to, 'c', true );
			return;
		}

		$user = wp_authenticate( $username, $password );

		if ( $user instanceof WP_Error ) {
			// Fire manually so security plugins still see the miss (we bypassed wp_signon).
			do_action( 'wp_login_failed', $username, $user );
			self::end_with_generic_envelope( $redirect_to, 'c', true );
			return;
		}

		if ( ! ( $user instanceof WP_User ) ) {
			self::end_with_generic_envelope( $redirect_to, 'c', true );
			return;
		}

		self::set_auth_cookie_or_retry( $user, $redirect_to );
		self::redirect_after_login( $user, $redirect_to );
	}

	/**
	 * Lost-password POST (state D → D with sent toast). Always opaque envelope —
	 * never reveals whether the email exists. Discards retrieve_password()'s
	 * return so we can't accidentally branch on found/not-found.
	 */
	public static function handle_lostpassword_post(): void {
		$nonce_ok = isset( $_POST['magicauth_nonce'] )
			&& wp_verify_nonce( sanitize_key( wp_unslash( (string) $_POST['magicauth_nonce'] ) ), 'magicauth_lostpassword' );

		$gates_ok    = self::pre_throttle_gates( (array) $_POST, (array) $_SERVER );
		$redirect_to = self::sanitize_redirect( isset( $_POST['redirect_to'] ) ? (string) wp_unslash( $_POST['redirect_to'] ) : '' );

		$pw_enabled = (bool) magicauth_get_setting( 'allow_password_login', true );

		if ( ! $nonce_ok || ! $gates_ok || ! $pw_enabled ) {
			// State D + sent-toast keeps envelope indistinguishable from happy path.
			self::end_with_generic_envelope( $redirect_to, 'd', false );
			return;
		}

		$ip_hmac = magicauth_hash_ip( magicauth_client_ip() );
		if ( ! Throttle::allow_password_reset_ip( $ip_hmac ) ) {
			self::end_with_generic_envelope( $redirect_to, 'd', false, '', 'ip_password_reset' );
			return;
		}

		$user_login = isset( $_POST['user_login'] ) ? trim( (string) wp_unslash( $_POST['user_login'] ) ) : '';

		if ( '' !== $user_login ) {
			// Defer to after-response so SMTP latency can't leak whether the
			// account exists. Mirrors the magic-link path in handle_email_request.
			magicauth_dispatch_after_response(
				static function () use ( $user_login ): void {
					retrieve_password( $user_login );
				}
			);
		}

		self::end_with_generic_envelope( $redirect_to, 'd', false );
	}

	/**
	 * Reset-password POST (state E → authenticated). reset_password destroys
	 * all existing sessions, so we issue a fresh auth cookie afterwards.
	 */
	public static function handle_resetpass_post(): void {
		$nonce_ok = isset( $_POST['magicauth_nonce'] )
			&& wp_verify_nonce( sanitize_key( wp_unslash( (string) $_POST['magicauth_nonce'] ) ), 'magicauth_resetpass' );

		$gates_ok    = self::pre_throttle_gates( (array) $_POST, (array) $_SERVER );
		$redirect_to = self::sanitize_redirect( isset( $_POST['redirect_to'] ) ? (string) wp_unslash( $_POST['redirect_to'] ) : '' );

		$key   = isset( $_POST['key'] ) ? trim( (string) wp_unslash( $_POST['key'] ) ) : '';
		$login = isset( $_POST['login'] ) ? trim( (string) wp_unslash( $_POST['login'] ) ) : '';

		if ( ! $nonce_ok || ! $gates_ok ) {
			self::redirect_to_resetpass_with_error( $key, $login, $redirect_to );
			return;
		}

		// Reuse password-submit bucket — brute-force at reset confirmation is functionally a pw attempt.
		$ip_hmac = magicauth_hash_ip( magicauth_client_ip() );
		if ( ! Throttle::allow_password_submit_ip( $ip_hmac ) ) {
			self::redirect_to_resetpass_with_error( $key, $login, $redirect_to );
			return;
		}

		$user = check_password_reset_key( $key, $login );
		if ( $user instanceof WP_Error || ! ( $user instanceof WP_User ) ) {
			// Bad/expired key — bounce to state D (fresh link) instead of dead-end retry.
			self::redirect_safe(
				add_query_arg(
					[
						'action'                 => 'lostpassword',
						'magicauth_link_invalid' => '1',
					],
					wp_login_url()
				)
			);
			return;
		}

		$pass1 = isset( $_POST['pass1'] ) ? (string) wp_unslash( $_POST['pass1'] ) : '';
		$pass2 = isset( $_POST['pass2'] ) ? (string) wp_unslash( $_POST['pass2'] ) : '';

		if ( '' === $pass1 || $pass1 !== $pass2 ) {
			self::redirect_to_resetpass_with_error( $key, $login, $redirect_to );
			return;
		}

		reset_password( $user, $pass1 );

		self::set_auth_cookie_or_retry( $user, $redirect_to );
		self::redirect_after_login( $user, $redirect_to );
	}

	/**
	 * Bounce to branded reset-password form with generic error.
	 * Preserves key+login so user can retry without re-clicking the email.
	 */
	private static function redirect_to_resetpass_with_error( string $key, string $login, string $redirect_to ): void {
		magicauth_jitter();
		$args = [
			'action'          => 'rp',
			'key'             => $key,
			'login'           => $login,
			'magicauth_error' => '1',
		];
		if ( '' !== $redirect_to ) {
			$args['redirect_to'] = $redirect_to;
		}
		self::redirect_safe( add_query_arg( $args, wp_login_url() ) );
	}

	/**
	 * Already-logged-in link click (plan §6.D).
	 * Same user → consume + redirect. Different user → refuse without consume (session fixation).
	 */
	private static function handle_link_click_logged_in( string $selector, string $verifier, string $redirect_to ): void {
		// Match by selector first so we can read user_id.
		if ( ! preg_match( '/^[0-9a-f]{16}$/', $selector ) ) {
			magicauth_jitter();
			self::redirect_safe( home_url( '/' ) );
			return;
		}

		global $wpdb;
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name from class constant via TokenManager::table(), not user input.
		$row = $wpdb->get_row(
			$wpdb->prepare( 'SELECT user_id FROM ' . TokenManager::table() . ' WHERE selector = %s', $selector )
		);

		$current_id = (int) get_current_user_id();

		if ( ! $row || $current_id !== (int) $row->user_id ) {
			magicauth_jitter();
			self::render_terminal_notice(
				__( 'This sign-in link is for a different account.', 'magicauth' ),
				__( 'Sign out first if you need to switch accounts.', 'magicauth' )
			);
			return;
		}

		$result = TokenManager::validate_link( $selector, $verifier );
		magicauth_jitter();
		self::redirect_after_login( $result instanceof WP_User ? $result : null, $redirect_to );
	}

	/**
	 * wp_set_auth_cookie in try/catch; on throw, redirect to retry URL.
	 * Plan §0 #3 + §5: token already counted, no rollback.
	 * Clears the A→B session cookie for both auth paths — stale past sign-in.
	 */
	private static function set_auth_cookie_or_retry( WP_User $user, string $retry_url ): void {
		self::end_session();

		try {
			do_action( 'magicauth_pre_set_auth_cookie', (int) $user->ID, 'shortcode' );
			$remember = (bool) apply_filters( 'magicauth_remember_default', true );
			wp_set_auth_cookie( (int) $user->ID, $remember, is_ssl() );
			wp_set_current_user( (int) $user->ID );
			do_action( 'wp_login', $user->user_login, $user );
		} catch ( \Throwable $e ) {
			magicauth_debug_log( 'wp_set_auth_cookie threw: ' . $e->getMessage() );
			self::redirect_safe( add_query_arg( 'magicauth_retry', '1', $retry_url ) );
		}
	}

	/**
	 * Post-login redirect. Preference: validated form `redirect_to` →
	 * `redirect_to_default` setting → `magicauth_redirect_to` filter (final).
	 */
	private static function redirect_after_login( ?WP_User $user, string $redirect_to = '' ): void {
		$default = self::default_redirect_target( $user );
		$target  = $default;

		if ( '' !== $redirect_to ) {
			$validated = wp_validate_redirect( $redirect_to, $default );
			// Reject wp-login.php targets — would re-render the form post-auth.
			if ( '' !== $validated && false === stripos( $validated, '/wp-login.php' ) ) {
				$target = $validated;
			}
		}

		$target = (string) apply_filters( 'magicauth_redirect_to', $target, $user, 'shortcode' );
		self::redirect_safe( $target );
	}

	/** Default per redirect_to_default setting; 'auto' = admin if user_can read, else home. */
	private static function default_redirect_target( ?WP_User $user ): string {
		$choice = (string) magicauth_get_setting( 'redirect_to_default', 'auto' );
		$home   = home_url( '/' );
		$admin  = function_exists( 'admin_url' ) ? admin_url() : $home;

		switch ( $choice ) {
			case 'home':
				return $home;
			case 'admin':
				return $admin;
			case 'auto':
			default:
				if ( $user instanceof WP_User && function_exists( 'user_can' ) && user_can( $user, 'read' ) ) {
					return $admin;
				}
				return $home;
		}
	}

	/**
	 * Stash email for state B in a transient + HttpOnly cookie. Returns the
	 * session_id so callers can also propagate via URL/POST when the cookie
	 * gets eaten by caching/CDN/COOKIEPATH/headers-sent.
	 *
	 * session_id is only a transient key — doesn't authenticate (code/link still required).
	 * Cookie path hard-coded to '/' to bypass COOKIEPATH weirdness on subfolder/hide-admin setups.
	 *
	 * $selector binds the session to a specific row so wrong-code submits hit
	 * a per-session counter, not a shared per-row one (v1.6.0 — closes account-DoS).
	 * Empty when no row was issued (unknown email / disabled / throttled).
	 */
	private static function start_session_for_email( string $email, string $selector = '' ): string {
		$session_id = bin2hex( random_bytes( 16 ) );
		set_transient(
			'magicauth_session_' . $session_id,
			[
				'email'    => $email,
				'selector' => $selector,
				'attempts' => 0,
			],
			self::SESSION_TTL
		);

		if ( ! headers_sent() ) {
			setcookie(
				self::SESSION_COOKIE,
				$session_id,
				[
					'expires'  => time() + self::SESSION_TTL,
					'path'     => '/',
					'domain'   => defined( 'COOKIE_DOMAIN' ) && COOKIE_DOMAIN ? COOKIE_DOMAIN : '',
					'secure'   => is_ssl(),
					'httponly' => true,
					'samesite' => 'Lax',
				]
			);
		}

		return $session_id;
	}

	/**
	 * Email tied to the browser session. Order: explicit $session_id arg → cookie.
	 * URL/POST path is load-bearing when the cookie doesn't survive; cookie kept
	 * for resumability across tabs/refreshes.
	 */
	private static function session_email( string $session_id = '' ): string {
		if ( '' === $session_id && ! empty( $_COOKIE[ self::SESSION_COOKIE ] ) ) {
			$session_id = sanitize_key( wp_unslash( (string) $_COOKIE[ self::SESSION_COOKIE ] ) );
		}
		if ( '' === $session_id ) {
			return '';
		}
		$payload = get_transient( 'magicauth_session_' . $session_id );
		if ( ! is_array( $payload ) || empty( $payload['email'] ) ) {
			return '';
		}
		return (string) $payload['email'];
	}

	/** Drop session transient + expire cookie. */
	private static function end_session(): void {
		if ( ! empty( $_COOKIE[ self::SESSION_COOKIE ] ) ) {
			$session_id = sanitize_key( wp_unslash( (string) $_COOKIE[ self::SESSION_COOKIE ] ) );
			if ( '' !== $session_id ) {
				delete_transient( 'magicauth_session_' . $session_id );
			}
		}

		if ( ! headers_sent() ) {
			setcookie(
				self::SESSION_COOKIE,
				'',
				[
					'expires'  => time() - HOUR_IN_SECONDS,
					'path'     => '/',
					'domain'   => defined( 'COOKIE_DOMAIN' ) && COOKIE_DOMAIN ? COOKIE_DOMAIN : '',
					'secure'   => is_ssl(),
					'httponly' => true,
					'samesite' => 'Lax',
				]
			);
		}
	}

	/**
	 * Generic-error envelope: jitter + redirect, identical bytes regardless of cause.
	 * $with_error=true on code-submit retries (inline notice for legit user, but
	 * wrong/throttled/session-missing all look identical to a bot). $with_error=false
	 * on happy A→B transition for the clean "we sent it" screen.
	 */
	private static function end_with_generic_envelope(
		string $redirect_to,
		string $state,
		bool $with_error = false,
		string $session_id = '',
		string $blocked = '',
		int $block_secs = 0
	): void {
		magicauth_jitter();
		$step_for_state = [
			'a' => 'email',
			'b' => 'code',
			'c' => 'password',
			'd' => 'lostpassword',
		];
		$args = [ 'magicauth_step' => $step_for_state[ $state ] ?? 'email' ];
		if ( $with_error ) {
			$args['magicauth_error'] = '1';
		}
		// Cookie-free handoff: pass session_id via URL on A→B; renderer embeds in form so
		// code POST resolves session_email even when cookie didn't survive (cache/CDN/samesite).
		if ( '' !== $session_id ) {
			$args['magicauth_sid'] = $session_id;
		} elseif ( 'b' === $state && ! empty( $_COOKIE[ self::SESSION_COOKIE ] ) && ! headers_sent() ) {
			// State-B short-circuit with no fresh session: expire cookie so renderer
			// doesn't fall back to a stale one and surface a previous email.
			// Keep the transient: a concurrent tab POSTing with sid can still resolve.
			setcookie(
				self::SESSION_COOKIE,
				'',
				[
					'expires'  => time() - HOUR_IN_SECONDS,
					'path'     => '/',
					'domain'   => defined( 'COOKIE_DOMAIN' ) && COOKIE_DOMAIN ? COOKIE_DOMAIN : '',
					'secure'   => is_ssl(),
					'httponly' => true,
					'samesite' => 'Lax',
				]
			);
		}
		// Throttle-block toast: enumeration-safe (fires regardless of email existence).
		// block_secs only set when remaining time is portable (email cooldown yes,
		// counter-based IP throttles no — Toast falls back to static window copy).
		if ( '' !== $blocked ) {
			$args['magicauth_blocked'] = $blocked;
			if ( $block_secs > 0 ) {
				$args['magicauth_block_secs'] = $block_secs;
			}
		}
		// "Email sent" toast on every A→B and lostpassword (D) transition. Set
		// regardless of whether email actually issued (unknown/fail/throttle) so
		// envelope stays enumeration-safe. Skipped for retry/blocked — throttle
		// toast carries that signal.
		if ( ! $with_error && '' === $blocked && in_array( $state, [ 'b', 'd' ], true ) ) {
			$args['magicauth_sent'] = '1';
		}
		$url = add_query_arg( $args, $redirect_to );
		self::redirect_safe( $url );
	}

	/** Sanitize form redirect_to; fall back to home. */
	private static function sanitize_redirect( string $candidate ): string {
		$candidate = trim( $candidate );
		$default   = home_url( '/' );
		if ( '' === $candidate ) {
			return $default;
		}
		$validated = wp_validate_redirect( $candidate, '' );
		return '' !== $validated ? $validated : $default;
	}

	/** URL of the current request; used for retry round-trip. */
	private static function current_request_url(): string {
		$host = isset( $_SERVER['HTTP_HOST'] ) ? (string) $_SERVER['HTTP_HOST'] : '';
		$req  = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '/';
		$scheme = is_ssl() ? 'https://' : 'http://';
		return $host ? $scheme . $host . $req : home_url( '/' );
	}

	/** wp_safe_redirect + exit; tests can disable exit via MAGICAUTH_TESTING. */
	private static function redirect_safe( string $url ): void {
		if ( ! function_exists( 'wp_safe_redirect' ) ) {
			return;
		}
		wp_safe_redirect( $url );
		if ( defined( 'MAGICAUTH_TESTING' ) && MAGICAUTH_TESTING ) {
			return;
		}
		exit;
	}

	/** Terminal notice page (link expired, wrong account). Theme-wrapped via get_header/footer. */
	private static function render_terminal_notice( string $heading, string $body ): void {
		status_header( 200 );
		nocache_headers();
		if ( function_exists( 'get_header' ) ) {
			get_header();
		}
		?>
		<div class="magicauth-card magicauth-card--terminal">
			<h1 class="magicauth-heading"><?php echo esc_html( $heading ); ?></h1>
			<p class="magicauth-helper"><?php echo esc_html( $body ); ?></p>
			<p class="magicauth-helper magicauth-helper--small">
				<a class="magicauth-link" href="<?php echo esc_url( home_url( '/' ) ); ?>">
					<?php esc_html_e( 'Back to site', 'magicauth' ); ?>
				</a>
			</p>
		</div>
		<?php
		if ( function_exists( 'get_footer' ) ) {
			get_footer();
		}
		exit;
	}

	/**
	 * Hidden hygiene fields (honeypot + render timestamp). Lives next to the
	 * gate logic so they evolve together. Called by templates/login-form.php.
	 */
	public static function render_hygiene_fields(): void {
		$ts = time();
		?>
		<input
			type="text"
			name="magicauth_website"
			tabindex="-1"
			autocomplete="off"
			aria-hidden="true"
			value=""
			style="position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden;"
		/>
		<input type="hidden" name="magicauth_ts" value="<?php echo esc_attr( (string) $ts ); ?>" />
		<?php
	}
}
