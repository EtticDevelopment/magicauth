<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Passkeys;

defined( 'ABSPATH' ) || exit;

use MagicAuth\Auth\Login;
use MagicAuth\Auth\Throttle;
use WP_Error;
use WP_User;

/**
 * Passkey sign-in endpoints (SPEC 6.2, 6.3, 6.13, 7.4): request options, the
 * verify fetch that returns a single-use completion token, and the top-level
 * completion POST that establishes the session through Login::establish().
 * Registered for wp_ajax_nopriv_ and wp_ajax_ by Module::register() while the
 * module is enabled; every handler re-checks the module.
 *
 * Logged-out calls carry no WordPress nonce (cached pages, B15). They are
 * bound to the magicauth_pk_bind cookie (host-only, HttpOnly, SameSite=Strict,
 * scoped to admin-ajax) and gated on the Origin. No auth cookie is set except
 * by complete(), through Login::establish() (invariant 2).
 */
final class SignInEndpoints {

	/** Binding cookie of the signin challenge and the completion token (5.3). */
	public const BIND_COOKIE = 'magicauth_pk_bind';

	/** signin TTL + 120 s, so every bound row expires before the cookie (invariant 9). */
	public const BIND_MAX_AGE = 720;

	/** Seconds after which the login script fetches fresh options (6.2). */
	public const REFRESH_AFTER = 540;

	/** Query parameter of a completion failure on return_to (6.13). */
	public const ERROR_PARAM = 'magicauth_passkey_error';

	/** redirect_to and return_to cap in bytes. */
	private const MAX_URL = 2048;

	/** Completion token: 32 bytes, 43 base64url characters. */
	private const TOKEN_CHARS = 43;

	/** Expired challenge rows deleted per signin_options call (5.4). */
	private const PURGE_PER_CALL = 20;

	/** magicauth_passkey_signin_options (6.2). */
	public static function options(): void {
		Http::require_post();
		if ( ! Module::enabled() ) {
			self::fail( 'unavailable', 404 );
		}
		if ( ! Http::origin_ok() ) {
			self::fail( 'passkey_failed', 403 );
		}
		// Per network first: a call its network was refused for never counts
		// toward the global ceiling, so one host cannot use it up (T14).
		if ( ! Throttle::allow_passkey_options_ip( self::ip_bucket() ) || ! Throttle::allow_passkey_options_global() ) {
			self::fail( 'throttled', 429 );
		}

		ChallengeStore::purge_expired( self::PURGE_PER_CALL );

		$cookie = self::bind_cookie();
		if ( '' === $cookie ) {
			$cookie = bin2hex( random_bytes( 32 ) );
		}
		$challenge = ChallengeStore::issue( 'signin', 0, '', $cookie, '', ChallengeStore::TTL['signin'] );
		if ( $challenge instanceof WP_Error ) {
			self::fail( 'retry', 503 );
		}
		self::send_bind_cookie( $cookie, self::BIND_MAX_AGE );

		Http::ok(
			[
				'publicKey'     => Options::request( $challenge ),
				'refresh_after' => self::REFRESH_AFTER,
				'ttl'           => ChallengeStore::TTL['signin'],
			]
		);
	}

	/**
	 * magicauth_passkey_signin (6.3, 7.4): verify, then a completion token
	 * bound to this browser's cookie. Failures count toward passkey_fail_ip
	 * only after A-3 (a consumed signin challenge bound to this cookie) and
	 * never for a database error.
	 */
	public static function verify(): void {
		magicauth_jitter(); // Cryptographic input: once, before any response (6.1).
		Http::require_post();
		if ( ! Module::enabled() ) {
			self::fail( 'unavailable', 404 );
		}
		$bucket = self::ip_bucket();
		if ( Throttle::passkey_signin_blocked( $bucket ) ) {
			self::failed( 'throttled', 'throttled', 429 );
		}
		if ( ! Http::origin_ok() ) {
			self::failed( 'passkey_failed', 'origin', 400 );
		}
		$credential = Http::body_too_large() ? null : Http::field( 'credential', Verifier::MAX_CREDENTIAL );
		if ( null === $credential ) {
			self::failed( 'passkey_failed', 'malformed', 400 );
		}

		$cookie = self::bind_cookie();
		$result = Verifier::verify_assertion( $credential, $cookie );
		if ( $result instanceof WP_Error ) {
			self::verify_failed( $result, $bucket );
		}

		$user  = $result['user'];
		$row   = $result['row'];
		$token = ChallengeStore::issue( 'complete', (int) $user->ID, '', $cookie, '', ChallengeStore::TTL['complete'] );
		if ( $token instanceof WP_Error ) {
			self::failed( 'retry', 'error', 503, (int) $user->ID );
		}
		// A removal of this passkey (6.6) purges the user's completion tokens;
		// one that ran between A-9 and the issue above found none, so the
		// token is burnt here instead.
		$stored = CredentialStore::still_stored( (int) $user->ID, (int) $row->id );
		if ( true !== $stored ) {
			ChallengeStore::consume( 'complete', $token );
			if ( null === $stored ) {
				self::failed( 'retry', 'error', 503, (int) $user->ID );
			}
			self::failed( 'passkey_failed', 'removed', 400, (int) $user->ID );
		}
		// Same value, new Max-Age: the cookie outlives the completion row (5.3).
		self::send_bind_cookie( $cookie, self::BIND_MAX_AGE );

		$redirect = Login::redirect_target( $user, Login::sanitize_redirect( (string) Http::field( 'redirect_to', self::MAX_URL ) ), 'passkey' );
		do_action( 'magicauth_passkey_used', (int) $user->ID, (int) $row->id );

		Http::ok(
			[
				'complete' => Base64Url::encode( $token ),
				'redirect' => $redirect,
			]
		);
	}

	/**
	 * magicauth_passkey_complete (6.13): a top-level form POST, never fetch.
	 * Consumes the token, checks its binding, runs Login::establish() (the
	 * preflight runs again) and answers 303 to the validated target, or 303 to
	 * return_to with magicauth_passkey_error. Nothing is echoed.
	 */
	public static function complete(): void {
		magicauth_jitter(); // Secret input: once, before any response (6.1).
		Http::require_post();

		$return_to = (string) Http::field( 'return_to', self::MAX_URL );
		if ( ! Module::enabled() || ! Http::origin_ok( true ) || Http::body_too_large() ) {
			self::complete_failed( 'passkey_failed', $return_to );
			return;
		}

		// Expired, replayed, unbound or malformed token, database error: retry.
		$field = Http::field( 'token', self::TOKEN_CHARS );
		$token = null !== $field ? Base64Url::decode( $field, 32, 32 ) : null;
		$row   = null !== $token ? ChallengeStore::consume( 'complete', $token ) : null;
		if ( null === $row || ! ChallengeStore::binding_matches( (string) $row->binding_hash, ChallengeStore::binding_hash( self::bind_cookie() ) ) ) {
			self::complete_failed( 'retry', $return_to );
			return;
		}

		$user = get_userdata( (int) $row->user_id );
		if ( ! $user instanceof WP_User ) {
			self::complete_failed( 'passkey_failed', $return_to );
			return;
		}

		// The proof time is the token's issue, which came after A-9 and before
		// the still_stored() re-read: an email change after it (7.6 rule M)
		// leaves the session not fresh (3.4 step 6).
		$result = Login::establish( $user, 'passkey', ChallengeStore::created_at( $row ) );
		if ( $result instanceof WP_Error ) {
			switch ( $result->get_error_code() ) {
				case 'magicauth_cookie_failed':
					$code = 'retry';
					break;
				case 'magicauth_other_account':
					$code = 'other_account';
					break;
				case 'magicauth_reverify_required':
					$code = 'reverify_required';
					break;
				default: // Disabled, denied by a filter or spam flag since the verify.
					$code = 'passkey_failed';
			}
			self::complete_failed( $code, $return_to );
			return;
		}

		self::send_bind_cookie( '', 0 );
		self::redirect( Login::redirect_target( $user, Login::sanitize_redirect( (string) Http::field( 'redirect_to', self::MAX_URL ) ), 'passkey' ) );
	}

	/**
	 * Sign-in strings L1 to L11 and L3b (9.1), keyed by their IDs: the login
	 * config and the server messages share them. None mentions creating a
	 * passkey (decision 2, T-OFFER-4).
	 *
	 * @return array<string,string>
	 */
	public static function strings(): array {
		return [
			'L1'  => __( 'Sign in with a passkey', 'magicauth' ),
			'L2'  => __( 'Waiting for your passkey.', 'magicauth' ),
			'L3'  => __( 'Signing in with a passkey did not work. Try again, or sign in with your email.', 'magicauth' ),
			'L3b' => __( 'If you opened this page from an email app, open it in your browser and try again.', 'magicauth' ),
			'L4'  => __( 'Too many attempts from your network. Wait a few minutes, or sign in with your email.', 'magicauth' ),
			'L5'  => __( 'You are signed in to a different account. Sign out first, then try again.', 'magicauth' ),
			'L6'  => __( 'Signing in did not finish. Please try again.', 'magicauth' ),
			'L7'  => __( 'Passkeys are not available on this site right now. Sign in with your email.', 'magicauth' ),
			'L8'  => __( 'For your security, sign in with your email this time. After that you can use your passkey again.', 'magicauth' ),
			'L9'  => _x( 'or', 'divider between the email form and the passkey button', 'magicauth' ),
			'L10' => __( 'Signed in. Opening your page.', 'magicauth' ),
			'L11' => __( 'That took too long. Choose your passkey again.', 'magicauth' ),
		];
	}

	/**
	 * Verifier failure: the action, the failure count (only when the data
	 * says counted), the response. unknown_credential only when flagged.
	 *
	 * @return never
	 */
	private static function verify_failed( WP_Error $error, string $bucket ): void {
		$code = (string) $error->get_error_code();
		$data = (array) $error->get_error_data();
		if ( ! empty( $data['counted'] ) ) {
			Throttle::record_passkey_signin_failure( $bucket );
		}
		// Only the request whose UPDATE blocked the credential mails the owner (7.6, 10.5).
		if ( ! empty( $data['blocked_now'] ) ) {
			AccountEvents::send_blocked( (int) ( $data['user_id'] ?? 0 ), (int) ( $data['row_id'] ?? 0 ) );
		}
		self::failed(
			$code,
			(string) ( $data['reason'] ?? 'error' ),
			(int) ( $data['status'] ?? 400 ),
			(int) ( $data['user_id'] ?? 0 ),
			! empty( $data['unknown_credential'] )
		);
	}

	/**
	 * A failed signin response: magicauth_passkey_signin_failed( $reason,
	 * $user_id ) for integrators (D-13), then the body.
	 *
	 * @return never
	 */
	private static function failed( string $code, string $reason, int $status, int $user_id = 0, bool $unknown_credential = false ): void {
		do_action( 'magicauth_passkey_signin_failed', $reason, $user_id );
		self::fail( $code, $status, $unknown_credential );
	}

	/**
	 * Failure response with the code's sign-in message; unknown_credential
	 * only when flagged (never the key otherwise, T-AUTH 8c).
	 *
	 * @return never
	 */
	private static function fail( string $code, int $status, bool $unknown_credential = false ): void {
		Http::fail( $code, self::message( $code ), $status, $unknown_credential ? [ 'unknown_credential' => true ] : [] );
	}

	/** Server message per code (6.10); JS shows its own config string for these. */
	private static function message( string $code ): string {
		$map = [
			'passkey_failed'    => 'L3',
			'throttled'         => 'L4',
			'other_account'     => 'L5',
			'retry'             => 'L6',
			'unavailable'       => 'L7',
			'reverify_required' => 'L8',
		];
		return self::strings()[ $map[ $code ] ?? 'L3' ];
	}

	/** Completion failure: 303 to return_to (same host, else home) with the code. */
	private static function complete_failed( string $code, string $return_to ): void {
		$base = '' !== $return_to ? wp_validate_redirect( $return_to, home_url( '/' ) ) : '';
		self::redirect( add_query_arg( self::ERROR_PARAM, $code, '' !== $base ? $base : home_url( '/' ) ) );
	}

	/** 303 with no-store headers, then exit (not under MAGICAUTH_TESTING, where the stub records it). */
	private static function redirect( string $location ): void {
		Http::no_store();
		wp_safe_redirect( $location, 303 );
		if ( ! ( defined( 'MAGICAUTH_TESTING' ) && MAGICAUTH_TESTING ) ) {
			exit;
		}
	}

	/** This request's magicauth_pk_bind value when well formed, else ''. */
	private static function bind_cookie(): string {
		if ( ! isset( $_COOKIE[ self::BIND_COOKIE ] ) || ! is_string( $_COOKIE[ self::BIND_COOKIE ] ) ) {
			return '';
		}
		$raw = wp_unslash( $_COOKIE[ self::BIND_COOKIE ] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- strict hex pattern below.
		return 1 === preg_match( '/^[0-9a-f]{64}$/', $raw ) ? $raw : '';
	}

	/**
	 * Sets (or with Max-Age 0 deletes) magicauth_pk_bind: host-only, path of
	 * admin-ajax.php, HttpOnly, Secure per is_ssl(), SameSite=Strict (5.3).
	 */
	private static function send_bind_cookie( string $value, int $max_age ): void {
		$path = wp_parse_url( admin_url( 'admin-ajax.php' ), PHP_URL_PATH );

		Http::set_cookie(
			self::BIND_COOKIE,
			$value,
			[
				'expires'  => Clock::now() + $max_age,
				'path'     => is_string( $path ) && '' !== $path ? $path : '/',
				'domain'   => '', // Host-only; COOKIE_DOMAIN ignored.
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Strict',
			]
		);
	}

	/** Network bucket key of this client (/32 IPv4, /64 IPv6), HMAC'd (6.9). */
	private static function ip_bucket(): string {
		return magicauth_hash_ip( magicauth_ip_bucket( magicauth_client_ip() ) );
	}
}
