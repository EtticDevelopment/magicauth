<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Passkeys;

defined( 'ABSPATH' ) || exit;

use WP_Session_Tokens;

/**
 * Recent-authentication rule for adding a passkey (SPEC 3).
 *
 * Creation stamp: written once into core's session record through a one-shot
 * attach_session_information closure (Auth\Login::establish()); core's record
 * is never rewritten afterwards (invariant 11). Freshness also needs the
 * magicauth_pk_fresh cookie issued with that authentication, so copied
 * session cookies do not inherit it.
 *
 * Step-up stamps (state row, 5.6) are the second candidate; the newest valid
 * candidate decides.
 */
final class Freshness {

	/** Methods that prove the mailbox or an existing passkey. */
	public const FRESH_METHODS = [ 'link', 'code', 'reset', 'passkey' ];

	/** Browser binding of a fresh authentication. */
	public const COOKIE = 'magicauth_pk_fresh';

	/** Default window in seconds; filter magicauth_passkey_fresh_window. */
	public const FRESH_WINDOW = 600;

	private const WINDOW_MIN = 60;

	private const WINDOW_MAX = 3600;

	/**
	 * One-shot attach_session_information callback: stamps the first session
	 * created for $user_id and is a no-op afterwards, so a wp_login callback
	 * that issues another cookie gets an unstamped session.
	 *
	 * magicauth_auth_at is when the proof was checked ($auth_at), not when
	 * the session is written, so step 6 judges an email change against the
	 * proof (7.6 rule M).
	 *
	 * @param int     $user_id    User whose new session is stamped.
	 * @param string  $method     Sign-in method (Auth\Login::METHODS).
	 * @param ?string $fresh_hash HMAC of the fresh cookie, or null (no cookie issued).
	 * @param ?int    $auth_at    Unix time the proof was checked; null for now.
	 */
	public static function stamp_callback( int $user_id, string $method, ?string $fresh_hash, ?int $auth_at = null ): \Closure {
		$done = false;
		return static function ( $session, $uid = 0 ) use ( &$done, $user_id, $method, $fresh_hash, $auth_at ) {
			if ( $done || (int) $uid !== $user_id ) {
				return $session;
			}
			$done    = true;
			$session = is_array( $session ) ? $session : [];

			$session['magicauth_method']  = $method;
			$session['magicauth_auth_at'] = $auth_at ?? Clock::now();
			if ( null !== $fresh_hash ) {
				$session['magicauth_fresh_hash'] = $fresh_hash;
			}
			return $session;
		};
	}

	/**
	 * Core session record of the current request, or null.
	 *
	 * @return array<string,mixed>|null
	 */
	public static function session(): ?array {
		$token   = wp_get_session_token();
		$user_id = get_current_user_id();
		if ( '' === $token || $user_id <= 0 ) {
			return null;
		}
		$session = WP_Session_Tokens::get_instance( $user_id )->get( $token );
		return is_array( $session ) ? $session : null;
	}

	/** SPEC 3.4: true only when every rule holds. */
	public static function is_fresh(): bool {
		// 1. A session token and its hash.
		if ( '' === wp_get_session_token() || '' === self::session_hash() ) {
			return false;
		}

		// 2. The core record still exists.
		$session = self::session();
		if ( null === $session ) {
			return false;
		}

		// 3. Valid candidates: B, the step-up stamp in the state row; A, the
		// creation stamp. B goes first: a step-up in the second of the sign-in
		// replaced the cookie, so on a tie (stable sort) B decides.
		$candidates = [];
		$step_up    = self::step_up_candidate();
		if ( null !== $step_up ) {
			$candidates[] = $step_up;
		}
		$creation = self::creation_candidate( $session );
		if ( null !== $creation ) {
			$candidates[] = $creation;
		}
		if ( [] === $candidates ) {
			return false;
		}
		usort(
			$candidates,
			static function ( array $a, array $b ): int {
				return $b['at'] <=> $a['at'];
			}
		);
		$newest = $candidates[0];

		// 4. Within the window.
		if ( Clock::now() - $newest['at'] > self::window() ) {
			return false;
		}

		// 5. This browser holds the cookie issued with that authentication.
		$cookie = self::request_cookie();
		if ( '' === $cookie || ! hash_equals( $newest['hash'], self::fresh_hmac( $cookie ) ) ) {
			return false;
		}

		// 6. Later than the last email change: it proved the current mailbox.
		// Both stamps hold the time the proof was checked, not the write time.
		$changed_at = (int) get_user_meta( get_current_user_id(), 'magicauth_email_changed_at', true );
		return $newest['at'] > $changed_at;
	}

	/** Filtered window, clamped to [60, 3600] seconds. */
	public static function window(): int {
		$window = (int) apply_filters( 'magicauth_passkey_fresh_window', self::FRESH_WINDOW );
		return max( self::WINDOW_MIN, min( self::WINDOW_MAX, $window ) );
	}

	/** HMAC of the current session token; '' when there is none (5.2). */
	public static function session_hash(): string {
		$token = wp_get_session_token();
		if ( '' === $token ) {
			return '';
		}
		return hash_hmac( 'sha256', 'magicauth-passkey-session|' . $token, wp_salt( 'auth' ) );
	}

	/** Sets magicauth_pk_fresh to a new random value; returns its HMAC for storage. */
	public static function issue_fresh_cookie(): string {
		$fresh = self::new_fresh_value();
		self::send_fresh_cookie( $fresh['value'] );
		return $fresh['hash'];
	}

	/**
	 * A new magicauth_pk_fresh value and its HMAC, nothing sent: callers that
	 * store the HMAC first send the cookie only once it is stored.
	 *
	 * @return array{value:string,hash:string}
	 */
	public static function new_fresh_value(): array {
		$value = bin2hex( random_bytes( 32 ) );
		return [
			'value' => $value,
			'hash'  => self::fresh_hmac( $value ),
		];
	}

	/**
	 * Sets magicauth_pk_fresh.
	 *
	 * @param string $value From new_fresh_value().
	 */
	public static function send_fresh_cookie( string $value ): void {
		$path = wp_parse_url( admin_url( 'admin-ajax.php' ), PHP_URL_PATH );

		Http::set_cookie(
			self::COOKIE,
			$value,
			[
				'expires'  => Clock::now() + self::window(),
				'path'     => is_string( $path ) && '' !== $path ? $path : '/',
				'domain'   => '', // Host-only; COOKIE_DOMAIN ignored.
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Strict',
			]
		);
	}

	/**
	 * Fresh methods after the filter; the filter can only remove.
	 *
	 * @return array<int,string>
	 */
	private static function methods(): array {
		$filtered = apply_filters( 'magicauth_passkey_fresh_methods', self::FRESH_METHODS );
		if ( ! is_array( $filtered ) ) {
			return [];
		}
		return array_values( array_intersect( self::FRESH_METHODS, $filtered ) );
	}

	/**
	 * Creation stamp as a candidate, or null when it cannot count.
	 *
	 * @param array<string,mixed> $session
	 * @return array{at:int,hash:string}|null
	 */
	private static function creation_candidate( array $session ): ?array {
		$method = $session['magicauth_method'] ?? null;
		$at     = $session['magicauth_auth_at'] ?? null;
		$hash   = $session['magicauth_fresh_hash'] ?? null;

		if ( ! is_string( $method ) || ! in_array( $method, self::methods(), true ) ) {
			return null;
		}
		if ( ! is_int( $at ) ) {
			return null;
		}
		if ( ! is_string( $hash ) || 1 !== preg_match( '/^[0-9a-f]{64}$/', $hash ) ) {
			return null;
		}
		return [
			'at'   => $at,
			'hash' => $hash,
		];
	}

	/**
	 * Step-up stamp (5.6) as a candidate, or null. SessionState::get() reads
	 * the row only while the core record exists.
	 *
	 * @return array{at:int,hash:string}|null
	 */
	private static function step_up_candidate(): ?array {
		$row = SessionState::get();
		if ( null === $row ) {
			return null;
		}
		$at   = (int) ( $row->reauth_at ?? 0 );
		$hash = (string) ( $row->fresh_hash ?? '' );
		if ( $at <= 0 || 1 !== preg_match( '/^[0-9a-f]{64}$/', $hash ) ) {
			return null;
		}
		return [
			'at'   => $at,
			'hash' => $hash,
		];
	}

	/** The request's magicauth_pk_fresh value when well formed, else ''. */
	private static function request_cookie(): string {
		if ( ! isset( $_COOKIE[ self::COOKIE ] ) || ! is_string( $_COOKIE[ self::COOKIE ] ) ) {
			return '';
		}
		$raw = wp_unslash( $_COOKIE[ self::COOKIE ] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- strict hex pattern below.
		return 1 === preg_match( '/^[0-9a-f]{64}$/', $raw ) ? $raw : '';
	}

	private static function fresh_hmac( string $value ): string {
		return hash_hmac( 'sha256', 'magicauth-passkey-fresh|' . $value, wp_salt( 'auth' ) );
	}
}
