<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Passkeys;

defined( 'ABSPATH' ) || exit;

use WP_User;

/**
 * Passkey endpoint preamble and responses (SPEC 6.1): POST only, the Origin
 * gate, body and field caps, no-store JSON in WordPress's envelope, the
 * signed-in session check, the cookie and header seams, and the
 * suppress-errors wrapper for expected-to-fail writes.
 *
 * Every endpoint is an admin-ajax action; fail() and ok() end the request
 * (wp_send_json dies), so nothing after them runs.
 */
final class Http {

	/** Request body cap in bytes (CONTENT_LENGTH). */
	public const MAX_BODY = 65536;

	/** Cache headers on every response, after nocache_headers(). */
	private const NO_STORE = [
		'Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private',
		'Pragma: no-cache',
		'X-Content-Type-Options: nosniff',
	];

	/** GET and every other method: 405, so no cache layer sees a cacheable request. */
	public static function require_post(): void {
		// Methods are case-sensitive: only the exact token POST passes.
		$method = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] )
			? (string) wp_unslash( $_SERVER['REQUEST_METHOD'] ) // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- compared to a literal only.
			: '';
		if ( 'POST' !== $method ) {
			self::send_header( 'Allow: POST' );
			self::fail( 'bad_request', self::message( 'bad_request' ), 405 );
		}
	}

	/**
	 * RelyingParty::request_origin_ok() on this request.
	 *
	 * @param bool $navigation Top-level form POST (magicauth_passkey_complete, 6.13).
	 */
	public static function origin_ok( bool $navigation = false ): bool {
		return RelyingParty::request_origin_ok( $_SERVER, $navigation );
	}

	/**
	 * CONTENT_LENGTH above MAX_BODY, or not a number. Without the header
	 * (chunked bodies) the field caps still apply.
	 */
	public static function body_too_large(): bool {
		if ( ! isset( $_SERVER['CONTENT_LENGTH'] ) ) {
			return false;
		}
		$length = $_SERVER['CONTENT_LENGTH']; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- digits only, checked below.
		if ( ! is_string( $length ) && ! is_int( $length ) ) {
			return true;
		}
		$length = (string) $length;
		return 1 !== preg_match( '/^[0-9]{1,18}$/', $length ) || (int) $length > self::MAX_BODY;
	}

	/**
	 * One POST field, unslashed (core slashes $_POST); null when absent, not a
	 * string, or longer than $max_len bytes.
	 *
	 * @param string $name    Field name.
	 * @param int    $max_len Byte cap.
	 */
	public static function field( string $name, int $max_len ): ?string {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- callers gate on nonce or binding cookie first.
		if ( ! isset( $_POST[ $name ] ) || ! is_string( $_POST[ $name ] ) ) {
			return null;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- raw by design: credential JSON and tokens are validated strictly by the caller.
		$value = (string) wp_unslash( $_POST[ $name ] );
		return strlen( $value ) > $max_len ? null : $value;
	}

	/**
	 * Success: no-store headers, then { success: true, data }.
	 *
	 * @param array<string,mixed> $data   Response data.
	 * @param int                 $status HTTP status.
	 */
	public static function ok( array $data, int $status = 200 ): void {
		self::no_store();
		wp_send_json_success( $data, $status );
	}

	/**
	 * Failure: no-store headers, then { success: false, data: { code,
	 * message, ...extra } }. $extra never replaces code or message.
	 *
	 * @param string              $code    Error code (6.10).
	 * @param string              $message Translated fallback message.
	 * @param int                 $status  HTTP status.
	 * @param array<string,mixed> $extra   Extra data members.
	 * @return never
	 */
	public static function fail( string $code, string $message, int $status, array $extra = [] ): void {
		self::no_store();
		wp_send_json_error(
			[
				'code'    => $code,
				'message' => $message,
			] + $extra,
			$status
		);
	}

	/**
	 * Signed-in endpoint gate (6.4 order): logged in, else 403 not_logged_in;
	 * the nonce, else 403 bad_nonce; the Origin, else 403 bad_origin.
	 *
	 * @param string $nonce_action Nonce action (6.11).
	 */
	public static function require_session( string $nonce_action ): WP_User {
		if ( ! is_user_logged_in() ) {
			self::fail( 'not_logged_in', self::message( 'not_logged_in' ), 403 );
		}
		if ( false === check_ajax_referer( $nonce_action, '_ajax_nonce', false ) ) {
			self::fail( 'bad_nonce', self::message( 'bad_nonce' ), 403 );
		}
		if ( ! self::origin_ok() ) {
			self::fail( 'bad_origin', self::message( 'bad_origin' ), 403 );
		}
		return wp_get_current_user();
	}

	/**
	 * Runs an expected-to-fail write with wpdb errors suppressed (a printed
	 * SQL error would land before the JSON under WP_DEBUG_DISPLAY), restores
	 * the previous state and logs a failure under $context. The error text is
	 * not logged: MySQL quotes the offending values in it.
	 *
	 * @template T
	 * @param callable():T $query   The write.
	 * @param string       $context Log label.
	 * @return T
	 */
	public static function quietly( callable $query, string $context ) {
		global $wpdb;
		$prev = $wpdb->suppress_errors( true );
		try {
			$result = $query();
			if ( '' !== $wpdb->last_error ) {
				magicauth_debug_log( $context . ': query failed' );
			}
			return $result;
		} finally {
			$wpdb->suppress_errors( $prev );
		}
	}

	/**
	 * Cookie seam (14.1): setcookie() unless headers are sent; under
	 * MAGICAUTH_TESTING the cookie is recorded in
	 * $magicauth_test_state['cookies'] with name, value, max_age and every
	 * option instead.
	 *
	 * @param string                                                                                 $name    Cookie name.
	 * @param string                                                                                 $value   Cookie value.
	 * @param array{expires:int,path:string,domain:string,secure:bool,httponly:bool,samesite:string} $options setcookie() options.
	 */
	public static function set_cookie( string $name, string $value, array $options ): void {
		if ( defined( 'MAGICAUTH_TESTING' ) && MAGICAUTH_TESTING ) {
			global $magicauth_test_state;
			if ( isset( $magicauth_test_state ) && is_array( $magicauth_test_state ) ) {
				$magicauth_test_state['cookies'][] = [
					'name'    => $name,
					'value'   => $value,
					'max_age' => $options['expires'] - Clock::now(),
				] + $options;
			}
			return;
		}
		if ( headers_sent() ) {
			magicauth_debug_log( 'cookie not sent, headers already sent: ' . $name );
			return;
		}
		setcookie( $name, $value, $options );
	}

	/** nocache_headers() plus the stricter set (6.1); also on the completion redirect (6.13). */
	public static function no_store(): void {
		nocache_headers();
		foreach ( self::NO_STORE as $line ) {
			self::send_header( $line );
		}
	}

	/** Header seam: recorded in $magicauth_test_state['headers'] under MAGICAUTH_TESTING. */
	private static function send_header( string $line ): void {
		if ( defined( 'MAGICAUTH_TESTING' ) && MAGICAUTH_TESTING ) {
			global $magicauth_test_state;
			if ( isset( $magicauth_test_state ) && is_array( $magicauth_test_state ) ) {
				$magicauth_test_state['headers'][] = $line;
			}
			return;
		}
		if ( ! headers_sent() ) {
			header( $line );
		}
	}

	/**
	 * Fallback messages of the preamble codes; JS shows its own strings for
	 * known codes (6.10).
	 */
	private static function message( string $code ): string {
		if ( 'bad_request' === $code ) {
			return __( 'Passkeys are not available on this site right now. Sign in with your email.', 'magicauth' );
		}
		return __( 'Your session has ended. Sign in again.', 'magicauth' );
	}
}
