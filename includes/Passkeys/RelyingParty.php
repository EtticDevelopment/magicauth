<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Passkeys;

defined( 'ABSPATH' ) || exit;

use WP_Error;

/**
 * Relying Party ID and the single allowed origin (SPEC 7.1, D-5), and the
 * request Origin gate of the passkey endpoints (6.1).
 *
 * RP ID: the lower-cased host of home_url(). The only override is the
 * wp-config constant MAGICAUTH_PASSKEY_RP_ID (a valid suffix of the host, two
 * labels or more); there is no filter, so a theme or plugin cannot widen it.
 * Origin: exactly normalise_origin( home_url() ); there is no origins filter.
 * Nothing is cached, so values read before init are never kept (4.1).
 */
final class RelyingParty {

	private const DEFAULT_PORTS = [
		'http'  => 80,
		'https' => 443,
	];

	/** RP ID, or '' when misconfigured (config_error() says why). */
	public static function id(): string {
		$host = self::host();
		if ( '' === $host ) {
			return '';
		}
		$constant = self::constant_value();
		if ( null === $constant ) {
			return self::is_valid_rp_id( $host, $host ) ? $host : '';
		}
		if ( substr_count( $constant, '.' ) < 1 || ! self::is_valid_rp_id( $constant, $host ) ) {
			return '';
		}
		return $constant;
	}

	/** Why id() is '' (S8g), or null when it is usable. */
	public static function config_error(): ?WP_Error {
		if ( '' !== self::id() ) {
			return null;
		}
		return new WP_Error( 'magicauth_pk_rp_id_invalid', __( 'MAGICAUTH_PASSKEY_RP_ID is not a valid suffix of the site host.', 'magicauth' ) );
	}

	/** Lower-cased host of home_url(); '' when it has none. */
	public static function host(): string {
		$host = wp_parse_url( home_url(), PHP_URL_HOST );
		return is_string( $host ) ? strtolower( $host ) : '';
	}

	/** The single allowed origin, normalised; '' when home_url() has none. */
	public static function origin(): string {
		return self::normalise_origin( home_url() ) ?? '';
	}

	/**
	 * Exact string compare against origin() (W3: clientData origin).
	 *
	 * @param string $origin Origin as the browser serialised it.
	 */
	public static function origin_allowed( string $origin ): bool {
		$allowed = self::origin();
		return '' !== $allowed && $origin === $allowed;
	}

	/**
	 * scheme://host[:port], lower-case, default port dropped; null when $url
	 * has no http(s) scheme or host, carries userinfo, or is not parsable
	 * (the literal 'null' included).
	 *
	 * @param string $url URL or origin.
	 */
	public static function normalise_origin( string $url ): ?string {
		if ( '' === $url || 1 === preg_match( '/[\x00-\x20\x7f]/', $url ) ) {
			return null;
		}
		$parts = wp_parse_url( $url );
		if ( ! is_array( $parts ) || ! isset( $parts['scheme'], $parts['host'] ) ) {
			return null;
		}
		if ( isset( $parts['user'] ) || isset( $parts['pass'] ) ) {
			return null;
		}
		$scheme = strtolower( (string) $parts['scheme'] );
		$host   = strtolower( (string) $parts['host'] );
		if ( ! isset( self::DEFAULT_PORTS[ $scheme ] ) || '' === $host ) {
			return null;
		}
		$origin = $scheme . '://' . $host;
		if ( isset( $parts['port'] ) ) {
			$port = (int) $parts['port'];
			if ( $port < 1 || $port > 65535 ) {
				return null;
			}
			if ( self::DEFAULT_PORTS[ $scheme ] !== $port ) {
				$origin .= ':' . $port;
			}
		}
		return $origin;
	}

	/**
	 * Origin gate (6.1). A present Origin must normalise and equal origin();
	 * a present Origin that does not (the literal 'null' included) is
	 * rejected without a Referer fallback. Only without Origin, the Referer's
	 * origin must equal it; neither present: rejected. With $navigation
	 * (magicauth_passkey_complete, 6.13) 'Origin: null' passes only with
	 * Sec-Fetch-Site exactly same-origin and Sec-Fetch-Mode exactly navigate.
	 *
	 * @param array<string,mixed> $server     $_SERVER (slashed by core; unslashed here).
	 * @param bool                $navigation Top-level form POST navigation.
	 */
	public static function request_origin_ok( array $server, bool $navigation = false ): bool {
		$allowed = self::origin();
		if ( '' === $allowed ) {
			return false;
		}

		if ( array_key_exists( 'HTTP_ORIGIN', $server ) ) {
			$origin = self::header( $server, 'HTTP_ORIGIN' );
			if ( null === $origin ) {
				return false;
			}
			if ( 'null' === $origin ) {
				return $navigation
					&& 'same-origin' === self::header( $server, 'HTTP_SEC_FETCH_SITE' )
					&& 'navigate' === self::header( $server, 'HTTP_SEC_FETCH_MODE' );
			}
			return self::normalise_origin( $origin ) === $allowed;
		}

		$referer = self::header( $server, 'HTTP_REFERER' );
		if ( null === $referer ) {
			return false;
		}
		return self::normalise_origin( $referer ) === $allowed;
	}

	/**
	 * Valid RP ID for $host (7.1): lower-case A-labels, no leading, trailing
	 * or double dot, not an IP, a dot unless exactly localhost, equal to the
	 * host or a dot-bounded suffix of it.
	 *
	 * @param string $rp_id Candidate RP ID.
	 * @param string $host  Lower-cased host of home_url().
	 */
	public static function is_valid_rp_id( string $rp_id, string $host ): bool {
		if ( '' === $rp_id || strlen( $rp_id ) > 253 || 1 !== preg_match( '/^[a-z0-9.-]+$/', $rp_id ) ) {
			return false;
		}
		if ( '.' === $rp_id[0] || '.' === substr( $rp_id, -1 ) || false !== strpos( $rp_id, '..' ) ) {
			return false;
		}
		if ( false !== filter_var( $rp_id, FILTER_VALIDATE_IP ) || false !== strpos( $host, '[' ) ) {
			return false;
		}
		if ( false === strpos( $rp_id, '.' ) && 'localhost' !== $rp_id ) {
			return false;
		}
		if ( $rp_id === $host ) {
			return true;
		}
		$suffix = '.' . $rp_id;
		return strlen( $host ) > strlen( $suffix ) && substr( $host, -strlen( $suffix ) ) === $suffix;
	}

	/** Lower-cased MAGICAUTH_PASSKEY_RP_ID, or null when not defined. */
	private static function constant_value(): ?string {
		if ( ! defined( 'MAGICAUTH_PASSKEY_RP_ID' ) ) {
			return null;
		}
		$value = constant( 'MAGICAUTH_PASSKEY_RP_ID' );
		return is_string( $value ) ? strtolower( $value ) : '';
	}

	/**
	 * One unslashed header value, or null when absent or not a string.
	 *
	 * @param array<string,mixed> $server $_SERVER.
	 * @param string              $key    Header key, e.g. HTTP_ORIGIN.
	 */
	private static function header( array $server, string $key ): ?string {
		if ( ! isset( $server[ $key ] ) || ! is_string( $server[ $key ] ) ) {
			return null;
		}
		return (string) wp_unslash( $server[ $key ] );
	}
}
