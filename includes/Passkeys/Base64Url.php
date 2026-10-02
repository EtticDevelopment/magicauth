<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Passkeys;

defined( 'ABSPATH' ) || exit;

/**
 * Strict canonical base64url without padding (SPEC 8.2). One encoding of any
 * byte string is accepted: no padding, no '+' or '/', no non-zero trailing bits.
 */
final class Base64Url {

	public static function encode( string $raw ): string {
		return rtrim( strtr( base64_encode( $raw ), '+/', '-_' ), '=' );
	}

	/**
	 * Raw bytes, or null when $s is not the canonical encoding of $min to $max bytes.
	 *
	 * @param string $s   Candidate text.
	 * @param int    $min Minimum decoded length in bytes.
	 * @param int    $max Maximum decoded length in bytes.
	 */
	public static function decode( string $s, int $min, int $max ): ?string {
		if ( 1 !== preg_match( '/^[A-Za-z0-9_-]*$/', $s ) ) {
			return null;
		}
		if ( 1 === strlen( $s ) % 4 ) {
			return null;
		}
		$raw = base64_decode( strtr( $s, '-_', '+/' ), true );
		if ( false === $raw ) {
			return null;
		}
		// Canonical: rejects non-zero trailing bits.
		if ( self::encode( $raw ) !== $s ) {
			return null;
		}
		$len = strlen( $raw );
		if ( $len < $min || $len > $max ) {
			return null;
		}
		return $raw;
	}
}
