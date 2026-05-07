<?php
/**
 * Crockford base-32: alphabet 0123456789ABCDEFGHJKMNPQRSTVWXYZ (no I, L, O, U).
 *
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Auth;

defined( 'ABSPATH' ) || exit;

/**
 * Crockford base-32 helpers. We never decode back to bytes — verification
 * HMACs the normalized plaintext, so a one-way alphabet is fine.
 */
final class Crockford {

	private const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

	/**
	 * Encode raw bytes into Crockford base-32, truncating to $length chars.
	 *
	 * MSB-first bit-buffer, 5 bits at a time (RFC4648 ordering, Crockford alphabet).
	 */
	public static function encode_bytes( string $bytes, int $length ): string {
		if ( $length <= 0 ) {
			return '';
		}

		$max_chars = (int) ceil( ( strlen( $bytes ) * 8 ) / 5 );
		if ( $length > $max_chars ) {
			throw new \InvalidArgumentException( 'Crockford::encode_bytes: requested length exceeds available entropy.' );
		}

		$buffer = 0;
		$bits   = 0;
		$out    = '';
		$len    = strlen( $bytes );

		for ( $i = 0; $i < $len && strlen( $out ) < $length; $i++ ) {
			$buffer = ( $buffer << 8 ) | ( ord( $bytes[ $i ] ) & 0xFF );
			$bits  += 8;

			while ( $bits >= 5 && strlen( $out ) < $length ) {
				$bits   -= 5;
				$index   = ( $buffer >> $bits ) & 0x1F;
				$out    .= self::ALPHABET[ $index ];
			}
		}

		if ( strlen( $out ) < $length && $bits > 0 ) {
			$index = ( $buffer << ( 5 - $bits ) ) & 0x1F;
			$out  .= self::ALPHABET[ $index ];
		}

		return $out;
	}

	/**
	 * Uppercase, strip dashes/spaces, fold lookalikes (O→0, I/L→1, U→V).
	 * Runs before HMAC compare so typos against the alphabet don't punish users.
	 */
	public static function normalize( string $input ): string {
		$input = strtoupper( $input );
		$input = preg_replace( '/[\s\-]+/', '', $input ) ?? '';
		$input = strtr(
			$input,
			[
				'O' => '0',
				'I' => '1',
				'L' => '1',
				'U' => 'V',
			]
		);

		// Strip anything off-alphabet rather than throw — callers length-check.
		return preg_replace( '/[^0-9A-HJKMNPQRSTVWXYZ]/', '', $input ) ?? '';
	}

	/** Charset/length pre-check before any DB work. */
	public static function looks_valid( string $candidate ): bool {
		$normalized = self::normalize( $candidate );
		return 6 === strlen( $normalized );
	}

	/** Insert hyphen at position 3 ("XXX-XXX") for display. */
	public static function format_for_display( string $code ): string {
		if ( 6 !== strlen( $code ) ) {
			return $code;
		}
		return substr( $code, 0, 3 ) . '-' . substr( $code, 3, 3 );
	}
}
