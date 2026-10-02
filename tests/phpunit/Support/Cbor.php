<?php
/**
 * Minimal CTAP2-canonical CBOR encoder for building WebAuthn test inputs,
 * plus a small decoder for inspecting what the encoder or a fixture holds.
 * Test support only; never shipped.
 *
 * Encoding: PHP int -> unsigned or negative int; Bytes -> byte string; PHP
 * string -> text string; list -> array; other PHP array or CborMap -> map;
 * bool -> simple value; null -> null; Raw -> its bytes verbatim. Map keys are
 * sorted CTAP2-canonically: by major type, then encoded length, then bytes.
 * Bytes, Raw and CborMap live in this file: create them through Cbor::bytes(),
 * Cbor::raw() and Cbor::map() so the autoloader has loaded it.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Support;

/** Byte string marker (a bare PHP string encodes as a text string). */
final class Bytes {

	public string $data;

	public function __construct( string $data ) {
		$this->data = $data;
	}
}

/** Pre-encoded CBOR, emitted verbatim. */
final class Raw {

	public string $bytes;

	public function __construct( string $bytes ) {
		$this->bytes = $bytes;
	}
}

/** Forces map encoding for an array whose keys happen to form a list. */
final class CborMap {

	/** @var array<int|string,mixed> */
	public array $entries;

	/** @param array<int|string,mixed> $entries */
	public function __construct( array $entries ) {
		$this->entries = $entries;
	}
}

final class Cbor {

	/** @param mixed $value */
	public static function encode( $value ): string {
		if ( $value instanceof Raw ) {
			return $value->bytes;
		}
		if ( $value instanceof Bytes ) {
			return self::head( 2, strlen( $value->data ) ) . $value->data;
		}
		if ( $value instanceof CborMap ) {
			return self::encode_map( $value->entries );
		}
		if ( is_int( $value ) ) {
			return $value >= 0 ? self::head( 0, $value ) : self::head( 1, -1 - $value );
		}
		if ( is_string( $value ) ) {
			return self::head( 3, strlen( $value ) ) . $value;
		}
		if ( is_bool( $value ) ) {
			return $value ? "\xf5" : "\xf4";
		}
		if ( null === $value ) {
			return "\xf6";
		}
		if ( is_array( $value ) ) {
			if ( self::is_list( $value ) ) {
				$out = self::head( 4, count( $value ) );
				foreach ( $value as $item ) {
					$out .= self::encode( $item );
				}
				return $out;
			}
			return self::encode_map( $value );
		}
		throw new \InvalidArgumentException( 'Cbor::encode: unsupported type ' . gettype( $value ) );
	}

	public static function raw( string $bytes ): Raw {
		return new Raw( $bytes );
	}

	public static function bytes( string $data ): Bytes {
		return new Bytes( $data );
	}

	public static function map( array $entries ): CborMap {
		return new CborMap( $entries );
	}

	/** $depth nested one-element arrays around an empty array: [[[...[]...]]]. */
	public static function nested_array( int $depth ): string {
		return str_repeat( "\x81", $depth ) . "\x80";
	}

	/** A two-entry map whose keys are equal (not canonical, not valid CTAP2). */
	public static function map_with_duplicate_key( $key = 1, $first = 2, $second = 2 ): string {
		return "\xa2" . self::encode( $key ) . self::encode( $first ) . self::encode( $key ) . self::encode( $second );
	}

	/**
	 * Decode one definite-length item. Byte strings come back as Bytes, maps as
	 * PHP arrays (int or string keys), arrays as lists. Throws on trailing bytes,
	 * indefinite lengths, tags and floats.
	 *
	 * @return mixed
	 */
	public static function decode( string $bytes ) {
		$offset = 0;
		$value  = self::decode_item( $bytes, $offset );
		if ( $offset !== strlen( $bytes ) ) {
			throw new \UnexpectedValueException( 'Cbor::decode: trailing bytes' );
		}
		return $value;
	}

	/**
	 * Decode one item at $offset and advance it (for authData, where the COSE key is followed by more data).
	 *
	 * @return mixed
	 */
	public static function decode_item( string $bytes, int &$offset ) {
		if ( $offset >= strlen( $bytes ) ) {
			throw new \UnexpectedValueException( 'Cbor::decode: truncated' );
		}
		$initial = ord( $bytes[ $offset ] );
		++$offset;
		$major = $initial >> 5;
		$info  = $initial & 0x1f;

		if ( 7 === $major ) {
			switch ( $info ) {
				case 20:
					return false;
				case 21:
					return true;
				case 22:
					return null;
				default:
					throw new \UnexpectedValueException( 'Cbor::decode: unsupported simple value or float' );
			}
		}

		$length = self::read_length( $bytes, $offset, $info );

		switch ( $major ) {
			case 0:
				return $length;
			case 1:
				return -1 - $length;
			case 2:
			case 3:
				if ( $offset + $length > strlen( $bytes ) ) {
					throw new \UnexpectedValueException( 'Cbor::decode: truncated string' );
				}
				$data    = substr( $bytes, $offset, $length );
				$offset += $length;
				return 2 === $major ? new Bytes( $data ) : $data;
			case 4:
				$out = [];
				for ( $i = 0; $i < $length; $i++ ) {
					$out[] = self::decode_item( $bytes, $offset );
				}
				return $out;
			case 5:
				$out = [];
				for ( $i = 0; $i < $length; $i++ ) {
					$key = self::decode_item( $bytes, $offset );
					if ( ! is_int( $key ) && ! is_string( $key ) ) {
						throw new \UnexpectedValueException( 'Cbor::decode: unsupported map key type' );
					}
					$out[ $key ] = self::decode_item( $bytes, $offset );
				}
				return $out;
			default:
				throw new \UnexpectedValueException( 'Cbor::decode: tags are not supported' );
		}
	}

	private static function read_length( string $bytes, int &$offset, int $info ): int {
		if ( $info < 24 ) {
			return $info;
		}
		$sizes = [
			24 => 1,
			25 => 2,
			26 => 4,
			27 => 8,
		];
		if ( ! isset( $sizes[ $info ] ) ) {
			throw new \UnexpectedValueException( 'Cbor::decode: indefinite or reserved length' );
		}
		$size = $sizes[ $info ];
		if ( $offset + $size > strlen( $bytes ) ) {
			throw new \UnexpectedValueException( 'Cbor::decode: truncated length' );
		}
		$value = 0;
		for ( $i = 0; $i < $size; $i++ ) {
			$value = ( $value << 8 ) | ord( $bytes[ $offset + $i ] );
		}
		$offset += $size;
		if ( $value < 0 ) {
			throw new \UnexpectedValueException( 'Cbor::decode: length exceeds PHP_INT_MAX' );
		}
		return $value;
	}

	private static function head( int $major, int $value ): string {
		$type = $major << 5;
		if ( $value < 24 ) {
			return chr( $type | $value );
		}
		if ( $value <= 0xff ) {
			return chr( $type | 24 ) . chr( $value );
		}
		if ( $value <= 0xffff ) {
			return chr( $type | 25 ) . pack( 'n', $value );
		}
		if ( $value <= 0xffffffff ) {
			return chr( $type | 26 ) . pack( 'N', $value );
		}
		return chr( $type | 27 ) . pack( 'J', $value );
	}

	/**
	 * array_is_list() is PHP 8.1+; the plugin floor is 8.0.
	 *
	 * @param array<mixed> $value
	 */
	private static function is_list( array $value ): bool {
		$i = 0;
		foreach ( array_keys( $value ) as $key ) {
			if ( $key !== $i ) {
				return false;
			}
			++$i;
		}
		return true;
	}

	/** @param array<int|string,mixed> $entries */
	private static function encode_map( array $entries ): string {
		$pairs = [];
		foreach ( $entries as $key => $value ) {
			$pairs[] = [ self::encode( $key ), self::encode( $value ) ];
		}
		usort(
			$pairs,
			static function ( array $a, array $b ): int {
				$major = ( ord( $a[0][0] ) >> 5 ) <=> ( ord( $b[0][0] ) >> 5 );
				if ( 0 !== $major ) {
					return $major;
				}
				$length = strlen( $a[0] ) <=> strlen( $b[0] );
				return 0 !== $length ? $length : strcmp( $a[0], $b[0] );
			}
		);
		$out = self::head( 5, count( $pairs ) );
		foreach ( $pairs as $pair ) {
			$out .= $pair[0] . $pair[1];
		}
		return $out;
	}
}
