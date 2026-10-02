<?php
/**
 * Normalised form of rendered HTML and plain text for golden comparisons
 * (SPEC 14.1, build step 1).
 *
 * HTML is parsed into a DOM and serialised one node per line, indented by
 * depth, with attributes sorted by name. Per-request values become
 * placeholders: nonce values ({{nonce}}), `ver=` query values ({{ver}}),
 * magicauth_sid values ({{sid}}) and the magicauth_ts hygiene timestamp
 * ({{ts}}). Whitespace runs in text collapse to one space and
 * whitespace-only text nodes are dropped, so indentation and the blank
 * output of a skipped PHP conditional do not count as a change; text inside
 * pre, textarea, script and style is kept as is (line endings normalised).
 *
 * Test support only; never shipped.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Support;

final class Normalise {

	private const VOID = [ 'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr' ];

	private const RAW_TEXT = [ 'pre', 'textarea', 'script', 'style' ];

	private const NONCE_FIELDS = [ 'magicauth_nonce', '_wpnonce', '_ajax_nonce' ];

	public static function html( string $html ): string {
		$html     = str_replace( [ "\r\n", "\r" ], "\n", $html );
		$document = 1 === preg_match( '/<html[\s>]/i', $html );
		$source   = $document ? $html : '<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>' . $html . '</body></html>';
		// Non-ASCII as numeric entities: libxml's HTML parser then needs no charset hint.
		$source = mb_encode_numericentity( $source, [ 0x80, 0x10FFFF, 0, 0x1FFFFF ], 'UTF-8' );

		$dom      = new \DOMDocument();
		$previous = libxml_use_internal_errors( true );
		$dom->loadHTML( $source, LIBXML_NONET | LIBXML_COMPACT );
		libxml_clear_errors();
		libxml_use_internal_errors( $previous );

		$lines = [];
		if ( $document ) {
			if ( null !== $dom->doctype ) {
				$lines[] = '<!DOCTYPE ' . $dom->doctype->name . '>';
			}
			foreach ( $dom->childNodes as $child ) {
				if ( $child instanceof \DOMElement ) {
					self::walk( $child, 0, $lines );
				}
			}
		} else {
			$body = $dom->getElementsByTagName( 'body' )->item( 0 );
			if ( null !== $body ) {
				foreach ( $body->childNodes as $child ) {
					self::walk( $child, 0, $lines );
				}
			}
		}
		return implode( "\n", $lines ) . "\n";
	}

	/** Plain text: line endings, trailing spaces per line, placeholders; trailing blank lines trimmed. */
	public static function text( string $text ): string {
		$text  = str_replace( [ "\r\n", "\r" ], "\n", $text );
		$lines = array_map( 'rtrim', explode( "\n", self::placeholders( $text ) ) );
		return rtrim( implode( "\n", $lines ) ) . "\n";
	}

	/** URL and JSON per-request values to placeholders. */
	public static function placeholders( string $value ): string {
		$value = (string) preg_replace( '/([?&](?:amp;|#038;)?)ver=[^&#"\'\s]*/', '$1ver={{ver}}', $value );
		$value = (string) preg_replace( '/([?&](?:amp;|#038;)?)_wpnonce=[^&#"\'\s]*/', '$1_wpnonce={{nonce}}', $value );
		$value = (string) preg_replace( '/([?&](?:amp;|#038;)?)magicauth_sid=[^&#"\'\s]*/', '$1magicauth_sid={{sid}}', $value );
		return (string) preg_replace( '/("[A-Za-z_]*nonce"\s*:\s*)"[^"]*"/i', '$1"{{nonce}}"', $value );
	}

	/** @param array<int,string> $lines */
	private static function walk( \DOMNode $node, int $depth, array &$lines ): void {
		$pad = str_repeat( '  ', $depth );

		if ( $node instanceof \DOMText ) {
			$text = (string) preg_replace( '/\s+/u', ' ', $node->data );
			if ( '' !== trim( $text ) ) {
				$lines[] = $pad . json_encode( self::placeholders( $text ), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode
			}
			return;
		}
		if ( $node instanceof \DOMComment ) {
			$lines[] = $pad . '<!--' . trim( (string) preg_replace( '/\s+/u', ' ', $node->data ) ) . '-->';
			return;
		}
		if ( ! $node instanceof \DOMElement ) {
			return;
		}

		$tag   = strtolower( $node->tagName );
		$attrs = [];
		foreach ( $node->attributes as $attr ) {
			$attrs[ strtolower( $attr->name ) ] = (string) $attr->value;
		}
		ksort( $attrs, SORT_STRING );

		$field = $attrs['name'] ?? '';
		$parts = [];
		foreach ( $attrs as $name => $value ) {
			if ( 'value' === $name && ( in_array( $field, self::NONCE_FIELDS, true ) || '' !== $field && 'nonce' === substr( $field, -5 ) ) ) {
				$value = '{{nonce}}';
			} elseif ( 'value' === $name && 'magicauth_sid' === $field ) {
				$value = '{{sid}}';
			} elseif ( 'value' === $name && 'magicauth_ts' === $field ) {
				$value = '{{ts}}';
			} elseif ( 0 === strpos( $name, 'data-' ) && false !== strpos( $name, 'nonce' ) ) {
				$value = '{{nonce}}';
			} else {
				$value = self::placeholders( $value );
			}
			$parts[] = $name . '="' . htmlspecialchars( $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8' ) . '"';
		}
		$open = '<' . $tag . ( [] !== $parts ? ' ' . implode( ' ', $parts ) : '' );

		if ( in_array( $tag, self::VOID, true ) ) {
			$lines[] = $pad . $open . ' />';
			return;
		}
		$lines[] = $pad . $open . '>';

		if ( in_array( $tag, self::RAW_TEXT, true ) ) {
			$raw = trim( self::placeholders( str_replace( [ "\r\n", "\r" ], "\n", (string) $node->textContent ) ) );
			if ( '' !== $raw ) {
				foreach ( explode( "\n", $raw ) as $line ) {
					$lines[] = $pad . '  ' . rtrim( $line );
				}
			}
		} else {
			foreach ( $node->childNodes as $child ) {
				self::walk( $child, $depth + 1, $lines );
			}
		}
		$lines[] = $pad . '</' . $tag . '>';
	}
}
