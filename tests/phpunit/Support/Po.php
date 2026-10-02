<?php
/**
 * Minimal gettext .po/.pot reader for the i18n tests (SPEC 9, build step
 * 15): msgctxt, msgid, msgid_plural, msgstr and msgstr[n] with continuation
 * lines, reference files, flags and extracted comments. Obsolete entries
 * (#~) and the header entry are skipped. Test support only.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Support;

final class Po {

	/**
	 * Entries of a .po or .pot file.
	 *
	 * @return array<int,array{ctx:?string,id:string,plural:?string,str:array<int,string>,refs:array<int,string>,flags:array<int,string>,extracted:string}>
	 */
	public static function entries( string $file ): array {
		$text    = (string) file_get_contents( $file );
		$blocks  = preg_split( '/\n\s*\n/', str_replace( "\r\n", "\n", $text ) );
		$entries = [];
		foreach ( (array) $blocks as $block ) {
			$entry = self::block( (string) $block );
			if ( null !== $entry && '' !== $entry['id'] ) {
				$entries[] = $entry;
			}
		}
		return $entries;
	}

	/**
	 * Entries keyed by "ctx\4msgid" (as core's .l10n.php keys them).
	 *
	 * @return array<string,array{ctx:?string,id:string,plural:?string,str:array<int,string>,refs:array<int,string>,flags:array<int,string>,extracted:string}>
	 */
	public static function keyed( string $file ): array {
		$out = [];
		foreach ( self::entries( $file ) as $entry ) {
			$out[ self::key( $entry ) ] = $entry;
		}
		return $out;
	}

	/** @param array{ctx:?string,id:string} $entry */
	public static function key( array $entry ): string {
		return null !== $entry['ctx'] ? $entry['ctx'] . "\4" . $entry['id'] : $entry['id'];
	}

	/**
	 * Entries referenced from $path (a file relative to the plugin root).
	 *
	 * @param array<int|string,array{refs:array<int,string>}> $entries
	 * @return array<int|string,array{refs:array<int,string>}>
	 */
	public static function referenced_from( array $entries, string $path ): array {
		return array_filter(
			$entries,
			static fn( array $entry ): bool => in_array( $path, $entry['refs'], true )
		);
	}

	/**
	 * Single-quoted gettext msgids in a PHP source file: __(), _e(), _n()
	 * (both forms), _x(), esc_html__(), esc_html_e(), esc_attr__(),
	 * esc_attr_e() with the magicauth domain.
	 *
	 * @return array<int,string>
	 */
	public static function source_msgids( string $file ): array {
		return self::msgids_in( (string) file_get_contents( $file ) );
	}

	/**
	 * Msgids of the method bodies named in $methods (their source lines).
	 *
	 * @param class-string      $class   Class.
	 * @param array<int,string> $methods Method names.
	 * @return array<int,string>
	 */
	public static function method_msgids( string $class, array $methods ): array {
		$out = [];
		foreach ( $methods as $method ) {
			$ref   = new \ReflectionMethod( $class, $method );
			$lines = file( (string) $ref->getFileName() );
			$body  = implode( '', array_slice( (array) $lines, (int) $ref->getStartLine() - 1, (int) $ref->getEndLine() - (int) $ref->getStartLine() + 1 ) );
			$out   = array_merge( $out, self::msgids_in( $body ) );
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Msgids in PHP source text (see source_msgids()).
	 *
	 * @return array<int,string>
	 */
	public static function msgids_in( string $src ): array {
		// A single-quoted literal, or a double-quoted one without variables.
		$q   = '(?:\'((?:[^\'\\\\]|\\\\.)*)\'|"((?:[^"\\\\$]|\\\\.)*)")';
		$out = [];
		preg_match_all( '/\b(?:__|_e|_x|esc_html__|esc_html_e|esc_attr__|esc_attr_e|esc_html_x|esc_attr_x)\(\s*' . $q . '/', $src, $m, PREG_SET_ORDER );
		foreach ( $m as $match ) {
			$out[] = self::literal( $match, 1 );
		}
		preg_match_all( '/\b_n\(\s*' . $q . '\s*,\s*' . $q . '/', $src, $m, PREG_SET_ORDER );
		foreach ( $m as $match ) {
			$out[] = self::literal( $match, 1 );
			$out[] = self::literal( $match, 3 );
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Value of the literal captured at $group (single-quoted) or $group + 1
	 * (double-quoted).
	 *
	 * @param array<int,string> $match
	 */
	private static function literal( array $match, int $group ): string {
		if ( isset( $match[ $group + 1 ] ) && '' !== $match[ $group + 1 ] ) {
			return stripcslashes( $match[ $group + 1 ] );
		}
		return str_replace( [ "\\'", '\\\\' ], [ "'", '\\' ], $match[ $group ] ?? '' );
	}

	/** @return array{ctx:?string,id:string,plural:?string,str:array<int,string>,refs:array<int,string>,flags:array<int,string>,extracted:string}|null */
	private static function block( string $block ): ?array {
		$entry = [
			'ctx'       => null,
			'id'        => '',
			'plural'    => null,
			'str'       => [],
			'refs'      => [],
			'flags'     => [],
			'extracted' => '',
		];
		$field = null;
		$seen  = false;
		foreach ( explode( "\n", trim( $block ) ) as $line ) {
			if ( 0 === strpos( $line, '#~' ) ) {
				return null;
			}
			if ( 0 === strpos( $line, '#:' ) ) {
				foreach ( preg_split( '/\s+/', trim( substr( $line, 2 ) ) ) as $ref ) {
					if ( '' !== $ref ) {
						$entry['refs'][] = (string) preg_replace( '/:\d+$/', '', $ref );
					}
				}
				continue;
			}
			if ( 0 === strpos( $line, '#,' ) ) {
				$entry['flags'] = array_merge( $entry['flags'], array_map( 'trim', explode( ',', substr( $line, 2 ) ) ) );
				continue;
			}
			if ( 0 === strpos( $line, '#.' ) ) {
				$entry['extracted'] .= trim( substr( $line, 2 ) ) . "\n";
				continue;
			}
			if ( 0 === strpos( $line, '#' ) ) {
				continue;
			}
			if ( 1 === preg_match( '/^(msgctxt|msgid_plural|msgid|msgstr(?:\[(\d+)\])?)\s+"(.*)"$/', $line, $m ) ) {
				$seen  = true;
				$field = 'msgstr' === substr( $m[1], 0, 6 ) ? 'str' . ( '' !== $m[2] ? $m[2] : '0' ) : $m[1];
				self::append( $entry, $field, self::unescape( $m[3] ), true );
				continue;
			}
			if ( null !== $field && 1 === preg_match( '/^"(.*)"$/', $line, $m ) ) {
				self::append( $entry, $field, self::unescape( $m[1] ), false );
			}
		}
		return $seen ? $entry : null;
	}

	/** @param array<string,mixed> $entry */
	private static function append( array &$entry, string $field, string $value, bool $start ): void {
		if ( 'msgctxt' === $field ) {
			$entry['ctx'] = ( $start ? '' : (string) $entry['ctx'] ) . $value;
		} elseif ( 'msgid' === $field ) {
			$entry['id'] = ( $start ? '' : $entry['id'] ) . $value;
		} elseif ( 'msgid_plural' === $field ) {
			$entry['plural'] = ( $start ? '' : (string) $entry['plural'] ) . $value;
		} else {
			$n                  = (int) substr( $field, 3 );
			$entry['str'][ $n ] = ( $start ? '' : ( $entry['str'][ $n ] ?? '' ) ) . $value;
		}
	}

	private static function unescape( string $s ): string {
		return strtr(
			$s,
			[
				'\\\\' => '\\',
				'\\"'  => '"',
				'\\n'  => "\n",
				'\\t'  => "\t",
			]
		);
	}
}
