<?php
/**
 * dbDelta() fake. The harness's ABSPATH is tests/phpunit/, so production's
 * `require_once ABSPATH . 'wp-admin/includes/upgrade.php'` lands here.
 *
 * Each CREATE TABLE in MySQL dbDelta syntax is translated to SQLite and run
 * through $wpdb->query() (so error injection and the query log apply):
 * a missing table is created with its PRIMARY KEY, UNIQUE KEY and KEY
 * indexes; an existing table gets ALTER TABLE ... ADD COLUMN for missing
 * columns and CREATE INDEX for missing indexes, as dbDelta would.
 * Calls are recorded in $magicauth_test_state['dbdelta_calls'].
 *
 * On the real-database harness ($wpdb->driver 'mysql') nothing is
 * translated: a missing table runs the CREATE TABLE string as given (what
 * core's dbDelta() sends for a new table), a missing column runs ALTER TABLE
 * ... ADD COLUMN with its definition as written, a missing index ALTER TABLE
 * ... ADD [UNIQUE] KEY.
 *
 * Translation: integer types -> INTEGER, char/text/date types -> TEXT,
 * binary/blob types -> BLOB, float types -> REAL; unsigned, AUTO_INCREMENT,
 * CHARACTER SET and COLLATE dropped; index prefix lengths dropped. A single
 * AUTO_INCREMENT primary key becomes INTEGER PRIMARY KEY AUTOINCREMENT. An
 * added NOT NULL column without DEFAULT gets the type's zero value as
 * DEFAULT, which is what MySQL fills existing rows with.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

if ( ! function_exists( 'magicauth_test_split_top_level' ) ) {
	/** @return array<int,string> Comma-separated parts outside parentheses and quotes. */
	function magicauth_test_split_top_level( string $body ): array {
		$parts = [];
		$buf   = '';
		$depth = 0;
		$quote = '';
		$len   = strlen( $body );
		for ( $i = 0; $i < $len; $i++ ) {
			$c = $body[ $i ];
			if ( '' !== $quote ) {
				$buf .= $c;
				if ( $c === $quote ) {
					$quote = '';
				}
				continue;
			}
			if ( "'" === $c || '"' === $c ) {
				$quote = $c;
			} elseif ( '(' === $c ) {
				++$depth;
			} elseif ( ')' === $c ) {
				--$depth;
			} elseif ( ',' === $c && 0 === $depth ) {
				$parts[] = trim( $buf );
				$buf     = '';
				continue;
			}
			$buf .= $c;
		}
		if ( '' !== trim( $buf ) ) {
			$parts[] = trim( $buf );
		}
		return $parts;
	}
}

if ( ! function_exists( 'magicauth_test_index_columns' ) ) {
	function magicauth_test_index_columns( string $cols ): string {
		$out = [];
		foreach ( explode( ',', $cols ) as $col ) {
			$out[] = trim( (string) preg_replace( '/\(\d+\)/', '', $col ) );
		}
		return implode( ', ', $out );
	}
}

if ( ! function_exists( 'magicauth_test_parse_create_table' ) ) {
	/**
	 * @return array{table:string,columns:array<string,array{raw:string,sql:string,type:string,not_null:bool,has_default:bool,auto_increment:bool}>,primary:array<int,string>,indexes:array<string,array{unique:bool,columns:string,raw:string}>}|null
	 */
	function magicauth_test_parse_create_table( string $query ): ?array {
		if ( ! preg_match( '/^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?`?(\w+)`?\s*\((.*)\)[^)]*$/is', $query, $m ) ) {
			return null;
		}
		$parsed = [
			'table'   => $m[1],
			'columns' => [],
			'primary' => [],
			'indexes' => [],
		];
		foreach ( magicauth_test_split_top_level( $m[2] ) as $def ) {
			if ( preg_match( '/^PRIMARY\s+KEY\s*\((.+)\)$/is', $def, $pk ) ) {
				$parsed['primary'] = array_map( 'trim', explode( ',', magicauth_test_index_columns( $pk[1] ) ) );
				continue;
			}
			if ( preg_match( '/^(UNIQUE\s+)?(?:KEY|INDEX)\s+`?(\w+)`?\s*\((.+)\)$/is', $def, $ix ) ) {
				$parsed['indexes'][ $ix[2] ] = [
					'unique'  => '' !== trim( $ix[1] ),
					'columns' => magicauth_test_index_columns( $ix[3] ),
					'raw'     => trim( $ix[3] ),
				];
				continue;
			}
			if ( ! preg_match( '/^`?(\w+)`?\s+(\w+)(\([^)]*\))?(.*)$/is', $def, $col ) ) {
				continue;
			}
			$type = strtolower( $col[2] );
			if ( preg_match( '/^(tinyint|smallint|mediumint|int|integer|bigint|bool|boolean)$/', $type ) ) {
				$sqlite_type = 'INTEGER';
			} elseif ( preg_match( '/^(binary|varbinary|blob|tinyblob|mediumblob|longblob)$/', $type ) ) {
				$sqlite_type = 'BLOB';
			} elseif ( preg_match( '/^(float|double|decimal|real)$/', $type ) ) {
				$sqlite_type = 'REAL';
			} else {
				$sqlite_type = 'TEXT';
			}
			$rest = $col[4];
			$auto = (bool) preg_match( '/\bAUTO_INCREMENT\b/i', $rest );
			$rest = (string) preg_replace( '/\b(unsigned|AUTO_INCREMENT)\b/i', '', $rest );
			$rest = (string) preg_replace( '/\b(CHARACTER\s+SET|COLLATE)\s+\w+/i', '', $rest );
			$rest = trim( (string) preg_replace( '/\s+/', ' ', $rest ) );

			$parsed['columns'][ $col[1] ] = [
				'raw'            => trim( $def ),
				'sql'            => trim( $col[1] . ' ' . $sqlite_type . ' ' . $rest ),
				'type'           => $sqlite_type,
				'not_null'       => (bool) preg_match( '/\bNOT\s+NULL\b/i', $rest ),
				'has_default'    => (bool) preg_match( '/\bDEFAULT\b/i', $rest ),
				'auto_increment' => $auto,
			];
		}
		return $parsed;
	}
}

if ( ! function_exists( 'dbDelta' ) ) {
	/**
	 * @param string|array<int,string> $queries
	 * @return array<string,string> Messages keyed like core's (table or table.column).
	 */
	function dbDelta( $queries = '', $execute = true ): array { // phpcs:ignore WordPress.NamingConventions.ValidFunctionName.FunctionNameInvalid
		global $wpdb, $magicauth_test_state;

		if ( ! is_array( $queries ) ) {
			$queries = explode( ';', (string) $queries );
		}
		$queries = array_values( array_filter( array_map( 'trim', $queries ), static fn( $q ) => '' !== $q ) );

		$magicauth_test_state['dbdelta_calls'][] = [
			'queries' => $queries,
			'execute' => (bool) $execute,
		];

		$messages = [];
		foreach ( $queries as $query ) {
			$parsed = magicauth_test_parse_create_table( $query );
			if ( null === $parsed ) {
				if ( $execute ) {
					$wpdb->query( $query );
				}
				continue;
			}
			$table  = $parsed['table'];
			$exists = $wpdb->table_exists( $table );
			$mysql  = 'mysql' === $wpdb->driver;

			if ( ! $exists && $mysql ) {
				$messages[ $table ] = 'Created table ' . $table;
				if ( $execute ) {
					$wpdb->query( rtrim( $query, "; \n\t" ) );
				}
				continue;
			}

			if ( $mysql ) {
				$have_columns = array_map( 'strtolower', $wpdb->table_columns( $table ) );
				foreach ( $parsed['columns'] as $name => $col ) {
					if ( in_array( strtolower( $name ), $have_columns, true ) ) {
						continue;
					}
					$messages[ $table . '.' . $name ] = 'Added column ' . $table . '.' . $name;
					if ( $execute ) {
						$wpdb->query( 'ALTER TABLE ' . $table . ' ADD COLUMN ' . $col['raw'] );
					}
				}
				$have_indexes = $wpdb->table_indexes( $table );
				foreach ( $parsed['indexes'] as $index => $info ) {
					if ( isset( $have_indexes[ $index ] ) ) {
						continue;
					}
					$messages[] = 'Added index ' . $table . ' ' . $index;
					if ( $execute ) {
						$wpdb->query( sprintf( 'ALTER TABLE %s ADD %sKEY %s (%s)', $table, $info['unique'] ? 'UNIQUE ' : '', $index, $info['raw'] ) );
					}
				}
				continue;
			}

			if ( ! $exists ) {
				$defs   = [];
				$single = 1 === count( $parsed['primary'] ) ? $parsed['primary'][0] : '';
				foreach ( $parsed['columns'] as $name => $col ) {
					if ( $name === $single && $col['auto_increment'] ) {
						$defs[] = $name . ' INTEGER PRIMARY KEY AUTOINCREMENT';
						continue;
					}
					$defs[] = $col['sql'];
				}
				if ( [] !== $parsed['primary'] && ! ( '' !== $single && $parsed['columns'][ $single ]['auto_increment'] ) ) {
					$defs[] = 'PRIMARY KEY (' . implode( ', ', $parsed['primary'] ) . ')';
				}
				$messages[ $table ] = 'Created table ' . $table;
				if ( $execute ) {
					$wpdb->query( 'CREATE TABLE ' . $table . ' (' . implode( ', ', $defs ) . ')' );
				}
				foreach ( $parsed['indexes'] as $index => $info ) {
					if ( $execute ) {
						$wpdb->query( sprintf( 'CREATE %sINDEX %s__%s ON %s (%s)', $info['unique'] ? 'UNIQUE ' : '', $table, $index, $table, $info['columns'] ) );
					}
				}
				continue;
			}

			$have = [];
			foreach ( $wpdb->get_results( 'PRAGMA table_info(' . $table . ')' ) as $row ) {
				$have[ strtolower( (string) $row->name ) ] = true;
			}
			foreach ( $parsed['columns'] as $name => $col ) {
				if ( isset( $have[ strtolower( $name ) ] ) ) {
					continue;
				}
				$sql = $col['sql'];
				if ( $col['not_null'] && ! $col['has_default'] ) {
					$sql .= 'BLOB' === $col['type'] ? " DEFAULT X''" : ( 'TEXT' === $col['type'] ? " DEFAULT ''" : ' DEFAULT 0' );
				}
				$messages[ $table . '.' . $name ] = 'Added column ' . $table . '.' . $name;
				if ( $execute ) {
					$wpdb->query( 'ALTER TABLE ' . $table . ' ADD COLUMN ' . $sql );
				}
			}

			$have_index = [];
			foreach ( $wpdb->get_results( 'PRAGMA index_list(' . $table . ')' ) as $row ) {
				$have_index[ (string) $row->name ] = true;
			}
			foreach ( $parsed['indexes'] as $index => $info ) {
				$sqlite_name = $table . '__' . $index;
				if ( isset( $have_index[ $sqlite_name ] ) ) {
					continue;
				}
				$messages[] = 'Added index ' . $table . ' ' . $index;
				if ( $execute ) {
					$wpdb->query( sprintf( 'CREATE %sINDEX %s ON %s (%s)', $info['unique'] ? 'UNIQUE ' : '', $sqlite_name, $table, $info['columns'] ) );
				}
			}
		}
		return $messages;
	}
}
