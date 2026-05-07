<?php
/**
 * SQLite-backed $wpdb shim.
 *
 * Implements just enough of $wpdb for TokenManager and Throttle: insert(),
 * prepare(), query(), get_row(), get_results(), prefix/options properties.
 *
 * Atomic UPDATE-with-WHERE semantics are real because they're delegated to
 * SQLite. The TOCTOU-style tests in TokenManagerTest exercise the WHERE
 * clauses end-to-end, not via mocks.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Stubs;

use PDO;
use PDOException;

/**
 * Thin $wpdb facade over an in-memory SQLite connection.
 */
final class WPDBSqlite {

	public string $prefix;

	public string $options;

	public string $charset = 'utf8mb4';

	public string $collate = 'utf8mb4_unicode_ci';

	public int $insert_id = 0;

	public string $last_error = '';

	private PDO $pdo;

	public function __construct( string $prefix = 'wp_' ) {
		$this->prefix  = $prefix;
		$this->options = $prefix . 'options';

		$this->pdo = new PDO( 'sqlite::memory:' );
		$this->pdo->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );

		// Use TEXT for datetime columns; lexicographic comparison on
		// "Y-m-d H:i:s" strings is monotonic, which is all our queries need.
		$this->pdo->exec(
			"CREATE TABLE {$this->options} (
				option_id INTEGER PRIMARY KEY AUTOINCREMENT,
				option_name TEXT NOT NULL UNIQUE,
				option_value TEXT NOT NULL,
				autoload TEXT NOT NULL DEFAULT 'yes'
			)"
		);
	}

	/**
	 * Create the magicauth_requests table for the SQLite instance. Mirrors the
	 * production schema modulo the SQL dialect (SQLite is loose with types so
	 * declarations are accepted as-is; the WHERE clauses we test are dialect-
	 * neutral).
	 */
	public function install_magicauth_schema(): void {
		$table = $this->prefix . 'magicauth_requests';
		$this->pdo->exec( "DROP TABLE IF EXISTS {$table}" );
		$this->pdo->exec(
			"CREATE TABLE {$table} (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				selector TEXT NOT NULL UNIQUE,
				link_verifier_hash TEXT NOT NULL,
				code_verifier_hash TEXT NOT NULL,
				user_id INTEGER NOT NULL,
				email_hmac TEXT NOT NULL,
				ip_hmac TEXT NOT NULL,
				created_at TEXT NOT NULL,
				expires_at TEXT NOT NULL,
				consumed_at TEXT DEFAULT NULL,
				use_count INTEGER NOT NULL DEFAULT 0,
				code_attempts INTEGER NOT NULL DEFAULT 0
			)"
		);
	}

	public function truncate_magicauth_table(): void {
		$table = $this->prefix . 'magicauth_requests';
		$this->pdo->exec( "DELETE FROM {$table}" );
		$this->pdo->exec( "DELETE FROM sqlite_sequence WHERE name = '{$table}'" );
		$this->pdo->exec( "DELETE FROM {$this->options}" );
	}

	public function get_charset_collate(): string {
		return "DEFAULT CHARACTER SET {$this->charset} COLLATE {$this->collate}";
	}

	/**
	 * Substitute WP-style %s/%d/%f placeholders.
	 *
	 * @param string $query Query with placeholders.
	 * @param mixed  ...$args Replacement values.
	 */
	public function prepare( string $query, ...$args ): string {
		// WP supports passing a single array of args; collapse that case.
		if ( 1 === count( $args ) && is_array( $args[0] ) ) {
			$args = $args[0];
		}

		$out   = '';
		$cur   = 0;
		$len   = strlen( $query );
		$index = 0;
		while ( $cur < $len ) {
			$pos = strpos( $query, '%', $cur );
			if ( false === $pos ) {
				$out .= substr( $query, $cur );
				break;
			}
			$out .= substr( $query, $cur, $pos - $cur );
			$spec = $query[ $pos + 1 ] ?? '';
			$cur  = $pos + 2;

			if ( '%' === $spec ) {
				$out .= '%';
				continue;
			}

			$value = $args[ $index ] ?? null;
			++$index;

			switch ( $spec ) {
				case 's':
					$out .= null === $value ? 'NULL' : $this->pdo->quote( (string) $value );
					break;
				case 'd':
					$out .= null === $value ? 'NULL' : (string) (int) $value;
					break;
				case 'f':
					$out .= null === $value ? 'NULL' : (string) (float) $value;
					break;
				default:
					$out .= '%' . $spec;
					break;
			}
		}

		return $out;
	}

	public function query( $query ) {
		try {
			$stmt = $this->pdo->query( (string) $query );
			if ( false === $stmt ) {
				return false;
			}
			// Return rowCount for INSERT/UPDATE/DELETE; for SELECT it's not
			// meaningful but TokenManager never query()s a SELECT.
			$count = $stmt->rowCount();
			if ( 0 === stripos( ltrim( (string) $query ), 'INSERT' ) ) {
				$this->insert_id = (int) $this->pdo->lastInsertId();
			}
			return $count;
		} catch ( PDOException $e ) {
			$this->last_error = $e->getMessage();
			return false;
		}
	}

	public function get_row( $query, $output = OBJECT_K, $row_offset = 0 ) {
		unset( $output, $row_offset );
		try {
			$stmt = $this->pdo->query( (string) $query );
			if ( false === $stmt ) {
				return null;
			}
			$row = $stmt->fetch( PDO::FETCH_OBJ );
			return false === $row ? null : $row;
		} catch ( PDOException $e ) {
			$this->last_error = $e->getMessage();
			return null;
		}
	}

	public function get_results( $query, $output = OBJECT ) {
		unset( $output );
		try {
			$stmt = $this->pdo->query( (string) $query );
			if ( false === $stmt ) {
				return [];
			}
			return $stmt->fetchAll( PDO::FETCH_OBJ );
		} catch ( PDOException $e ) {
			$this->last_error = $e->getMessage();
			return [];
		}
	}

	public function get_var( $query ) {
		try {
			$stmt = $this->pdo->query( (string) $query );
			if ( false === $stmt ) {
				return null;
			}
			$row = $stmt->fetch( PDO::FETCH_NUM );
			return false === $row ? null : ( $row[0] ?? null );
		} catch ( PDOException $e ) {
			$this->last_error = $e->getMessage();
			return null;
		}
	}

	public function get_col( $query, int $column = 0 ): array {
		try {
			$stmt = $this->pdo->query( (string) $query );
			if ( false === $stmt ) {
				return [];
			}
			$out = [];
			while ( $row = $stmt->fetch( PDO::FETCH_NUM ) ) {
				$out[] = $row[ $column ] ?? null;
			}
			return $out;
		} catch ( PDOException $e ) {
			$this->last_error = $e->getMessage();
			return [];
		}
	}

	public function insert( string $table, array $data, $format = null ) {
		unset( $format );
		$columns      = array_keys( $data );
		$placeholders = array_map(
			function ( $value ): string {
				if ( null === $value ) {
					return 'NULL';
				}
				if ( is_int( $value ) ) {
					return (string) $value;
				}
				if ( is_float( $value ) ) {
					return (string) $value;
				}
				return $this->pdo->quote( (string) $value );
			},
			array_values( $data )
		);

		$sql = sprintf(
			'INSERT INTO %s (%s) VALUES (%s)',
			$table,
			implode( ',', $columns ),
			implode( ',', $placeholders )
		);

		try {
			$count           = $this->pdo->exec( $sql );
			$this->insert_id = (int) $this->pdo->lastInsertId();
			return false === $count ? false : (int) $count;
		} catch ( PDOException $e ) {
			$this->last_error = $e->getMessage();
			return false;
		}
	}
}

if ( ! defined( 'OBJECT' ) ) {
	define( 'OBJECT', 'OBJECT' );
}
if ( ! defined( 'OBJECT_K' ) ) {
	define( 'OBJECT_K', 'OBJECT_K' );
}
