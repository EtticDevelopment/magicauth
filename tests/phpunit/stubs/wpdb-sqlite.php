<?php
/**
 * SQLite-backed $wpdb shim.
 *
 * Implements the slice of wpdb the plugin uses: insert(), prepare(), query(),
 * get_row(), get_results(), get_var(), get_col(), esc_like(), prefix/options
 * properties, last_error / rows_affected / insert_id, show_errors(),
 * suppress_errors() and print_error() as core behaves.
 *
 * Atomic UPDATE-with-WHERE semantics are real because they're delegated to
 * SQLite. The TOCTOU-style tests in TokenManagerTest exercise the WHERE
 * clauses end-to-end, not via mocks.
 *
 * MySQL emulation (SPEC 14.1):
 * - Rewrites before execution: `DELETE FROM t [WHERE c] [ORDER BY o] LIMIT n`
 *   becomes a rowid sub-select (SQLite rejects DELETE ... LIMIT), and
 *   `INSERT IGNORE INTO` becomes `INSERT OR IGNORE INTO`.
 * - LIKE: a quoted pattern gets `ESCAPE '\'` appended, MySQL's default escape
 *   character (the one $wpdb->esc_like() uses; SQLite has none). An explicit
 *   ESCAPE clause fails like a syntax error: the WordPress SQLite integration
 *   driver (Playground, Studio, the E2E suite) appends its own `ESCAPE '\'`
 *   to every LIKE, so a second one is a syntax error there.
 * - $mysql_changed_rows: an UPDATE returns the number of rows whose values
 *   changed, as WordPress's mysqli connection (client_flags = 0) reports it,
 *   instead of SQLite's matched rows. Off by default; the passkey suites turn
 *   it on.
 * - fail_next_query( $pattern ): the next query matching the pattern fails like
 *   a MySQL error (last_error set, print_error() called, query() returns false).
 * - before_next_query( $pattern, $callback ): runs $callback once just before
 *   the next matching query executes, to interleave a "concurrent request".
 * - Fetched values are strings (or null), as mysqli returns them.
 * - {prefix}users and {prefix}usermeta are mirrored from $magicauth_test_state
 *   just before any query that names them (orphan sweep joins, handle lookup).
 *
 * Real database (SPEC 14.1, CI job real-database): with the environment
 * variable MAGICAUTH_TEST_DB=mysql, from_environment() connects to MySQL or
 * MariaDB through PDO without CLIENT_FOUND_ROWS (PDO::MYSQL_ATTR_FOUND_ROWS
 * off), so an UPDATE reports changed rows exactly as WordPress's mysqli
 * connection does. No statement is rewritten and no changed-rows emulation
 * runs there; schema helpers create the tables from Installer::schema() (the
 * production DDL). Settings: MAGICAUTH_TEST_DB_HOST, _PORT, _NAME, _USER, _PASS.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Stubs;

use PDO;
use PDOException;
use PDOStatement;

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

	public ?string $last_query = null;

	public int $rows_affected = 0;

	public int $num_rows = 0;

	/** @var array<int,object> */
	public array $last_result = [];

	public bool $show_errors = false;

	public bool $suppress_errors = false;

	/** Emulate MySQL affected-rows (rows changed, not rows matched) for UPDATE. SQLite only; MySQL reports them natively. */
	public bool $mysql_changed_rows = false;

	/** 'sqlite' (in-memory, default) or 'mysql' (real server, CI). */
	public string $driver = 'sqlite';

	public string $users;

	public string $usermeta;

	/**
	 * Every statement as executed (after rewrites), for "no query against X" assertions.
	 *
	 * @var array<int,string>
	 */
	public array $query_log = [];

	/**
	 * Errors print_error() would have sent to error_log(), kept here instead of stderr.
	 *
	 * @var array<int,array{query:string,error:string}>
	 */
	public array $error_log = [];

	/** @var array<int,string> */
	private array $fail_patterns = [];

	/** @var array<int,array{0:string,1:callable}> */
	private array $before_hooks = [];

	private PDO $pdo;

	public function __construct( string $prefix = 'wp_', ?PDO $pdo = null ) {
		$this->prefix   = $prefix;
		$this->options  = $prefix . 'options';
		$this->users    = $prefix . 'users';
		$this->usermeta = $prefix . 'usermeta';

		if ( null !== $pdo && 'mysql' === $pdo->getAttribute( PDO::ATTR_DRIVER_NAME ) ) {
			$this->driver = 'mysql';
			$this->pdo    = $pdo;
			$this->pdo->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
			$this->pdo->setAttribute( PDO::ATTR_STRINGIFY_FETCHES, true );
			$this->pdo->exec( "DROP TABLE IF EXISTS {$this->options}" );
			$this->pdo->exec(
				"CREATE TABLE {$this->options} (
					option_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
					option_name varchar(191) NOT NULL DEFAULT '',
					option_value longtext NOT NULL,
					autoload varchar(20) NOT NULL DEFAULT 'yes',
					PRIMARY KEY (option_id),
					UNIQUE KEY option_name (option_name)
				) " . $this->get_charset_collate()
			);
			return;
		}

		$this->pdo = new PDO( 'sqlite::memory:' );
		$this->pdo->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
		$this->pdo->setAttribute( PDO::ATTR_STRINGIFY_FETCHES, true );

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
	 * SQLite in memory, or the real server named by MAGICAUTH_TEST_DB=mysql
	 * (CI). The MySQL session gets WordPress's sql_mode handling
	 * (wpdb::set_sql_mode() drops these incompatible modes) and utf8mb4.
	 */
	public static function from_environment( string $prefix = 'wp_' ): self {
		if ( 'mysql' !== getenv( 'MAGICAUTH_TEST_DB' ) ) {
			return new self( $prefix );
		}
		$env = static function ( string $name, string $default ): string {
			$value = getenv( 'MAGICAUTH_TEST_DB_' . $name );
			return false === $value || '' === $value ? $default : $value;
		};
		$dsn = sprintf( 'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $env( 'HOST', '127.0.0.1' ), (int) $env( 'PORT', '3306' ), $env( 'NAME', 'magicauth_test' ) );
		$pdo = new PDO(
			$dsn,
			$env( 'USER', 'root' ),
			(string) getenv( 'MAGICAUTH_TEST_DB_PASS' ),
			[ PDO::MYSQL_ATTR_FOUND_ROWS => false ]
		);
		$modes = array_filter(
			explode( ',', (string) $pdo->query( 'SELECT @@SESSION.sql_mode' )->fetchColumn() ),
			static fn( string $mode ): bool => '' !== $mode && ! in_array( $mode, [ 'NO_ZERO_DATE', 'ONLY_FULL_GROUP_BY', 'STRICT_TRANS_TABLES', 'STRICT_ALL_TABLES', 'TRADITIONAL', 'ANSI' ], true )
		);
		$pdo->exec( 'SET SESSION sql_mode = ' . $pdo->quote( implode( ',', $modes ) ) );
		return new self( $prefix, $pdo );
	}

	/** Server version string (VERSION()), for the driver guard test. */
	public function server_version(): string {
		if ( 'mysql' !== $this->driver ) {
			return 'SQLite ' . (string) $this->pdo->query( 'SELECT sqlite_version()' )->fetchColumn();
		}
		return (string) $this->pdo->query( 'SELECT VERSION()' )->fetchColumn();
	}

	/**
	 * Create the magicauth_requests table, current schema (with issued_by),
	 * or the 1.0.5 shape without it ($v1). Mirrors the production schema
	 * modulo the SQL dialect; on MySQL the production DDL itself runs.
	 */
	public function install_magicauth_schema( bool $v1 = false ): void {
		$table = $this->prefix . 'magicauth_requests';
		$this->pdo->exec( "DROP TABLE IF EXISTS {$table}" );
		if ( 'mysql' === $this->driver ) {
			$ddl = \MagicAuth\Installer::schema()[0];
			if ( $v1 ) {
				$ddl = (string) preg_replace( '/^\s*issued_by\b.*\n/m', '', $ddl );
			}
			$this->pdo->exec( rtrim( $ddl, "; \n\t" ) );
			return;
		}
		$this->pdo->exec(
			"CREATE TABLE {$table} (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				selector TEXT NOT NULL,
				link_verifier_hash TEXT NOT NULL,
				code_verifier_hash TEXT NOT NULL,
				user_id INTEGER NOT NULL,
				email_hmac TEXT NOT NULL,
				ip_hmac TEXT NOT NULL,
				created_at TEXT NOT NULL,
				expires_at TEXT NOT NULL,
				consumed_at TEXT DEFAULT NULL,
				use_count INTEGER NOT NULL DEFAULT 0,
				code_attempts INTEGER NOT NULL DEFAULT 0"
			. ( $v1 ? '' : ',
				issued_by INTEGER NOT NULL DEFAULT 0' ) . '
			)'
		);
		$this->pdo->exec( "CREATE UNIQUE INDEX {$table}__selector ON {$table} (selector)" );
		$this->pdo->exec( "CREATE INDEX {$table}__email_hmac_consumed ON {$table} (email_hmac, consumed_at)" );
		$this->pdo->exec( "CREATE INDEX {$table}__user_id ON {$table} (user_id)" );
	}

	/**
	 * Create the three passkey tables (SPEC 5.1, 5.2, 5.6), UNIQUE indexes
	 * included, in SQLite types. Index names follow the dbDelta fake
	 * ({table}__{key}). On MySQL the production DDL itself runs.
	 */
	public function install_magicauth_passkeys_schema(): void {
		$p = $this->prefix;
		foreach ( [ 'magicauth_passkeys', 'magicauth_passkey_challenges', 'magicauth_passkey_sessions' ] as $name ) {
			$this->pdo->exec( "DROP TABLE IF EXISTS {$p}{$name}" );
		}
		if ( 'mysql' === $this->driver ) {
			foreach ( array_slice( \MagicAuth\Installer::schema(), 1 ) as $ddl ) {
				$this->pdo->exec( rtrim( $ddl, "; \n\t" ) );
			}
			return;
		}
		$this->pdo->exec(
			"CREATE TABLE {$p}magicauth_passkeys (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				user_id INTEGER NOT NULL,
				rp_id TEXT NOT NULL,
				credential_id TEXT NOT NULL,
				credential_hash TEXT NOT NULL,
				user_handle TEXT NOT NULL,
				public_key TEXT NOT NULL,
				alg INTEGER NOT NULL,
				sign_count INTEGER NOT NULL DEFAULT 0,
				backup_eligible INTEGER NOT NULL DEFAULT 0,
				backup_state INTEGER NOT NULL DEFAULT 0,
				transports TEXT NOT NULL DEFAULT '',
				aaguid TEXT NOT NULL DEFAULT '',
				name TEXT NOT NULL DEFAULT '',
				user_registered TEXT NOT NULL DEFAULT '',
				created_at TEXT NOT NULL,
				last_used_at TEXT DEFAULT NULL,
				counter_anomaly_at TEXT DEFAULT NULL
			)"
		);
		$this->pdo->exec( "CREATE UNIQUE INDEX {$p}magicauth_passkeys__credential_hash ON {$p}magicauth_passkeys (credential_hash)" );
		$this->pdo->exec( "CREATE INDEX {$p}magicauth_passkeys__user_id ON {$p}magicauth_passkeys (user_id)" );
		$this->pdo->exec(
			"CREATE TABLE {$p}magicauth_passkey_challenges (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				lookup_hash TEXT NOT NULL,
				ceremony TEXT NOT NULL,
				user_id INTEGER NOT NULL DEFAULT 0,
				session_hash TEXT NOT NULL DEFAULT '',
				binding_hash TEXT NOT NULL DEFAULT '',
				secret_hash TEXT NOT NULL DEFAULT '',
				user_handle TEXT NOT NULL DEFAULT '',
				algs TEXT NOT NULL DEFAULT '',
				attempts INTEGER NOT NULL DEFAULT 0,
				created_at TEXT NOT NULL,
				expires_at TEXT NOT NULL,
				consumed_at TEXT DEFAULT NULL
			)"
		);
		$this->pdo->exec( "CREATE UNIQUE INDEX {$p}magicauth_passkey_challenges__lookup_hash ON {$p}magicauth_passkey_challenges (lookup_hash)" );
		$this->pdo->exec( "CREATE INDEX {$p}magicauth_passkey_challenges__expires_at ON {$p}magicauth_passkey_challenges (expires_at)" );
		$this->pdo->exec( "CREATE INDEX {$p}magicauth_passkey_challenges__user_id ON {$p}magicauth_passkey_challenges (user_id)" );
		$this->pdo->exec(
			"CREATE TABLE {$p}magicauth_passkey_sessions (
				session_hash TEXT NOT NULL,
				user_id INTEGER NOT NULL,
				reauth_at INTEGER NOT NULL DEFAULT 0,
				reauth_method TEXT NOT NULL DEFAULT '',
				fresh_hash TEXT NOT NULL DEFAULT '',
				prompt_done INTEGER NOT NULL DEFAULT 0,
				signals_at INTEGER NOT NULL DEFAULT 0,
				expires_at TEXT NOT NULL,
				PRIMARY KEY (session_hash)
			)"
		);
		$this->pdo->exec( "CREATE INDEX {$p}magicauth_passkey_sessions__user_id ON {$p}magicauth_passkey_sessions (user_id)" );
		$this->pdo->exec( "CREATE INDEX {$p}magicauth_passkey_sessions__expires_at ON {$p}magicauth_passkey_sessions (expires_at)" );
	}

	/** Every MagicAuth table that exists, emptied (auto-increment reset), plus the options table. */
	public function truncate_magicauth_table(): void {
		foreach ( [ 'magicauth_requests', 'magicauth_passkeys', 'magicauth_passkey_challenges', 'magicauth_passkey_sessions' ] as $name ) {
			$table = $this->prefix . $name;
			if ( ! $this->table_exists( $table ) ) {
				continue;
			}
			if ( 'mysql' === $this->driver ) {
				$this->pdo->exec( "TRUNCATE TABLE {$table}" );
				continue;
			}
			$this->pdo->exec( "DELETE FROM {$table}" );
			$this->pdo->exec( "DELETE FROM sqlite_sequence WHERE name = '{$table}'" );
		}
		$this->pdo->exec( "DELETE FROM {$this->options}" );
	}

	/** Whether a table exists (direct, not logged, no error injection). */
	public function table_exists( string $table ): bool {
		if ( 'mysql' === $this->driver ) {
			$stmt = $this->pdo->prepare( 'SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?' );
		} else {
			$stmt = $this->pdo->prepare( "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?" );
		}
		$stmt->execute( [ $table ] );
		return (int) $stmt->fetchColumn() > 0;
	}

	/**
	 * Column names in table order (direct, not logged).
	 *
	 * @return array<int,string>
	 */
	public function table_columns( string $table ): array {
		if ( 'mysql' === $this->driver ) {
			$stmt = $this->pdo->prepare( 'SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION' );
			$stmt->execute( [ $table ] );
			return array_map( 'strval', $stmt->fetchAll( PDO::FETCH_COLUMN ) );
		}
		$out = [];
		foreach ( $this->pdo->query( 'PRAGMA table_info(' . $table . ')' )->fetchAll( PDO::FETCH_ASSOC ) as $row ) {
			$out[] = (string) $row['name'];
		}
		return $out;
	}

	/**
	 * Secondary indexes as name => [ unique, columns ], primary key excluded
	 * (direct, not logged). SQLite names lose the dbDelta fake's "{table}__"
	 * prefix, so both drivers report the DDL key names.
	 *
	 * @return array<string,array{unique:bool,columns:string}>
	 */
	public function table_indexes( string $table ): array {
		$out = [];
		if ( 'mysql' === $this->driver ) {
			$stmt = $this->pdo->prepare( 'SELECT INDEX_NAME, NON_UNIQUE, COLUMN_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? ORDER BY INDEX_NAME, SEQ_IN_INDEX' );
			$stmt->execute( [ $table ] );
			foreach ( $stmt->fetchAll( PDO::FETCH_ASSOC ) as $row ) {
				$name = (string) $row['INDEX_NAME'];
				if ( 'PRIMARY' === $name ) {
					continue;
				}
				$out[ $name ]['unique']    = '0' === (string) $row['NON_UNIQUE'];
				$out[ $name ]['columns'][] = (string) $row['COLUMN_NAME'];
			}
		} else {
			foreach ( $this->pdo->query( 'PRAGMA index_list(' . $table . ')' )->fetchAll( PDO::FETCH_ASSOC ) as $index ) {
				if ( 'pk' === ( $index['origin'] ?? '' ) ) {
					continue;
				}
				$name = (string) $index['name'];
				$cols = [];
				foreach ( $this->pdo->query( 'PRAGMA index_info(' . $this->pdo->quote( $name ) . ')' )->fetchAll( PDO::FETCH_ASSOC ) as $col ) {
					$cols[] = (string) $col['name'];
				}
				$key           = 0 === strpos( $name, $table . '__' ) ? substr( $name, strlen( $table ) + 2 ) : $name;
				$out[ $key ] = [
					'unique'  => '1' === (string) $index['unique'],
					'columns' => $cols,
				];
			}
		}
		ksort( $out );
		foreach ( $out as $name => $info ) {
			$out[ $name ]['columns'] = implode( ', ', (array) $info['columns'] );
		}
		return $out;
	}

	/** Called by magicauth_test_reset_state(): every MySQL-emulation switch back to its default. */
	public function reset_test_switches(): void {
		$this->mysql_changed_rows = false;
		$this->show_errors        = false;
		$this->suppress_errors    = false;
		$this->fail_patterns      = [];
		$this->before_hooks       = [];
		$this->query_log          = [];
		$this->error_log          = [];
		$this->last_error         = '';
	}

	/**
	 * Make the next query that matches $pattern fail. A pattern starting with
	 * '/' or '#' is a regex; anything else is a case-insensitive substring.
	 * Patterns queue up and each is consumed by its first match.
	 */
	public function fail_next_query( string $pattern ): void {
		$this->fail_patterns[] = $pattern;
	}

	/**
	 * Run $callback once, just before the next query matching $pattern (same
	 * matching as fail_next_query()). The callback may run queries itself.
	 */
	public function before_next_query( string $pattern, callable $callback ): void {
		$this->before_hooks[] = [ $pattern, $callback ];
	}

	public function get_charset_collate(): string {
		return "DEFAULT CHARACTER SET {$this->charset} COLLATE {$this->collate}";
	}

	/** Core wpdb::esc_like(). */
	public function esc_like( string $text ): string {
		return addcslashes( $text, '_%\\' );
	}

	/** @return bool Previous value. */
	public function show_errors( bool $show = true ): bool {
		$previous          = $this->show_errors;
		$this->show_errors = $show;
		return $previous;
	}

	/** @return bool Previous value. */
	public function hide_errors(): bool {
		$previous          = $this->show_errors;
		$this->show_errors = false;
		return $previous;
	}

	/** @return bool Previous value. */
	public function suppress_errors( bool $suppress = true ): bool {
		$previous              = $this->suppress_errors;
		$this->suppress_errors = $suppress;
		return $previous;
	}

	/**
	 * Core wpdb::print_error(): suppressed -> nothing; otherwise logged, and
	 * echoed (single site) when show_errors is on.
	 *
	 * @return false|void
	 */
	public function print_error( string $str = '' ) {
		if ( '' === $str ) {
			$str = $this->last_error;
		}
		if ( $this->suppress_errors ) {
			return false;
		}
		$this->error_log[] = [
			'query' => (string) $this->last_query,
			'error' => $str,
		];
		if ( ! $this->show_errors ) {
			return false;
		}
		if ( function_exists( 'is_multisite' ) && is_multisite() ) {
			return;
		}
		printf(
			'<div id="error"><p class="wpdberror"><strong>%s</strong> [%s]<br /><code>%s</code></p></div>',
			'WordPress database error:',
			htmlspecialchars( $str, ENT_QUOTES ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			htmlspecialchars( (string) $this->last_query, ENT_QUOTES ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		);
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

	/**
	 * Core return values: true for CREATE/ALTER/TRUNCATE/DROP, affected rows for
	 * INSERT/UPDATE/DELETE/REPLACE, the number of rows for anything else, false on error.
	 *
	 * @return int|bool
	 */
	public function query( $query ) {
		$stmt = $this->execute( (string) $query );
		if ( null === $stmt ) {
			return false;
		}
		$sql = ltrim( (string) $query );
		if ( preg_match( '/^(create|alter|truncate|drop)\s/i', $sql ) ) {
			return true;
		}
		if ( preg_match( '/^(insert|delete|update|replace)\s/i', $sql ) ) {
			return $this->rows_affected;
		}
		return $this->num_rows;
	}

	/**
	 * @return object|array<mixed>|null
	 */
	public function get_row( $query, $output = OBJECT, $row_offset = 0 ) {
		if ( null === $this->execute( (string) $query ) ) {
			return null;
		}
		$row = $this->last_result[ (int) $row_offset ] ?? null;
		if ( null === $row ) {
			return null;
		}
		return $this->shape_row( $row, (string) $output );
	}

	/**
	 * Core: an error leaves last_result empty, so OBJECT returns [] (check last_error).
	 *
	 * @return array<int|string,mixed>
	 */
	public function get_results( $query, $output = OBJECT ) {
		if ( null === $this->execute( (string) $query ) ) {
			return [];
		}
		if ( OBJECT_K === $output ) {
			$out = [];
			foreach ( $this->last_result as $row ) {
				$vars = get_object_vars( $row );
				$key  = array_shift( $vars );
				if ( ! isset( $out[ $key ] ) ) {
					$out[ $key ] = $row;
				}
			}
			return $out;
		}
		$out = [];
		foreach ( $this->last_result as $row ) {
			$out[] = $this->shape_row( $row, (string) $output );
		}
		return $out;
	}

	public function get_var( $query ) {
		if ( null === $this->execute( (string) $query ) ) {
			return null;
		}
		$row = $this->last_result[0] ?? null;
		if ( null === $row ) {
			return null;
		}
		$values = array_values( get_object_vars( $row ) );
		return $values[0] ?? null;
	}

	public function get_col( $query, int $column = 0 ): array {
		if ( null === $this->execute( (string) $query ) ) {
			return [];
		}
		$out = [];
		foreach ( $this->last_result as $row ) {
			$values = array_values( get_object_vars( $row ) );
			$out[]  = $values[ $column ] ?? null;
		}
		return $out;
	}

	/** @return int|false */
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

		if ( null === $this->execute( $sql ) ) {
			return false;
		}
		return $this->rows_affected;
	}

	/**
	 * Run one statement: flush, error injection, rewrites, changed-rows emulation.
	 * Returns null on error (last_error set, print_error() called).
	 */
	private function execute( string $query ): ?PDOStatement {
		foreach ( $this->before_hooks as $i => $hook ) {
			if ( self::matches( $hook[0], $query ) ) {
				unset( $this->before_hooks[ $i ] );
				$this->before_hooks = array_values( $this->before_hooks );
				( $hook[1] )();
				break;
			}
		}

		$this->last_result   = [];
		$this->rows_affected = 0;
		$this->num_rows      = 0;
		$this->last_error    = '';
		$this->last_query    = $query;

		$injected = $this->take_failure( $query ) ?? self::mysql_syntax_error( $query );
		if ( null !== $injected ) {
			$this->last_error = $injected;
			$this->print_error();
			return null;
		}

		$sql               = 'mysql' === $this->driver ? $query : $this->rewrite( $query );
		$this->query_log[] = $sql;

		try {
			$this->mirror_user_tables( $sql );
			$changed = null;
			if ( $this->mysql_changed_rows && 'mysql' !== $this->driver ) {
				$changed = $this->changed_rows_update( $sql );
			}
			if ( null !== $changed ) {
				$stmt                = $changed['stmt'];
				$this->rows_affected = $changed['count'];
			} else {
				$stmt = $this->pdo->query( $sql );
				if ( false === $stmt ) {
					return null;
				}
				$this->rows_affected = $stmt->rowCount();
			}
			if ( preg_match( '/^\s*(insert|replace)\s/i', $sql ) ) {
				// An ignored INSERT IGNORE reports insert_id 0, as MySQL does.
				$this->insert_id = $this->rows_affected > 0 ? (int) $this->pdo->lastInsertId() : 0;
			}
			if ( $stmt->columnCount() > 0 ) {
				$this->last_result = $stmt->fetchAll( PDO::FETCH_OBJ );
				$this->num_rows    = count( $this->last_result );
			}
			return $stmt;
		} catch ( PDOException $e ) {
			$this->last_error = $e->getMessage();
			if ( preg_match( '/^\s*(insert|replace)\s/i', $sql ) ) {
				$this->insert_id = 0;
			}
			$this->print_error();
			return null;
		}
	}

	/**
	 * Users and user meta live in $magicauth_test_state; a query that names
	 * their tables sees a copy written just before it runs.
	 */
	private function mirror_user_tables( string $sql ): void {
		global $magicauth_test_state;
		$state = is_array( $magicauth_test_state ?? null ) ? $magicauth_test_state : [];
		$mysql = 'mysql' === $this->driver;

		if ( 1 === preg_match( '/\b' . preg_quote( $this->users, '/' ) . '\b/', $sql ) ) {
			$this->pdo->exec( "DROP TABLE IF EXISTS {$this->users}" );
			$this->pdo->exec(
				$mysql
					? "CREATE TABLE {$this->users} (ID bigint(20) unsigned NOT NULL, user_login varchar(60) NOT NULL DEFAULT '', user_email varchar(100) NOT NULL DEFAULT '', user_registered varchar(19) NOT NULL DEFAULT '', PRIMARY KEY (ID))"
					: "CREATE TABLE {$this->users} (ID INTEGER PRIMARY KEY, user_login TEXT NOT NULL DEFAULT '', user_email TEXT NOT NULL DEFAULT '', user_registered TEXT NOT NULL DEFAULT '')"
			);
			$insert = $this->pdo->prepare( "INSERT INTO {$this->users} (ID, user_login, user_email, user_registered) VALUES (?, ?, ?, ?)" );
			foreach ( (array) ( $state['users'] ?? [] ) as $id => $user ) {
				$insert->execute( [ (int) $id, (string) ( $user->user_login ?? '' ), (string) ( $user->user_email ?? '' ), (string) ( $user->user_registered ?? '' ) ] );
			}
		}

		if ( 1 === preg_match( '/\b' . preg_quote( $this->usermeta, '/' ) . '\b/', $sql ) ) {
			$this->pdo->exec( "DROP TABLE IF EXISTS {$this->usermeta}" );
			$this->pdo->exec(
				$mysql
					? "CREATE TABLE {$this->usermeta} (umeta_id bigint(20) unsigned NOT NULL AUTO_INCREMENT, user_id bigint(20) unsigned NOT NULL DEFAULT 0, meta_key varchar(255) DEFAULT NULL, meta_value longtext, PRIMARY KEY (umeta_id), KEY user_id (user_id), KEY meta_key (meta_key(191)))"
					: "CREATE TABLE {$this->usermeta} (umeta_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL DEFAULT 0, meta_key TEXT DEFAULT NULL, meta_value TEXT)"
			);
			$insert = $this->pdo->prepare( "INSERT INTO {$this->usermeta} (user_id, meta_key, meta_value) VALUES (?, ?, ?)" );
			foreach ( (array) ( $state['usermeta'] ?? [] ) as $id => $meta ) {
				foreach ( (array) $meta as $key => $value ) {
					$values = array_merge( [ $value ], (array) ( $state['usermeta_extra'][ $id ][ $key ] ?? [] ) );
					foreach ( $values as $one ) {
						$insert->execute( [ (int) $id, (string) $key, is_scalar( $one ) || null === $one ? (string) $one : serialize( $one ) ] ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize -- core's maybe_serialize().
					}
				}
			}
		}
	}

	private function take_failure( string $query ): ?string {
		foreach ( $this->fail_patterns as $i => $pattern ) {
			if ( self::matches( $pattern, $query ) ) {
				unset( $this->fail_patterns[ $i ] );
				$this->fail_patterns = array_values( $this->fail_patterns );
				return 'Injected failure for test (' . $pattern . ')';
			}
		}
		return null;
	}

	/** A pattern starting with '/' or '#' is a regex; anything else a case-insensitive substring. */
	private static function matches( string $pattern, string $query ): bool {
		$is_regex = '' !== $pattern && ( '/' === $pattern[0] || '#' === $pattern[0] );
		return $is_regex ? 1 === preg_match( $pattern, $query ) : false !== stripos( $query, $pattern );
	}

	/**
	 * A quoted literal (consumed whole, so words inside values never match),
	 * or LIKE with its quoted pattern and an explicit ESCAPE in group 1.
	 */
	private const LIKE_SCAN = "/'(?:[^']|'')*'|\\bLIKE\\s+'(?:[^']|'')*'(\\s*ESCAPE\\b)?/i";

	/** An explicit LIKE ... ESCAPE: rejected by the WordPress SQLite driver (see the header). */
	private static function mysql_syntax_error( string $query ): ?string {
		preg_match_all( self::LIKE_SCAN, $query, $m );
		foreach ( $m[1] as $escape ) {
			if ( '' !== $escape ) {
				return 'Explicit LIKE ... ESCAPE: a syntax error on the WordPress SQLite driver, which appends its own; MySQL already escapes with a backslash';
			}
		}
		return null;
	}

	/** MySQL statements SQLite rejects, rewritten to equivalents. */
	private function rewrite( string $sql ): string {
		$sql = (string) preg_replace( '/^(\s*)INSERT\s+IGNORE\s+INTO\b/i', '$1INSERT OR IGNORE INTO', $sql );

		// MySQL's default LIKE escape character is the backslash.
		$sql = (string) preg_replace_callback(
			self::LIKE_SCAN,
			static fn( array $m ): string => "'" === $m[0][0] ? $m[0] : $m[0] . " ESCAPE '" . chr( 92 ) . "'",
			$sql
		);

		if ( preg_match( '/^\s*DELETE\s+FROM\s+(\S+)\s+(.*)\bLIMIT\s+(\d+)\s*;?\s*$/is', $sql, $m ) ) {
			$table = $m[1];
			$rest  = trim( $m[2] );
			$sql   = sprintf(
				'DELETE FROM %1$s WHERE rowid IN (SELECT rowid FROM %1$s%2$s LIMIT %3$d)',
				$table,
				'' !== $rest ? ' ' . $rest : '',
				(int) $m[3]
			);
		}
		return $sql;
	}

	/**
	 * For an UPDATE: read the matched rows by rowid, run the UPDATE, re-read
	 * exactly those rowids and count the rows whose values differ. Re-running
	 * the WHERE afterwards would miss rows the UPDATE moved out of it.
	 *
	 * @return array{stmt:PDOStatement,count:int}|null Null when $sql is not an UPDATE.
	 */
	private function changed_rows_update( string $sql ): ?array {
		if ( ! preg_match( '/^\s*UPDATE\s+([`\w]+)\s+SET\s+/is', $sql, $m ) ) {
			return null;
		}
		$table = $m[1];
		$where = $this->top_level_where( $sql );

		$select = sprintf( 'SELECT rowid AS magicauth_rowid, * FROM %s%s', $table, '' !== $where ? ' WHERE ' . $where : '' );
		$before = [];
		foreach ( $this->pdo->query( $select )->fetchAll( PDO::FETCH_ASSOC ) as $row ) {
			$before[ (string) $row['magicauth_rowid'] ] = $row;
		}

		$stmt = $this->pdo->query( $sql );

		$count = 0;
		if ( [] !== $before ) {
			$ids   = implode( ',', array_map( 'intval', array_keys( $before ) ) );
			$after = $this->pdo->query( sprintf( 'SELECT rowid AS magicauth_rowid, * FROM %s WHERE rowid IN (%s)', $table, $ids ) )->fetchAll( PDO::FETCH_ASSOC );
			foreach ( $after as $row ) {
				$old = $before[ (string) $row['magicauth_rowid'] ] ?? null;
				if ( null === $old || self::normalise_row( $old ) !== self::normalise_row( $row ) ) {
					++$count;
				}
			}
		}
		return [
			'stmt'  => $stmt,
			'count' => $count,
		];
	}

	/** Text after the first WHERE keyword outside quotes and parentheses ('' when none). */
	private function top_level_where( string $sql ): string {
		$len   = strlen( $sql );
		$quote = '';
		$depth = 0;
		for ( $i = 0; $i < $len; $i++ ) {
			$c = $sql[ $i ];
			if ( '' !== $quote ) {
				if ( '\\' === $c ) {
					++$i;
				} elseif ( $c === $quote ) {
					$quote = '';
				}
				continue;
			}
			if ( "'" === $c || '"' === $c || '`' === $c ) {
				$quote = $c;
			} elseif ( '(' === $c ) {
				++$depth;
			} elseif ( ')' === $c ) {
				--$depth;
			} elseif ( 0 === $depth && preg_match( '/\GWHERE\b/i', $sql, $mm, 0, $i ) && ( 0 === $i || ! preg_match( '/\w/', $sql[ $i - 1 ] ) ) ) {
				return rtrim( trim( substr( $sql, $i + 5 ) ), ';' );
			}
		}
		return '';
	}

	/**
	 * @param array<string,mixed> $row
	 * @return array<string,string|null>
	 */
	private static function normalise_row( array $row ): array {
		unset( $row['magicauth_rowid'] );
		return array_map(
			static function ( $value ): ?string {
				return null === $value ? null : (string) $value;
			},
			$row
		);
	}

	/**
	 * @return object|array<mixed>
	 */
	private function shape_row( object $row, string $output ) {
		if ( ARRAY_A === $output ) {
			return get_object_vars( $row );
		}
		if ( ARRAY_N === $output ) {
			return array_values( get_object_vars( $row ) );
		}
		return $row;
	}
}

if ( ! defined( 'OBJECT' ) ) {
	define( 'OBJECT', 'OBJECT' );
}
if ( ! defined( 'OBJECT_K' ) ) {
	define( 'OBJECT_K', 'OBJECT_K' );
}
if ( ! defined( 'ARRAY_A' ) ) {
	define( 'ARRAY_A', 'ARRAY_A' );
}
if ( ! defined( 'ARRAY_N' ) ) {
	define( 'ARRAY_N', 'ARRAY_N' );
}
