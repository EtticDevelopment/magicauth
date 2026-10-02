<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Passkeys;

defined( 'ABSPATH' ) || exit;

/**
 * Mutable per-session state (SPEC 5.6): step-up stamp, prompt and signals
 * markers. Core's session record is written only at creation (D-30); this
 * table holds what changes afterwards. Rows are keyed by
 * Freshness::session_hash() and are read or written only while the core
 * record of the token exists, so a destroyed session never gets state again.
 * Each write is one statement on one row (no read-modify-write).
 */
final class SessionState {

	/** Columns set() may write. */
	private const SETTABLE = [ 'prompt_done', 'signals_at' ];

	/** Step-up methods (3.5). */
	private const REAUTH_METHODS = [ 'email_code', 'passkey' ];

	public static function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'magicauth_passkey_sessions';
	}

	/** The current session's row, or null (no session, record gone, no row, failed query). */
	public static function get(): ?object {
		global $wpdb;

		$key = self::current_key();
		if ( null === $key ) {
			return null;
		}
		$table = self::table();
		$prev  = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE session_hash = %s AND user_id = %d", $key['hash'], $key['user_id'] ) );
			if ( '' !== $wpdb->last_error ) {
				return null;
			}
		} finally {
			$wpdb->suppress_errors( $prev );
		}
		return is_object( $row ) ? $row : null;
	}

	/**
	 * Set prompt_done or signals_at for the current session.
	 *
	 * @param string $column prompt_done | signals_at.
	 * @param int    $value  New value (prompt_done 0 or 1).
	 */
	public static function set( string $column, int $value ): bool {
		global $wpdb;

		if ( ! in_array( $column, self::SETTABLE, true ) || $value < 0 || ( 'prompt_done' === $column && $value > 1 ) ) {
			return false;
		}
		$key = self::ensure();
		if ( null === $key ) {
			return false;
		}
		$table = self::table();
		$prev  = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table and column names are constants.
			$done = $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET {$column} = %d WHERE session_hash = %s", $value, $key['hash'] ) );
		} finally {
			$wpdb->suppress_errors( $prev );
		}
		return false !== $done;
	}

	/**
	 * Step-up stamp (3.2, 3.5): reauth_at, reauth_method and a new fresh_hash
	 * in one UPDATE, plus a new magicauth_pk_fresh cookie, sent only once the
	 * UPDATE changed the row (a failed stamp leaves the browser's cookie).
	 * reauth_at is $at, the time the proof was checked (never later than
	 * now), so 3.4 step 6 judges an email change against the proof.
	 *
	 * @param string   $method email_code | passkey.
	 * @param int|null $at     Unix time the proof was checked; null for now.
	 */
	public static function stamp_reauth( string $method, ?int $at = null ): bool {
		global $wpdb;

		if ( ! in_array( $method, self::REAUTH_METHODS, true ) ) {
			return false;
		}
		$key = self::ensure();
		if ( null === $key ) {
			return false;
		}
		$fresh     = Freshness::new_fresh_value();
		$table     = self::table();
		$reauth_at = null === $at ? Clock::now() : max( 1, min( $at, Clock::now() ) );
		$prev      = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$done = $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET reauth_at = %d, reauth_method = %s, fresh_hash = %s WHERE session_hash = %s", $reauth_at, $method, $fresh['hash'], $key['hash'] ) );
		} finally {
			$wpdb->suppress_errors( $prev );
		}
		if ( 1 !== $done ) {
			magicauth_debug_log( 'session state: step-up stamp failed' );
			return false;
		}
		Freshness::send_fresh_cookie( $fresh['value'] );
		return true;
	}

	/**
	 * Email change (7.6 rule M): no step-up stamp of the user survives, in
	 * one UPDATE over every session row of the user.
	 *
	 * @return int Rows changed; 0 on a failed query (logged).
	 */
	public static function clear_reauth_for_user( int $user_id ): int {
		global $wpdb;

		if ( $user_id <= 0 ) {
			return 0;
		}
		$table = self::table();
		$prev  = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$done = $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET reauth_at = 0, reauth_method = '', fresh_hash = '' WHERE user_id = %d", $user_id ) );
		} finally {
			$wpdb->suppress_errors( $prev );
		}
		if ( false === $done ) {
			magicauth_debug_log( 'session state: clear step-up failed' );
			return 0;
		}
		return (int) $done;
	}

	/**
	 * Every row of a user (delete_user, eraser, revoke-all).
	 *
	 * @return int Rows deleted; 0 on a failed query (logged).
	 */
	public static function delete_for_user( int $user_id ): int {
		global $wpdb;

		if ( $user_id <= 0 ) {
			return 0;
		}
		$table = self::table();
		$prev  = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$done = $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE user_id = %d", $user_id ) );
		} finally {
			$wpdb->suppress_errors( $prev );
		}
		if ( false === $done ) {
			magicauth_debug_log( 'session state: delete for user failed' );
			return 0;
		}
		return (int) $done;
	}

	/**
	 * Delete up to $limit rows whose session expired (daily cleanup).
	 *
	 * @return int Rows deleted.
	 */
	public static function purge_expired( int $limit ): int {
		global $wpdb;

		$table = self::table();
		$prev  = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$keys = $wpdb->get_col( $wpdb->prepare( "SELECT session_hash FROM {$table} WHERE expires_at < %s ORDER BY expires_at LIMIT %d", gmdate( 'Y-m-d H:i:s', Clock::now() ), max( 1, $limit ) ) );
			if ( '' !== $wpdb->last_error ) {
				magicauth_debug_log( 'session state: purge select failed' );
				return 0;
			}
			if ( [] === $keys ) {
				return 0;
			}
			$in = implode( ',', array_fill( 0, count( $keys ), '%s' ) );
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- one placeholder per key.
			$done = $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE session_hash IN ({$in})", $keys ) );
			if ( false === $done ) {
				magicauth_debug_log( 'session state: purge delete failed' );
				return 0;
			}
			return (int) $done;
		} finally {
			$wpdb->suppress_errors( $prev );
		}
	}

	/**
	 * Create the current session's row if missing. INSERT IGNORE: an existing
	 * row is the expected case (0 rows), only a failed query is an error.
	 * expires_at is the core record's expiration.
	 *
	 * @return array{hash:string,user_id:int}|null
	 */
	private static function ensure(): ?array {
		global $wpdb;

		$key = self::current_key();
		if ( null === $key ) {
			return null;
		}
		$table = self::table();
		$prev  = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$done = $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO {$table} (session_hash, user_id, expires_at) VALUES (%s, %d, %s)", $key['hash'], $key['user_id'], gmdate( 'Y-m-d H:i:s', $key['expiration'] ) ) );
		} finally {
			$wpdb->suppress_errors( $prev );
		}
		if ( false === $done ) {
			magicauth_debug_log( 'session state: insert failed' );
			return null;
		}
		return [
			'hash'    => $key['hash'],
			'user_id' => $key['user_id'],
		];
	}

	/**
	 * Key of the current session while its core record exists.
	 *
	 * @return array{hash:string,user_id:int,expiration:int}|null
	 */
	private static function current_key(): ?array {
		$hash = Freshness::session_hash();
		if ( '' === $hash ) {
			return null;
		}
		$session = Freshness::session();
		if ( null === $session ) {
			return null;
		}
		$expiration = isset( $session['expiration'] ) && is_int( $session['expiration'] ) ? $session['expiration'] : Clock::now();
		return [
			'hash'       => $hash,
			'user_id'    => get_current_user_id(),
			'expiration' => $expiration,
		];
	}
}
