<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Passkeys;

defined( 'ABSPATH' ) || exit;

use MagicAuth\Installer;
use WP_Error;
use WP_User;

/**
 * Credential rows and the per-user WebAuthn user handle (SPEC 5.1, 5.3).
 *
 * Every query that decides a security outcome is tri-state: a failed query is
 * a WP_Error (or null), never "not found" (D-32). Per-user reads also match
 * the user's current user_registered string against the row's snapshot, so a
 * row left by a former holder of a reused user ID is invisible (7.6 rule X),
 * and skip rows created at or before the last email change (7.6 rule M
 * backstop, revoked()); deletes match by user_id only. Every query runs with
 * errors suppressed.
 */
final class CredentialStore {

	/** find_by_raw_id() result for a credential that is not stored. */
	public const NOT_FOUND = 'not_found';

	/** User meta holding the base64url WebAuthn user handle. */
	public const HANDLE_META = 'magicauth_passkey_user_handle';

	/** Meta removed with the user (delete_user on single site, wpmu_delete_user). */
	private const USER_META = [
		self::HANDLE_META,
		'magicauth_passkey_prompt',
		'magicauth_passkey_details_at',
		'magicauth_email_verified_at',
		'magicauth_email_changed_at',
	];

	private const TRANSPORTS = [ 'usb', 'nfc', 'ble', 'smart-card', 'hybrid', 'internal' ];

	private const ALGS = [ -7, -8, -257 ];

	/** Columns a caller may set on insert; credential_hash and created_at are the store's. */
	private const INSERT_COLUMNS = [
		'user_id',
		'rp_id',
		'credential_id',
		'user_handle',
		'public_key',
		'alg',
		'sign_count',
		'backup_eligible',
		'backup_state',
		'transports',
		'aaguid',
		'name',
		'user_registered',
	];

	public static function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'magicauth_passkeys';
	}

	/**
	 * Store a verified credential (R-12, R-13). Duplicate check by
	 * credential_hash across all users before the INSERT.
	 *
	 * @param array<string,mixed> $record Columns of INSERT_COLUMNS.
	 * @return int|WP_Error Row id. Codes: magicauth_invalid_record, magicauth_duplicate_credential, magicauth_db_error.
	 */
	public static function insert( array $record ) {
		global $wpdb;

		$row = self::validate_record( $record );
		if ( null === $row ) {
			return new WP_Error( 'magicauth_invalid_record' );
		}
		$raw_id = (string) Base64Url::decode( (string) $row['credential_id'], 16, 1023 );

		$found = self::find_by_raw_id( $raw_id );
		if ( $found instanceof WP_Error ) {
			return $found;
		}
		if ( self::NOT_FOUND !== $found ) {
			return new WP_Error( 'magicauth_duplicate_credential' );
		}

		$row['credential_hash'] = hash( 'sha256', $raw_id );
		$row['created_at']      = gmdate( 'Y-m-d H:i:s', Clock::now() );

		$formats = [];
		foreach ( $row as $value ) {
			$formats[] = is_int( $value ) ? '%d' : '%s';
		}

		$prev = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- own table, one row per registration.
			$inserted = $wpdb->insert( self::table(), $row, $formats );
		} finally {
			$wpdb->suppress_errors( $prev );
		}
		if ( 1 !== $inserted ) {
			magicauth_debug_log( 'passkeys: insert failed' );
			return new WP_Error( 'magicauth_db_error' );
		}
		return (int) $wpdb->insert_id;
	}

	/**
	 * Credential by raw ID (any user), through credential_hash (A-4, R-13).
	 *
	 * @return object|string|WP_Error The row, NOT_FOUND, or magicauth_db_error.
	 */
	public static function find_by_raw_id( string $raw_id ) {
		global $wpdb;

		if ( '' === $raw_id ) {
			return self::NOT_FOUND;
		}
		$table = self::table();
		$prev  = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE credential_hash = %s", hash( 'sha256', $raw_id ) ) );
			if ( '' !== $wpdb->last_error ) {
				return new WP_Error( 'magicauth_db_error' );
			}
		} finally {
			$wpdb->suppress_errors( $prev );
		}
		return is_object( $row ) ? $row : self::NOT_FOUND;
	}

	/**
	 * Whether MagicAuth ever issued this user handle to any user (A-4, after a
	 * confirmed not-found). Decides the unknown-credential flag, nothing else.
	 *
	 * @param string $user_handle base64url user handle from the assertion.
	 * @return bool|WP_Error
	 */
	public static function handle_issued( string $user_handle ) {
		global $wpdb;

		if ( '' === $user_handle ) {
			return false;
		}
		$prev = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.SlowDBQuery.slow_db_query_meta_key,WordPress.DB.SlowDBQuery.slow_db_query_meta_value -- one indexed lookup, after a not-found only.
			$found = $wpdb->get_var( $wpdb->prepare( "SELECT user_id FROM {$wpdb->usermeta} WHERE meta_key = %s AND meta_value = %s LIMIT 1", self::HANDLE_META, $user_handle ) );
			if ( '' !== $wpdb->last_error ) {
				return new WP_Error( 'magicauth_db_error' );
			}
		} finally {
			$wpdb->suppress_errors( $prev );
		}
		return null !== $found;
	}

	/**
	 * The user's credentials, oldest first, optionally for one RP ID. Rows
	 * whose user_registered snapshot differs from the user's, and rows rule M
	 * revoked (revoked()), are skipped; the privacy exporter keeps the latter
	 * (still stored, still the account's data).
	 *
	 * @param WP_User $user    Owner.
	 * @param string  $rp_id   Only this RP ID; '' for all.
	 * @param bool    $revoked Also rows rule M revoked (export only).
	 * @return array<int,object>|null Null on a failed query.
	 */
	public static function for_user( WP_User $user, string $rp_id = '', bool $revoked = false ): ?array {
		global $wpdb;

		$registered = (string) $user->user_registered;
		if ( (int) $user->ID <= 0 || '' === $registered ) {
			return [];
		}
		$table = self::table();
		$sql   = "SELECT * FROM {$table} WHERE user_id = %d AND user_registered = %s";
		$args  = [ (int) $user->ID, $registered ];
		if ( '' !== $rp_id ) {
			$sql   .= ' AND rp_id = %s';
			$args[] = $rp_id;
		}
		$sql .= ' ORDER BY created_at ASC, id ASC';

		$prev = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- built from constants and placeholders above.
			$rows = $wpdb->get_results( $wpdb->prepare( $sql, $args ) );
			if ( '' !== $wpdb->last_error ) {
				return null;
			}
		} finally {
			$wpdb->suppress_errors( $prev );
		}
		$changed = $revoked ? 0 : self::email_changed_at( (int) $user->ID );
		$out     = [];
		foreach ( (array) $rows as $row ) {
			if ( is_object( $row ) && ! self::created_by( $row, $changed ) ) {
				$out[] = $row;
			}
		}
		return $out;
	}

	/**
	 * Count of the user's credentials (snapshot and rule M as for_user()).
	 *
	 * @param WP_User $user  Owner.
	 * @param string  $rp_id Only this RP ID; '' for all.
	 * @return int|null Null on a failed query.
	 */
	public static function count_for_user( WP_User $user, string $rp_id = '' ): ?int {
		global $wpdb;

		$registered = (string) $user->user_registered;
		if ( (int) $user->ID <= 0 || '' === $registered ) {
			return 0;
		}
		$table = self::table();
		$sql   = "SELECT COUNT(*) FROM {$table} WHERE user_id = %d AND user_registered = %s";
		$args  = [ (int) $user->ID, $registered ];
		if ( '' !== $rp_id ) {
			$sql   .= ' AND rp_id = %s';
			$args[] = $rp_id;
		}
		$changed = self::email_changed_at( (int) $user->ID );
		if ( $changed > 0 ) {
			$sql   .= ' AND created_at > %s';
			$args[] = gmdate( 'Y-m-d H:i:s', $changed );
		}

		$prev = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- built from constants and placeholders above.
			$count = $wpdb->get_var( $wpdb->prepare( $sql, $args ) );
			if ( '' !== $wpdb->last_error ) {
				return null;
			}
		} finally {
			$wpdb->suppress_errors( $prev );
		}
		return (int) $count;
	}

	/** Credentials stored on this site (diagnostics); null on a failed query. */
	public static function site_count(): ?int {
		global $wpdb;

		$table = self::table();
		$prev  = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$count = $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );
			if ( '' !== $wpdb->last_error ) {
				return null;
			}
		} finally {
			$wpdb->suppress_errors( $prev );
		}
		return (int) $count;
	}

	/**
	 * Rename a credential of its owner (6.6). $name comes sanitised
	 * (Presenter::sanitize_name()); a name equal, case-insensitively, to
	 * another of the owner's passkeys is refused. Only rows of the user's
	 * user_registered snapshot count (7.6 rule X, as for_user()): a former ID
	 * holder's row, or one rule M revoked, neither blocks a name nor is found. Success is decided by
	 * the row existing for ( id, user_id ), never by the affected-rows count
	 * (an unchanged name changes 0 rows on MySQL).
	 *
	 * @return true|WP_Error Codes: magicauth_not_found, magicauth_invalid_name, magicauth_duplicate_name, magicauth_db_error.
	 */
	public static function rename( int $user_id, int $id, string $name ) {
		global $wpdb;

		if ( '' === $name || mb_strlen( $name ) > 64 ) {
			return new WP_Error( 'magicauth_invalid_name' );
		}
		if ( $user_id <= 0 || $id <= 0 ) {
			return new WP_Error( 'magicauth_not_found' );
		}
		$user       = get_userdata( $user_id );
		$registered = $user instanceof WP_User ? (string) $user->user_registered : '';
		if ( '' === $registered ) {
			return new WP_Error( 'magicauth_not_found' );
		}
		$table = self::table();
		$prev  = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT id, name, created_at FROM {$table} WHERE user_id = %d AND user_registered = %s", $user_id, $registered ) );
			if ( '' !== $wpdb->last_error ) {
				return new WP_Error( 'magicauth_db_error' );
			}
			$found   = false;
			$lower   = Presenter::name_key( $name );
			$changed = self::email_changed_at( $user_id );
			foreach ( (array) $rows as $row ) {
				if ( self::created_by( $row, $changed ) ) {
					continue;
				} elseif ( (int) $row->id === $id ) {
					$found = true;
				} elseif ( Presenter::name_key( (string) $row->name ) === $lower ) {
					return new WP_Error( 'magicauth_duplicate_name' );
				}
			}
			if ( ! $found ) {
				return new WP_Error( 'magicauth_not_found' );
			}
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$done = $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET name = %s WHERE id = %d AND user_id = %d", $name, $id, $user_id ) );
			if ( false === $done ) {
				return new WP_Error( 'magicauth_db_error' );
			}
		} finally {
			$wpdb->suppress_errors( $prev );
		}
		return true;
	}

	/**
	 * Delete one credential of its owner; another user's id is not found (IDOR).
	 *
	 * @return true|WP_Error Codes: magicauth_not_found, magicauth_db_error.
	 */
	public static function delete( int $user_id, int $id ) {
		global $wpdb;

		if ( $user_id <= 0 || $id <= 0 ) {
			return new WP_Error( 'magicauth_not_found' );
		}
		$table = self::table();
		$prev  = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$done = $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE id = %d AND user_id = %d", $id, $user_id ) );
		} finally {
			$wpdb->suppress_errors( $prev );
		}
		if ( false === $done ) {
			return new WP_Error( 'magicauth_db_error' );
		}
		return 1 === $done ? true : new WP_Error( 'magicauth_not_found' );
	}

	/**
	 * Whether row $id of $user_id is still stored (6.3, after the completion
	 * token is issued: a removal that ran before it existed did not purge it).
	 *
	 * @return bool|null Null on a failed query.
	 */
	public static function still_stored( int $user_id, int $id ): ?bool {
		global $wpdb;

		if ( $user_id <= 0 || $id <= 0 ) {
			return false;
		}
		$table = self::table();
		$prev  = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$found = $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$table} WHERE id = %d AND user_id = %d", $id, $user_id ) );
			if ( '' !== $wpdb->last_error ) {
				return null;
			}
		} finally {
			$wpdb->suppress_errors( $prev );
		}
		return null !== $found;
	}

	/**
	 * Every credential of a user id, snapshot or not (revoke-all, delete_user,
	 * eraser, email change).
	 *
	 * @return int|WP_Error Rows deleted, or magicauth_db_error.
	 */
	public static function delete_all_for_user( int $user_id ) {
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
			magicauth_debug_log( 'passkeys: delete for user failed' );
			return new WP_Error( 'magicauth_db_error' );
		}
		return (int) $done;
	}

	/**
	 * The account's last email change (rule M, 7.6), 0 when none. Network-wide
	 * user meta, so it also covers the tables of every other site.
	 */
	public static function email_changed_at( int $user_id ): int {
		if ( $user_id <= 0 ) {
			return 0;
		}
		return max( 0, (int) get_user_meta( $user_id, 'magicauth_email_changed_at', true ) );
	}

	/**
	 * Rule M backstop (7.6): true for a row created at or before the owner's
	 * last email change. Such a row proves only the old mailbox: rule M's
	 * DELETE failed, a registration's INSERT raced it, or it ran on another
	 * site of the network. A row registered after the change is always
	 * later: R-11 refuses a challenge issued at or before it. Fails closed on
	 * an unreadable created_at.
	 */
	public static function revoked( object $row ): bool {
		return self::created_by( $row, self::email_changed_at( (int) ( $row->user_id ?? 0 ) ) );
	}

	/**
	 * Delete the user's rows rule M revoked (revoked()), lazily, when one is
	 * presented. A failure is logged only: the row stays refused.
	 */
	public static function purge_revoked( int $user_id ): void {
		global $wpdb;

		$changed = self::email_changed_at( $user_id );
		if ( $changed <= 0 ) {
			return;
		}
		$table = self::table();
		$prev  = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$done = $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE user_id = %d AND created_at <= %s", $user_id, gmdate( 'Y-m-d H:i:s', $changed ) ) );
		} finally {
			$wpdb->suppress_errors( $prev );
		}
		if ( false === $done ) {
			magicauth_debug_log( 'passkeys: purge of revoked rows failed' );
		}
	}

	/**
	 * Counter compare-and-swap (7.6): raises sign_count only. The caller
	 * requires 1 for a device-bound credential.
	 *
	 * @return int|false Rows changed, or false on a failed query.
	 */
	public static function advance_counter( int $id, int $sign_count ) {
		global $wpdb;

		$table = self::table();
		$prev  = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$done = $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET sign_count = %d WHERE id = %d AND sign_count < %d", $sign_count, $id, $sign_count ) );
		} finally {
			$wpdb->suppress_errors( $prev );
		}
		return false === $done ? false : (int) $done;
	}

	/**
	 * Block a credential after a BE=0 counter regression (7.6). 1 only for the
	 * request that blocked it, so the blocked email goes once.
	 *
	 * @return int|false Rows changed, or false on a failed query.
	 */
	public static function block( int $id ) {
		global $wpdb;

		$table = self::table();
		$prev  = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$done = $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET counter_anomaly_at = %s WHERE id = %d AND counter_anomaly_at IS NULL", gmdate( 'Y-m-d H:i:s', Clock::now() ), $id ) );
		} finally {
			$wpdb->suppress_errors( $prev );
		}
		return false === $done ? false : (int) $done;
	}

	/** Usage after a verified assertion: backup state and last use. Result is not a success signal (a no-op on MySQL can be 0). */
	public static function record_use( int $id, bool $backup_state ): bool {
		global $wpdb;

		$table = self::table();
		$prev  = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$done = $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET backup_state = %d, last_used_at = %s WHERE id = %d", $backup_state ? 1 : 0, gmdate( 'Y-m-d H:i:s', Clock::now() ), $id ) );
		} finally {
			$wpdb->suppress_errors( $prev );
		}
		return false !== $done;
	}

	/**
	 * The user's WebAuthn user handle (5.3), created on demand: 64 random
	 * bytes, unique across users, race-safe. Core's add_user_meta( unique )
	 * is a COUNT then an INSERT, so after adding, the meta is re-read and
	 * every value but the earliest inserted is deleted. Earliest, not the
	 * smallest: a concurrent caller that re-read before a later insert has
	 * already returned its own value, and that value is the earliest one, so
	 * every caller ends with the same handle in every interleaving. Null when
	 * it does not exist (and $create is false) or cannot be created.
	 */
	public static function user_handle( int $user_id, bool $create ): ?string {
		if ( $user_id <= 0 ) {
			return null;
		}
		$have = self::handles( $user_id );
		if ( [] !== $have ) {
			return $have[0];
		}
		if ( ! $create ) {
			return null;
		}

		$handle = null;
		for ( $i = 0; $i < 3 && null === $handle; $i++ ) {
			$candidate = Base64Url::encode( random_bytes( 64 ) );
			$taken     = get_users(
				[
					'meta_key'   => self::HANDLE_META, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
					'meta_value' => $candidate, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value
					'fields'     => 'ID',
					'number'     => 1,
				]
			);
			if ( [] === $taken ) {
				$handle = $candidate;
			}
		}
		if ( null === $handle ) {
			magicauth_debug_log( 'passkeys: no unique user handle' );
			return null;
		}

		add_user_meta( $user_id, self::HANDLE_META, $handle, true );
		wp_cache_delete( $user_id, 'user_meta' );

		$have = self::handles( $user_id );
		if ( [] === $have ) {
			return null;
		}
		foreach ( array_slice( $have, 1 ) as $other ) {
			delete_user_meta( $user_id, self::HANDLE_META, $other );
		}
		return $have[0];
	}

	/**
	 * delete_user (4.6): credential, challenge and session state rows, the
	 * requests rows (B10) and, on single site, the user's passkey and email
	 * meta. On multisite the hook fires when the user is removed from this
	 * site, so only this site's rows go; network-wide meta stays
	 * (wpmu_delete_user removes it).
	 *
	 * @param int $user_id ID of the user being deleted.
	 */
	public static function on_delete_user( int $user_id ): void {
		if ( $user_id <= 0 ) {
			return;
		}
		self::delete_site_rows( $user_id );
		if ( ! is_multisite() ) {
			self::delete_user_meta( $user_id );
		}
	}

	/**
	 * wpmu_delete_user (multisite, 4.6). Core's wpmu_delete_user() removes
	 * the user from each site without firing delete_user, so this deletes
	 * the per-site rows of the current site and of every site the user
	 * belongs to (still listed: the hook fires first), then the network-wide
	 * user meta. Rows on a site the user never belonged to go with that
	 * site's daily sweep.
	 *
	 * @param int $user_id ID of the user being deleted from the network.
	 */
	public static function on_wpmu_delete_user( int $user_id ): void {
		if ( $user_id <= 0 ) {
			return;
		}
		self::delete_site_rows( $user_id );
		if ( is_multisite() && function_exists( 'get_blogs_of_user' ) && function_exists( 'switch_to_blog' ) ) {
			$current = get_current_blog_id();
			foreach ( (array) get_blogs_of_user( $user_id, true ) as $blog ) {
				$blog_id = is_object( $blog ) ? (int) ( $blog->userblog_id ?? 0 ) : 0;
				if ( $blog_id <= 0 || $blog_id === $current ) {
					continue;
				}
				switch_to_blog( $blog_id );
				try {
					self::delete_site_rows( $user_id );
				} finally {
					restore_current_blog();
				}
			}
		}
		self::delete_user_meta( $user_id );
	}

	/** This site's credential, challenge, session state and requests rows of the user. */
	private static function delete_site_rows( int $user_id ): void {
		self::delete_all_for_user( $user_id );
		ChallengeStore::delete_for_user( $user_id );
		SessionState::delete_for_user( $user_id );
		Installer::on_delete_user( $user_id );
	}

	private static function delete_user_meta( int $user_id ): void {
		foreach ( self::USER_META as $key ) {
			delete_user_meta( $user_id, $key );
		}
	}

	/**
	 * Valid handles in the user's meta, earliest inserted first (core reads
	 * meta ordered by umeta_id).
	 *
	 * @return array<int,string>
	 */
	private static function handles( int $user_id ): array {
		$values = get_user_meta( $user_id, self::HANDLE_META, false );
		$out    = [];
		foreach ( is_array( $values ) ? $values : [] as $value ) {
			if ( is_string( $value ) && 1 === preg_match( '/^[A-Za-z0-9_-]{86}$/', $value ) ) {
				$out[] = $value;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Typed insert row, or null when a value is out of range.
	 *
	 * @param array<string,mixed> $record
	 * @return array<string,int|string>|null
	 */
	private static function validate_record( array $record ): ?array {
		if ( [] !== array_diff( array_keys( $record ), self::INSERT_COLUMNS ) ) {
			return null;
		}
		$row = [
			'user_id'         => $record['user_id'] ?? null,
			'rp_id'           => $record['rp_id'] ?? null,
			'credential_id'   => $record['credential_id'] ?? null,
			'user_handle'     => $record['user_handle'] ?? null,
			'public_key'      => $record['public_key'] ?? null,
			'alg'             => $record['alg'] ?? null,
			'sign_count'      => $record['sign_count'] ?? 0,
			'backup_eligible' => ! empty( $record['backup_eligible'] ) ? 1 : 0,
			'backup_state'    => ! empty( $record['backup_state'] ) ? 1 : 0,
			'transports'      => $record['transports'] ?? '',
			'aaguid'          => $record['aaguid'] ?? '',
			'name'            => $record['name'] ?? '',
			'user_registered' => $record['user_registered'] ?? null,
		];

		$ints = is_int( $row['user_id'] ) && $row['user_id'] > 0
			&& is_int( $row['alg'] ) && in_array( $row['alg'], self::ALGS, true )
			&& is_int( $row['sign_count'] ) && $row['sign_count'] >= 0 && $row['sign_count'] <= 4294967295;
		$strings = is_string( $row['rp_id'] ) && '' !== $row['rp_id'] && strlen( $row['rp_id'] ) <= 253
			&& is_string( $row['credential_id'] ) && null !== Base64Url::decode( $row['credential_id'], 16, 1023 )
			&& is_string( $row['user_handle'] ) && null !== Base64Url::decode( $row['user_handle'], 1, 64 )
			&& is_string( $row['public_key'] ) && '' !== $row['public_key']
			&& is_string( $row['name'] ) && mb_strlen( $row['name'] ) <= 64
			&& is_string( $row['user_registered'] ) && 1 === preg_match( '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $row['user_registered'] )
			&& is_string( $row['aaguid'] ) && ( '' === $row['aaguid'] || 1 === preg_match( '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $row['aaguid'] ) )
			&& is_string( $row['transports'] ) && self::transports_ok( $row['transports'] );
		if ( ! $ints || ! $strings ) {
			return null;
		}
		/** @var array<string,int|string> $row */
		return $row;
	}

	/** Whether $row was created at or before $changed (0: no change, false). */
	private static function created_by( object $row, int $changed ): bool {
		if ( $changed <= 0 ) {
			return false;
		}
		$created = (string) ( $row->created_at ?? '' );
		$time    = 1 === preg_match( '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $created ) ? strtotime( $created . ' UTC' ) : false;
		return false === $time || $time <= $changed;
	}

	/** '' or comma-separated, allowlisted, unique transports. */
	private static function transports_ok( string $transports ): bool {
		if ( '' === $transports ) {
			return true;
		}
		$list = explode( ',', $transports );
		return count( $list ) <= count( self::TRANSPORTS )
			&& count( $list ) === count( array_unique( $list ) )
			&& [] === array_diff( $list, self::TRANSPORTS );
	}
}
