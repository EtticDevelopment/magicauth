<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Passkeys;

defined( 'ABSPATH' ) || exit;

use MagicAuth\Auth\Crockford;
use WP_Error;

/**
 * Challenges, completion tokens and step-up codes (SPEC 5.2, 7.5, 6.7).
 *
 * Only keyed hashes are stored: the ceremony is inside the lookup HMAC, so a
 * value issued for one ceremony is unusable for another. Every row is
 * consumed at most once by an atomic UPDATE; callers compare bindings after
 * consume(), so a mismatch still burns the row. Every query runs with errors
 * suppressed (nothing printed into a JSON body); a failed query is reported
 * as such, never as "not found" (D-32).
 */
final class ChallengeStore {

	public const CEREMONIES = [ 'signin', 'complete', 'register', 'reauth', 'reauth_code' ];

	/** Seconds from issue to expiry (5.2). TTL >= options timeout + 60 s for the browser ceremonies. */
	public const TTL = [
		'signin'      => 600,
		'complete'    => 120,
		'register'    => 420,
		'reauth'      => 420,
		'reauth_code' => 600,
	];

	/** Ceremonies bound to a signed-in session (user and session hash). */
	private const SESSION_BOUND = [ 'register', 'reauth', 'reauth_code' ];

	/** Ceremonies bound to the magicauth_pk_bind cookie. */
	private const COOKIE_BOUND = [ 'signin', 'complete' ];

	/** Attempts per step-up code row. */
	public const CODE_ATTEMPTS = 5;

	public static function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'magicauth_passkey_challenges';
	}

	/**
	 * Store a new challenge. Refused (no row) for a session-bound ceremony
	 * without a session hash or user, and for a cookie-bound one without a
	 * binding value; 'complete' also needs its user.
	 *
	 * @param string $ceremony     One of CEREMONIES.
	 * @param int    $user_id      Owner, 0 for signin.
	 * @param string $session_hash Freshness::session_hash() for session-bound ceremonies.
	 * @param string $binding_raw  magicauth_pk_bind cookie value for cookie-bound ceremonies.
	 * @param string $algs         Offered COSE algs, e.g. '-7,-8,-257' (register).
	 * @param int    $ttl          Seconds until expiry.
	 * @param string $user_handle  Handle sent in user.id (register).
	 * @return string|WP_Error The raw 32-byte challenge.
	 */
	public static function issue( string $ceremony, int $user_id, string $session_hash, string $binding_raw, string $algs, int $ttl, string $user_handle = '' ) {
		$raw = random_bytes( 32 );
		$ok  = self::insert( $ceremony, $raw, $user_id, $session_hash, $binding_raw, '', $algs, $ttl, $user_handle );
		return true === $ok ? $raw : $ok;
	}

	/**
	 * Email step-up code: a 16-byte reauth_id and a 6-character Crockford code
	 * bound to user and session, TTL 600 s (3.5).
	 *
	 * @return array{0:string,1:string}|WP_Error [ reauth_id_raw, code ].
	 */
	public static function issue_code( int $user_id, string $session_hash ) {
		$reauth_id = random_bytes( 16 );
		$code      = Crockford::encode_bytes( random_bytes( 5 ), 6 );
		$ok        = self::insert( 'reauth_code', $reauth_id, $user_id, $session_hash, '', self::code_hmac( $code ), '', self::TTL['reauth_code'] );
		return true === $ok ? [ $reauth_id, $code ] : $ok;
	}

	/**
	 * Single use, whatever the outcome (7.5). On null, $reason is 'missing'
	 * (no row for this ceremony), 'replayed' (already consumed, or a
	 * concurrent consume won), 'expired' or 'error' (a query failed; callers
	 * answer 503 retry).
	 *
	 * @param string  $ceremony      One of CEREMONIES.
	 * @param string  $challenge_raw Raw challenge or token.
	 * @param ?string $reason        Set when null is returned.
	 */
	public static function consume( string $ceremony, string $challenge_raw, ?string &$reason = null ): ?object {
		global $wpdb;

		$reason = null;
		if ( ! in_array( $ceremony, self::CEREMONIES, true ) || '' === $challenge_raw ) {
			$reason = 'missing';
			return null;
		}

		$table = self::table();
		$now   = self::now_mysql();
		$prev  = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE lookup_hash = %s AND ceremony = %s", self::lookup_hash( $ceremony, $challenge_raw ), $ceremony ) );
			if ( '' !== $wpdb->last_error ) {
				$reason = 'error';
				return null;
			}
			if ( ! is_object( $row ) ) {
				$reason = 'missing';
				return null;
			}

			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$updated = $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET consumed_at = %s WHERE id = %d AND consumed_at IS NULL AND expires_at > %s", $now, (int) $row->id, $now ) );
			if ( 1 === $updated ) {
				$row->consumed_at = $now;
				return $row;
			}
			if ( false === $updated ) {
				$reason = 'error';
			} elseif ( null !== $row->consumed_at || (string) $row->expires_at > $now ) {
				$reason = 'replayed';
			} else {
				$reason = 'expired';
			}
			return null;
		} finally {
			$wpdb->suppress_errors( $prev );
		}
	}

	/**
	 * Read-only: whether the row of this challenge was consumed (7.3 orphan
	 * flag condition 1). False for no row or an unconsumed one; WP_Error when
	 * the query failed (callers answer 503 retry, no flag).
	 *
	 * @param string $ceremony      One of CEREMONIES.
	 * @param string $challenge_raw Raw challenge.
	 * @return bool|WP_Error
	 */
	public static function consumed( string $ceremony, string $challenge_raw ) {
		global $wpdb;

		if ( ! in_array( $ceremony, self::CEREMONIES, true ) || '' === $challenge_raw ) {
			return false;
		}

		$table = self::table();
		$prev  = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE lookup_hash = %s AND ceremony = %s", self::lookup_hash( $ceremony, $challenge_raw ), $ceremony ) );
			if ( '' !== $wpdb->last_error ) {
				return new WP_Error( 'magicauth_db_error' );
			}
			return is_object( $row ) && null !== $row->consumed_at;
		} finally {
			$wpdb->suppress_errors( $prev );
		}
	}

	/**
	 * Email step-up code (6.7): the attempt is charged atomically before the
	 * constant-time compare, then the row is consumed atomically. False for
	 * every refusal; WP_Error when a query failed (callers answer 503 retry,
	 * so a database error never reads as a wrong code). Never true without
	 * the consume.
	 *
	 * @param string $reauth_id_raw 16-byte reauth_id.
	 * @param string $code          Code as typed.
	 * @param int    $user_id       Current user.
	 * @param string $session_hash  Freshness::session_hash().
	 * @param int    $issued_at     Set to the code's issue time (Unix) on success, else 0.
	 * @return bool|WP_Error
	 */
	public static function verify_code( string $reauth_id_raw, string $code, int $user_id, string $session_hash, int &$issued_at = 0 ) {
		global $wpdb;

		$issued_at = 0;
		if ( '' === $session_hash || $user_id <= 0 || '' === $reauth_id_raw ) {
			return false;
		}

		$table = self::table();
		$now   = self::now_mysql();
		$prev  = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE lookup_hash = %s AND ceremony = %s", self::lookup_hash( 'reauth_code', $reauth_id_raw ), 'reauth_code' ) );
			if ( '' !== $wpdb->last_error ) {
				return new WP_Error( 'magicauth_db_error' );
			}

			$owner = is_object( $row )
				&& self::binding_matches( (string) $row->user_id, (string) $user_id )
				&& self::binding_matches( (string) $row->session_hash, $session_hash );
			if ( ! $owner ) {
				// Timing parity with a real compare.
				$unused = hash_equals( str_repeat( '0', 64 ), self::code_hmac( $code ) );
				unset( $unused );
				return false;
			}

			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$charged = $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET attempts = attempts + 1 WHERE id = %d AND attempts < %d AND consumed_at IS NULL AND expires_at > %s", (int) $row->id, self::CODE_ATTEMPTS, $now ) );
			if ( false === $charged ) {
				return new WP_Error( 'magicauth_db_error' );
			}
			if ( 1 !== $charged ) {
				return false;
			}

			$stored = (string) $row->secret_hash;
			if ( '' === $stored || ! hash_equals( $stored, self::code_hmac( $code ) ) ) {
				return false;
			}

			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$consumed = $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET consumed_at = %s WHERE id = %d AND consumed_at IS NULL AND expires_at > %s", $now, (int) $row->id, $now ) );
			if ( false === $consumed ) {
				return new WP_Error( 'magicauth_db_error' );
			}
			if ( 1 !== $consumed ) {
				return false;
			}
			$issued_at = self::created_at( $row );
			return true;
		} finally {
			$wpdb->suppress_errors( $prev );
		}
	}

	/**
	 * A row's created_at as Unix time; 0 when unreadable (callers fail closed).
	 *
	 * @param object $row Challenge row.
	 */
	public static function created_at( object $row ): int {
		$created = (string) ( $row->created_at ?? '' );
		$time    = 1 === preg_match( '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $created ) ? strtotime( $created . ' UTC' ) : false;
		return false === $time ? 0 : max( 0, $time );
	}

	/**
	 * Binding comparison for session_hash, binding_hash and user ids: fails
	 * when either side is '', before hash_equals (5.2).
	 *
	 * @param string $stored Value from the row.
	 * @param string $given  Value of this request.
	 */
	public static function binding_matches( string $stored, string $given ): bool {
		if ( '' === $stored || '' === $given ) {
			return false;
		}
		return hash_equals( $stored, $given );
	}

	/** binding_hash of a magicauth_pk_bind cookie value; '' for ''. */
	public static function binding_hash( string $cookie_value ): string {
		if ( '' === $cookie_value ) {
			return '';
		}
		return self::hmac( 'magicauth-passkey-bind|' . $cookie_value );
	}

	/**
	 * Delete up to $limit rows that expired more than $grace seconds ago.
	 * SELECT ids then DELETE ... IN (portable; SQLite rejects DELETE ... LIMIT).
	 * Security never depends on it: consume() checks expires_at.
	 *
	 * @param int $limit Maximum rows.
	 * @param int $grace Seconds past expiry before a row goes (daily cleanup: one hour).
	 * @return int Rows deleted.
	 */
	public static function purge_expired( int $limit, int $grace = 0 ): int {
		global $wpdb;

		$table  = self::table();
		$cutoff = gmdate( 'Y-m-d H:i:s', Clock::now() - max( 0, $grace ) );
		$prev   = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$ids = $wpdb->get_col( $wpdb->prepare( "SELECT id FROM {$table} WHERE expires_at < %s ORDER BY expires_at LIMIT %d", $cutoff, max( 1, $limit ) ) );
			if ( '' !== $wpdb->last_error ) {
				magicauth_debug_log( 'challenges: purge select failed' );
				return 0;
			}
			if ( [] === $ids ) {
				return 0;
			}
			$in = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- one placeholder per id.
			$done = $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE id IN ({$in})", $ids ) );
			if ( false === $done ) {
				magicauth_debug_log( 'challenges: purge delete failed' );
				return 0;
			}
			return (int) $done;
		} finally {
			$wpdb->suppress_errors( $prev );
		}
	}

	/**
	 * Every row of a user, any ceremony (delete_user, eraser, revoke-all,
	 * email change).
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
			magicauth_debug_log( 'challenges: delete for user failed' );
			return 0;
		}
		return (int) $done;
	}

	/**
	 * The user's unspent completion tokens (6.13), when one passkey is
	 * removed: a token verified with it must not sign in afterwards.
	 *
	 * @return int Rows deleted; 0 on a failed query (logged).
	 */
	public static function delete_completions_for_user( int $user_id ): int {
		global $wpdb;

		if ( $user_id <= 0 ) {
			return 0;
		}
		$table = self::table();
		$prev  = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$done = $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE user_id = %d AND ceremony = %s", $user_id, 'complete' ) );
		} finally {
			$wpdb->suppress_errors( $prev );
		}
		if ( false === $done ) {
			magicauth_debug_log( 'challenges: delete completions failed' );
			return 0;
		}
		return (int) $done;
	}

	/**
	 * @return true|WP_Error
	 */
	private static function insert( string $ceremony, string $raw, int $user_id, string $session_hash, string $binding_raw, string $secret_hash, string $algs, int $ttl, string $user_handle = '' ) {
		global $wpdb;

		$refuse = ! in_array( $ceremony, self::CEREMONIES, true ) || $ttl <= 0 || $user_id < 0
			|| ( in_array( $ceremony, self::SESSION_BOUND, true ) && ( '' === $session_hash || $user_id <= 0 ) )
			|| ( in_array( $ceremony, self::COOKIE_BOUND, true ) && '' === $binding_raw )
			|| ( 'complete' === $ceremony && $user_id <= 0 )
			|| strlen( $algs ) > 32 || strlen( $user_handle ) > 88;
		if ( $refuse ) {
			return new WP_Error( 'magicauth_challenge_refused' );
		}

		$now  = Clock::now();
		$prev = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- own table, written once per ceremony.
			$inserted = $wpdb->insert(
				self::table(),
				[
					'lookup_hash'  => self::lookup_hash( $ceremony, $raw ),
					'ceremony'     => $ceremony,
					'user_id'      => $user_id,
					'session_hash' => $session_hash,
					'binding_hash' => self::binding_hash( $binding_raw ),
					'secret_hash'  => $secret_hash,
					'user_handle'  => $user_handle,
					'algs'         => $algs,
					'attempts'     => 0,
					'created_at'   => gmdate( 'Y-m-d H:i:s', $now ),
					'expires_at'   => gmdate( 'Y-m-d H:i:s', $now + $ttl ),
				],
				[ '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s' ]
			);
		} finally {
			$wpdb->suppress_errors( $prev );
		}
		if ( 1 !== $inserted ) {
			magicauth_debug_log( 'challenges: insert failed' );
			return new WP_Error( 'magicauth_unavailable' );
		}
		return true;
	}

	private static function lookup_hash( string $ceremony, string $raw ): string {
		return self::hmac( 'magicauth-passkey|' . $ceremony . '|' . $raw );
	}

	private static function code_hmac( string $code ): string {
		return self::hmac( 'magicauth-passkey-code|' . Crockford::normalize( $code ) );
	}

	private static function hmac( string $data ): string {
		return hash_hmac( 'sha256', $data, wp_salt( 'auth' ) );
	}

	private static function now_mysql(): string {
		return gmdate( 'Y-m-d H:i:s', Clock::now() );
	}
}
