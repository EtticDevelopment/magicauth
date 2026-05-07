<?php
/**
 * TokenManager: issue, validate (link/code), atomic consume, export, erase.
 *
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Auth;

use WP_Error;
use WP_User;

final class TokenManager {

	/** Generic-error code for every miss path. */
	public const ERROR_CODE = 'magicauth_invalid';

	private const SELECTOR_REGEX = '/^[0-9a-f]{16}$/';
	private const VERIFIER_REGEX = '/^[0-9a-f]{64}$/';

	/** Per-row code-attempt cap. Security floor; not admin-configurable. */
	private const CODE_ATTEMPT_CAP = 5;

	/**
	 * Issue a token. Invalidates outstanding rows for this email.
	 * Returns plaintext URL+code; only hashes are stored.
	 *
	 * @return array{link_url:string,code_plaintext:string,selector:string,expires_at:string}|WP_Error
	 */
	public static function issue( int $user_id, string $email ) {
		if ( $user_id <= 0 ) {
			return self::generic_error();
		}

		if ( get_user_meta( $user_id, 'magicauth_disabled', true ) ) {
			// Per-user disable: invalidate + refuse. Distinct error code lets
			// Controller show a one-shot notice; public UI envelope stays generic.
			$email_hmac = magicauth_hash_email( $email );
			self::invalidate_outstanding_for_email( $email_hmac );
			return new WP_Error(
				'magicauth_user_disabled',
				__( 'If an account exists for that email, we sent a sign-in link.', 'magicauth' )
			);
		}

		$email_hmac = magicauth_hash_email( $email );

		self::invalidate_outstanding_for_email( $email_hmac );

		$selector       = bin2hex( random_bytes( 8 ) );
		$link_plaintext = bin2hex( random_bytes( 32 ) );
		$code_plaintext = Crockford::encode_bytes( random_bytes( 5 ), 6 );

		$link_hash = hash_hmac( 'sha256', $link_plaintext, wp_salt( 'auth' ) );
		$code_hash = hash_hmac( 'sha256', Crockford::normalize( $code_plaintext ), wp_salt( 'auth' ) );

		$ttl_minutes = max( 1, min( 30, (int) magicauth_get_setting( 'ttl_minutes', 10 ) ) );
		$now         = current_time( 'mysql', true );
		$expires_at  = gmdate( 'Y-m-d H:i:s', time() + ( $ttl_minutes * MINUTE_IN_SECONDS ) );

		$ip_hmac = magicauth_hash_ip( magicauth_client_ip() );

		global $wpdb;
		$inserted = $wpdb->insert(
			self::table(),
			[
				'selector'           => $selector,
				'link_verifier_hash' => $link_hash,
				'code_verifier_hash' => $code_hash,
				'user_id'            => $user_id,
				'email_hmac'         => $email_hmac,
				'ip_hmac'            => $ip_hmac,
				'created_at'         => $now,
				'expires_at'         => $expires_at,
				'consumed_at'        => null,
				'use_count'          => 0,
				'code_attempts'      => 0,
			],
			[ '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%d', '%d' ]
		);

		if ( false === $inserted ) {
			magicauth_debug_log( 'TokenManager::issue insert failed' );
			return self::generic_error();
		}

		$verify_url = self::build_verify_url( $selector, $link_plaintext );

		do_action( 'magicauth_token_issued', $user_id, $selector );

		return [
			'link_url'       => $verify_url,
			'code_plaintext' => $code_plaintext,
			'selector'       => $selector,
			'expires_at'     => $expires_at,
		];
	}

	/**
	 * Validate a link click. Atomic increment-and-gate.
	 * First N clicks within TTL succeed; (N+1)th returns generic error.
	 * Once use_count > 0, the code path closes for this row.
	 *
	 * @return WP_User|WP_Error
	 */
	public static function validate_link( string $selector, string $verifier ) {
		if ( ! preg_match( self::SELECTOR_REGEX, $selector ) ) {
			return self::generic_error();
		}
		if ( ! preg_match( self::VERIFIER_REGEX, $verifier ) ) {
			return self::generic_error();
		}

		global $wpdb;
		$table = self::table();

		$row = $wpdb->get_row(
			$wpdb->prepare( "SELECT * FROM {$table} WHERE selector = %s", $selector ) // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		);

		// CVE-2025-12374 guard. Empty hashes never match.
		$link_stored = ( $row && ! empty( $row->link_verifier_hash ) ) ? (string) $row->link_verifier_hash : str_repeat( '0', 64 );
		$code_stored = ( $row && ! empty( $row->code_verifier_hash ) ) ? (string) $row->code_verifier_hash : str_repeat( '0', 64 );

		// Always compute both compares for timing parity; unused result discarded.
		$link_hash    = hash_hmac( 'sha256', $verifier, wp_salt( 'auth' ) );
		$code_dummy   = hash_hmac( 'sha256', '', wp_salt( 'auth' ) );
		$link_match   = hash_equals( $link_stored, $link_hash );
		$code_unused  = hash_equals( $code_stored, $code_dummy );
		unset( $code_unused );

		if ( ! $row ) {
			return self::generic_error();
		}
		if ( empty( $row->link_verifier_hash ) || empty( $row->code_verifier_hash ) ) {
			return self::generic_error();
		}
		if ( ! $link_match ) {
			return self::generic_error();
		}

		$max_uses = (int) magicauth_get_setting( 'max_link_uses', 2 );
		$max_uses = max( 1, min( 10, $max_uses ) );
		$now      = current_time( 'mysql', true );

		// Atomic increment-and-gate. Row lock serializes concurrent callers;
		// only $max_uses of them get $updated === 1.
		$updated = $wpdb->query(
			$wpdb->prepare(
				"UPDATE {$table} SET use_count = use_count + 1 " // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				. 'WHERE id = %d AND consumed_at IS NULL AND use_count < %d AND expires_at > %s',
				$row->id,
				$max_uses,
				$now
			)
		);

		if ( 1 !== (int) $updated ) {
			return self::generic_error();
		}

		$user = get_userdata( (int) $row->user_id );
		if ( ! $user instanceof WP_User ) {
			return self::generic_error();
		}

		do_action( 'magicauth_token_consumed', (int) $row->user_id, (string) $row->selector );

		return $user;
	}

	/**
	 * Validate a typed code. Single-use consume.
	 *
	 * Attempts counter lives in the session transient (v1.6.0). Empty selector
	 * means no row was issued for this session — refuse without DB work.
	 *
	 * @return WP_User|WP_Error
	 */
	public static function validate_code( string $email, string $code, string $session_id = '' ) {
		if ( ! Crockford::looks_valid( $code ) ) {
			return self::generic_error();
		}

		if ( '' === $session_id ) {
			return self::generic_error();
		}

		$session_key     = 'magicauth_session_' . $session_id;
		$session_payload = get_transient( $session_key );
		if ( ! is_array( $session_payload ) ) {
			return self::generic_error();
		}

		$selector = isset( $session_payload['selector'] ) ? (string) $session_payload['selector'] : '';
		$attempts = isset( $session_payload['attempts'] ) ? (int) $session_payload['attempts'] : 0;

		if ( $attempts >= self::CODE_ATTEMPT_CAP ) {
			return self::generic_error();
		}

		// Charge the attempt up front so an unknown-email session still costs
		// the attacker something even when there's no row to validate against.
		$session_payload['attempts'] = $attempts + 1;
		set_transient( $session_key, $session_payload, 30 * MINUTE_IN_SECONDS );

		if ( '' === $selector ) {
			return self::generic_error();
		}

		$normalized = Crockford::normalize( $code );
		$email_hmac = magicauth_hash_email( $email );
		$code_hash  = hash_hmac( 'sha256', $normalized, wp_salt( 'auth' ) );
		$now        = current_time( 'mysql', true );

		global $wpdb;
		$table = self::table();

		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE selector = %s AND email_hmac = %s AND consumed_at IS NULL AND use_count = 0 AND expires_at > %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$selector,
				$email_hmac,
				$now
			)
		);

		// CVE-2025-12374 guard: always run hash_equals so timing doesn't leak whether the row existed.
		$stored   = ( $row && ! empty( $row->code_verifier_hash ) ) ? (string) $row->code_verifier_hash : str_repeat( '0', 64 );
		$is_match = hash_equals( $stored, $code_hash );

		if ( ! $row || empty( $row->code_verifier_hash ) || ! $is_match ) {
			return self::generic_error();
		}

		$updated = $wpdb->query(
			$wpdb->prepare(
				"UPDATE {$table} SET consumed_at = %s WHERE id = %d AND consumed_at IS NULL AND use_count = 0 AND expires_at > %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$now,
				$row->id,
				$now
			)
		);

		if ( 1 !== (int) $updated ) {
			return self::generic_error();
		}

		$user = get_userdata( (int) $row->user_id );
		if ( ! $user instanceof WP_User ) {
			return self::generic_error();
		}

		// Successful auth: drop the session so a stale sid can't be reused.
		delete_transient( $session_key );

		do_action( 'magicauth_token_consumed', (int) $row->user_id, (string) $row->selector );

		return $user;
	}

	/**
	 * Mark every outstanding row for a user as consumed.
	 * Called by admin "Reset all" and per-user disable save.
	 */
	public static function invalidate_outstanding_for_user( int $user_id ): int {
		if ( $user_id <= 0 ) {
			return 0;
		}

		global $wpdb;
		$updated = $wpdb->query(
			$wpdb->prepare(
				'UPDATE ' . self::table() . ' SET consumed_at = %s WHERE user_id = %d AND consumed_at IS NULL',
				current_time( 'mysql', true ),
				$user_id
			)
		);

		return (int) $updated;
	}

	/**
	 * Mark every outstanding row for an email as consumed.
	 * Called pre-issue so a fresh request kills prior inbox tokens.
	 */
	public static function invalidate_outstanding_for_email( string $email_hmac ): int {
		if ( '' === $email_hmac ) {
			return 0;
		}

		global $wpdb;
		$updated = $wpdb->query(
			$wpdb->prepare(
				'UPDATE ' . self::table() . ' SET consumed_at = %s WHERE email_hmac = %s AND consumed_at IS NULL',
				current_time( 'mysql', true ),
				$email_hmac
			)
		);

		return (int) $updated;
	}

	/**
	 * Mark every outstanding row site-wide as consumed.
	 * Powers Settings → Diagnostics & Recovery → "Revoke all magic-links".
	 * Does NOT touch already-active auth cookies — only future token-consume.
	 */
	public static function invalidate_all_outstanding(): int {
		global $wpdb;
		$updated = $wpdb->query(
			$wpdb->prepare(
				'UPDATE ' . self::table() . ' SET consumed_at = %s WHERE consumed_at IS NULL',
				current_time( 'mysql', true )
			)
		);

		return (int) $updated;
	}

	/**
	 * Privacy exporter — non-secret metadata for a user.
	 *
	 * @return array{data:array<int,array<string,mixed>>,done:bool}
	 */
	public static function export( string $email_address, int $page = 1 ): array {
		unset( $page );
		$user = get_user_by( 'email', $email_address );
		if ( ! $user ) {
			return [
				'data' => [],
				'done' => true,
			];
		}

		global $wpdb;
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT selector, created_at, expires_at, consumed_at FROM ' . self::table() . ' WHERE user_id = %d ORDER BY created_at DESC',
				$user->ID
			)
		);

		$data = [];
		foreach ( (array) $rows as $row ) {
			$data[] = [
				'group_id'    => 'magicauth_tokens',
				'group_label' => __( 'MagicAuth sign-in tokens', 'magicauth' ),
				'item_id'     => 'magicauth-' . $row->selector,
				'data'        => [
					[
						'name'  => __( 'Selector', 'magicauth' ),
						'value' => $row->selector,
					],
					[
						'name'  => __( 'Issued', 'magicauth' ),
						'value' => $row->created_at,
					],
					[
						'name'  => __( 'Expires', 'magicauth' ),
						'value' => $row->expires_at,
					],
					[
						'name'  => __( 'Consumed', 'magicauth' ),
						'value' => $row->consumed_at ?? __( 'not yet', 'magicauth' ),
					],
				],
			];
		}

		return [
			'data' => $data,
			'done' => true,
		];
	}

	/**
	 * Privacy eraser — delete every row for the user, plus throttle counters.
	 *
	 * @return array{items_removed:bool,items_retained:bool,messages:array<int,string>,done:bool}
	 */
	public static function erase( string $email_address, int $page = 1 ): array {
		unset( $page );
		$user = get_user_by( 'email', $email_address );
		if ( ! $user ) {
			return [
				'items_removed'  => false,
				'items_retained' => false,
				'messages'       => [],
				'done'           => true,
			];
		}

		global $wpdb;
		$deleted = $wpdb->query(
			$wpdb->prepare(
				'DELETE FROM ' . self::table() . ' WHERE user_id = %d',
				$user->ID
			)
		);

		Throttle::reset_for_email( magicauth_hash_email( $email_address ) );

		return [
			'items_removed'  => (int) $deleted > 0,
			'items_retained' => false,
			'messages'       => [],
			'done'           => true,
		];
	}

	/** Generic-error WP_Error. Identical for every miss path. */
	public static function generic_error(): WP_Error {
		return new WP_Error(
			self::ERROR_CODE,
			__( 'If an account exists for that email, we sent a sign-in link.', 'magicauth' )
		);
	}

	/** Build the public verify URL. */
	public static function build_verify_url( string $selector, string $link_plaintext ): string {
		$base = function_exists( 'home_url' ) ? home_url( '/' ) : '/';
		return add_query_arg(
			[
				'magicauth' => 'verify',
				's'         => $selector,
				'v'         => $link_plaintext,
			],
			$base
		);
	}

	/** Fully-qualified table name. */
	public static function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'magicauth_requests';
	}
}
