<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Passkeys;

defined( 'ABSPATH' ) || exit;

use MagicAuth\Auth\Login;
use MagicAuth\ThirdParty\Passkeys\Attestation\AuthenticatorData;
use MagicAuth\ThirdParty\Passkeys\WebAuthn;
use WP_Error;
use WP_User;

/**
 * Registration and sign-in verification (SPEC 7.3, 7.4): the W1 to W9 wrapper
 * around the vendored library. Size caps and strict base64url before any
 * decoding (W1, W2), our own clientData checks (W3), challenges consumed
 * before use (W4), the library with UV and UP required on a fresh instance
 * (W5), our checks on its result (W6, W7), options never built by the
 * library (W8, Options), every library call inside catch ( \Throwable ) (W9).
 *
 * Failures are WP_Error objects whose code is the response code (6.10) and
 * whose data holds: status (HTTP), unknown_credential (the orphan or unknown
 * credential flag, 7.3 and 7.4 A-4), and for sign-in reason (for
 * magicauth_passkey_signin_failed), counted (counts toward passkey_fail_ip:
 * only after A-3 and never for a database error), user_id and blocked_now
 * (this request blocked the credential: send the blocked email, 7.6).
 * Nothing is echoed and no exception escapes; endpoints build the bodies.
 */
final class Verifier {

	/** W1: the credential form field. */
	public const MAX_CREDENTIAL = 24576;

	private const JSON_DEPTH_CREDENTIAL = 6;

	private const JSON_DEPTH_CLIENT_DATA = 4;

	private const MAX_CLIENT_DATA = 4096;

	private const MAX_ATTESTATION = 16384;

	private const MIN_AUTH_DATA = 37;

	private const MAX_AUTH_DATA = 1024;

	private const MAX_SIGNATURE = 512;

	private const MAX_TRANSPORT_INPUTS = 8;

	private const TRANSPORTS = [ 'usb', 'nfc', 'ble', 'smart-card', 'hybrid', 'internal' ];

	/** SubjectPublicKeyInfo prefix of an Ed25519 key (RFC 8410). */
	private const ED25519_SPKI_PREFIX = '302a300506032b6570032100';

	/** authData flag AT: attested credential data; never set in an assertion. */
	private const FLAG_AT = 0x40;

	/**
	 * R-11 issue time of each register challenge verified in this request,
	 * by credential_id, for store_registration()'s rule M re-check.
	 *
	 * @var array<string,int>
	 */
	private static $issued = [];

	/**
	 * Our own clientDataJSON checks (R-4, A-2; W3): valid UTF-8 JSON object
	 * (depth 4, so a BOM or array fails); type exactly $type; challenge a
	 * canonical base64url string of 32 bytes; origin exactly the allowed
	 * origin; crossOrigin absent or false; topOrigin absent. Other members are
	 * allowed (clients may add some).
	 *
	 * @param string $bytes clientDataJSON as received.
	 * @param string $type  webauthn.create or webauthn.get.
	 * @return array{challenge:string,origin:string}|null Raw challenge and origin.
	 */
	public static function client_data( string $bytes, string $type ): ?array {
		if ( '' === $bytes || strlen( $bytes ) > self::MAX_CLIENT_DATA || 1 !== preg_match( '//u', $bytes ) ) {
			return null;
		}
		$data = json_decode( $bytes, false, self::JSON_DEPTH_CLIENT_DATA );
		if ( ! $data instanceof \stdClass ) {
			return null;
		}
		$vars = get_object_vars( $data );

		if ( ! isset( $vars['type'] ) || ! is_string( $vars['type'] ) || $type !== $vars['type'] ) {
			return null;
		}
		if ( ! isset( $vars['challenge'] ) || ! is_string( $vars['challenge'] ) ) {
			return null;
		}
		$challenge = Base64Url::decode( $vars['challenge'], 32, 32 );
		if ( null === $challenge ) {
			return null;
		}
		if ( ! isset( $vars['origin'] ) || ! is_string( $vars['origin'] ) || ! RelyingParty::origin_allowed( $vars['origin'] ) ) {
			return null;
		}
		if ( array_key_exists( 'crossOrigin', $vars ) && false !== $vars['crossOrigin'] ) {
			return null;
		}
		if ( array_key_exists( 'topOrigin', $vars ) ) {
			return null;
		}
		return [
			'challenge' => $challenge,
			'origin'    => $vars['origin'],
		];
	}

	/**
	 * Registration verification, R-1 to R-12 (7.3). Returns the record to
	 * store with store_registration(), or a WP_Error: registration_failed
	 * (400), limit_reached (409), duplicate_name (400) or retry (503). Every
	 * failure after R-2 carries unknown_credential: true when the challenge
	 * was not replayed and a successful query proved the credential absent.
	 *
	 * @param string  $credential   The credential field (toJSON() string, unslashed).
	 * @param WP_User $user         Signed-in user.
	 * @param string  $session_hash Freshness::session_hash().
	 * @param string  $name         User-chosen name ('' for the default).
	 * @param string  $platform     Client platform hint (4.8).
	 * @param string  $user_agent   HTTP_USER_AGENT, for the default name only.
	 * @return array<string,mixed>|WP_Error
	 */
	public static function verify_registration( string $credential, WP_User $user, string $session_hash, string $name = '', string $platform = '', string $user_agent = '' ) {
		// R-1, R-2: no trusted credential ID before these pass, so no flag.
		$parsed = self::parse_credential( $credential );
		if ( null === $parsed ) {
			return self::error( 'registration_failed', 400 );
		}

		$reason = null;
		$result = self::registration_checks( $parsed['json'], $parsed['raw_id'], $user, $session_hash, $name, $platform, $user_agent, $reason );
		if ( ! $result instanceof WP_Error ) {
			return $result;
		}
		return self::registration_failure( $result, $parsed['raw_id'], $reason );
	}

	/**
	 * R-13: store a record from verify_registration(). The store's SELECT by
	 * credential_hash (any user) runs before the INSERT; a duplicate never
	 * carries the flag (the ID may belong to a stored, valid credential), and
	 * a database error is 503 retry. After the INSERT the email change time
	 * is read again: a change at or after the challenge was issued (rule M
	 * raced R-11) deletes the row and fails, with the orphan flag rule; when
	 * that DELETE leaves the row, it is blocked and the answer is 503 retry.
	 *
	 * @param array<string,mixed> $record From verify_registration().
	 * @return int|WP_Error Row id, or registration_failed (400) / retry (503).
	 */
	public static function store_registration( array $record ) {
		$credential_id = is_string( $record['credential_id'] ?? null ) ? $record['credential_id'] : '';
		$issued_at     = self::$issued[ $credential_id ] ?? null;
		unset( self::$issued[ $credential_id ] );

		$id = CredentialStore::insert( $record );
		if ( $id instanceof WP_Error ) {
			if ( 'magicauth_db_error' === $id->get_error_code() ) {
				return self::error( 'retry', 503 );
			}
			return self::error( 'registration_failed', 400 );
		}

		// Rule M after R-11 (7.6): an email change between the check and the
		// INSERT. Re-read from the database, not this request's meta cache.
		$user_id = (int) $record['user_id'];
		wp_cache_delete( $user_id, 'user_meta' );
		$changed = CredentialStore::email_changed_at( $user_id );
		if ( $changed > 0 && $changed >= ( $issued_at ?? Clock::now() ) ) {
			// Fail closed: a row that may survive is blocked (A-10 and step-up
			// refuse it) and the answer is retry, never a 400 over a live row.
			$deleted = CredentialStore::delete( $user_id, $id );
			if ( true !== $deleted && false !== CredentialStore::still_stored( $user_id, $id ) ) {
				CredentialStore::block( $id );
				return self::error( 'retry', 503 );
			}
			return self::registration_failure( self::error( 'registration_failed', 400 ), (string) Base64Url::decode( $credential_id, 16, 1023 ), null );
		}
		return $id;
	}

	/**
	 * Orphan flag for a registration refused as throttled (7.3): true only
	 * when the clientDataJSON passes R-3 and R-4 and names a register
	 * challenge that this check consumes (so it was not consumed before: no
	 * replay, condition 1) and that is bound to this user and session, and a
	 * successful query proves the ID is not stored (condition 2). Anything
	 * else is false with no credential lookup, so the throttled endpoint is
	 * no oracle: each lookup costs one register challenge (passkey_reg_user).
	 *
	 * @param string  $credential   The credential field.
	 * @param WP_User $user         Signed-in user.
	 * @param string  $session_hash Freshness::session_hash().
	 * @return bool|WP_Error WP_Error when a query failed (503, no flag).
	 */
	public static function unknown_credential_flag( string $credential, WP_User $user, string $session_hash ) {
		$parsed = self::parse_credential( $credential );
		if ( null === $parsed ) {
			return false;
		}
		$response = $parsed['json']['response'] ?? null;
		$cdj      = is_array( $response ) ? self::field( $response, 'clientDataJSON', 1, self::MAX_CLIENT_DATA ) : null;
		$client   = null === $cdj ? null : self::client_data( $cdj, 'webauthn.create' );
		if ( null === $client ) {
			return false;
		}
		$reason = null;
		$row    = ChallengeStore::consume( 'register', $client['challenge'], $reason );
		if ( null === $row ) {
			return 'error' === $reason ? new WP_Error( 'magicauth_db_error' ) : false;
		}
		if ( ! ChallengeStore::binding_matches( (string) $row->user_id, (string) $user->ID ) || ! ChallengeStore::binding_matches( (string) $row->session_hash, $session_hash ) ) {
			return false;
		}
		return self::absent( $parsed['raw_id'] );
	}

	/**
	 * Sign-in assertion verification, A-1 to A-11 (7.4). A-0 (gates), A-12
	 * (completion token) and A-13 (redirect, action) are the endpoint's. On
	 * success the counter, backup state and last use are written.
	 *
	 * @param string $credential  The credential field (toJSON() string, unslashed).
	 * @param string $bind_cookie This request's magicauth_pk_bind cookie value.
	 * @return array{user:WP_User,row:object}|WP_Error passkey_failed (400), retry (503), other_account (409), reverify_required (403).
	 */
	public static function verify_assertion( string $credential, string $bind_cookie ) {
		// A-1.
		$parsed = self::parse_credential( $credential );
		if ( null === $parsed ) {
			return self::signin_error( 'malformed', false );
		}
		$raw_id   = $parsed['raw_id'];
		$response = $parsed['json']['response'] ?? null;
		if ( ! is_array( $response ) ) {
			return self::signin_error( 'malformed', false );
		}
		$auth_data = self::field( $response, 'authenticatorData', self::MIN_AUTH_DATA, self::MAX_AUTH_DATA );
		$signature = self::field( $response, 'signature', 1, self::MAX_SIGNATURE );
		$cdj       = self::field( $response, 'clientDataJSON', 1, self::MAX_CLIENT_DATA );
		$handle    = isset( $response['userHandle'] ) && is_string( $response['userHandle'] ) ? $response['userHandle'] : '';
		if ( null === $auth_data || null === $signature || null === $cdj || null === Base64Url::decode( $handle, 1, 64 ) ) {
			return self::signin_error( 'malformed', false );
		}
		// AT is never set in an assertion: keep attacker bytes out of the COSE parser.
		if ( 0 !== ( ord( $auth_data[32] ) & self::FLAG_AT ) ) {
			return self::signin_error( 'malformed', false );
		}

		// A-2.
		$client = self::client_data( $cdj, 'webauthn.get' );
		if ( null === $client ) {
			return self::signin_error( 'client_data', false );
		}

		// A-3: consumed whatever the outcome; binding compared after.
		$reason = null;
		$row    = ChallengeStore::consume( 'signin', $client['challenge'], $reason );
		if ( null === $row ) {
			return 'error' === $reason ? self::retry() : self::signin_error( 'challenge', false );
		}
		$cookie = 1 === preg_match( '/^[0-9a-f]{64}$/', $bind_cookie ) ? $bind_cookie : '';
		if ( ! ChallengeStore::binding_matches( (string) $row->binding_hash, ChallengeStore::binding_hash( $cookie ) ) ) {
			return self::signin_error( 'binding', false );
		}

		// A-4. From here on, failures count (never a database error).
		$cred = CredentialStore::find_by_raw_id( $raw_id );
		if ( $cred instanceof WP_Error ) {
			return self::retry();
		}
		if ( ! is_object( $cred ) ) {
			// Flag only for a handle MagicAuth issued (S8e residual: other apps on the host).
			$issued = CredentialStore::handle_issued( $handle );
			if ( $issued instanceof WP_Error ) {
				return self::retry();
			}
			return self::signin_error( 'unknown_credential', true, [ 'unknown_credential' => true === $issued ] );
		}
		$user_id = (int) $cred->user_id;

		// A-5.
		$rp_id = RelyingParty::id();
		if ( '' === $rp_id || (string) $cred->rp_id !== $rp_id ) {
			return self::signin_error( 'rp_id', true, [ 'user_id' => $user_id ] );
		}

		// A-6.
		if ( ! hash_equals( (string) $cred->user_handle, $handle ) ) {
			return self::signin_error( 'user_handle', true, [ 'user_id' => $user_id ] );
		}

		// A-7: counter policy is ours (prevSignatureCnt null).
		try {
			$ok = ( new WebAuthn( $rp_id, $rp_id, true ) )->processGet( $cdj, $auth_data, $signature, (string) $cred->public_key, $client['challenge'], null, true, true );
		} catch ( \Throwable $e ) {
			$ok = false;
		}
		if ( true !== $ok ) {
			return self::signin_error( 'signature', true, [ 'user_id' => $user_id ] );
		}

		// A-8: second check of UP and UV; BE must never change (7.2/19).
		try {
			$ad = new AuthenticatorData( $auth_data );
		} catch ( \Throwable $e ) {
			return self::signin_error( 'flags', true, [ 'user_id' => $user_id ] );
		}
		$be = (bool) $ad->getIsBackupEligible();
		if ( true !== $ad->getUserPresent() || true !== $ad->getUserVerified() || ( (bool) $ad->getIsBackup() && ! $be ) || (int) $be !== (int) $cred->backup_eligible ) {
			return self::signin_error( 'flags', true, [ 'user_id' => $user_id ] );
		}

		// A-9: account, the user_registered snapshot (7.6 rule X), rule M, preflight.
		$user = get_userdata( $user_id );
		if ( ! $user instanceof WP_User ) {
			return self::signin_error( 'account', true, [ 'user_id' => $user_id ] );
		}
		$snapshot = (string) $cred->user_registered;
		if ( '' === $snapshot || ! hash_equals( $snapshot, (string) $user->user_registered ) ) {
			return self::signin_error( 'account_mismatch', true, [ 'user_id' => $user_id ] );
		}
		// Rule M backstop (7.6): created at or before the last email change.
		if ( CredentialStore::revoked( $cred ) ) {
			CredentialStore::purge_revoked( $user_id );
			return self::signin_error( 'account_mismatch', true, [ 'user_id' => $user_id ] );
		}
		$pre = Login::preflight( $user, 'passkey' );
		if ( $pre instanceof WP_Error ) {
			// The key holder proved possession at A-7: no guessing signal, so
			// these two never count toward passkey_fail_ip (6.3).
			switch ( $pre->get_error_code() ) {
				case 'magicauth_other_account':
					return self::error( 'other_account', 409, self::signin_data( 'other_account', false, [ 'user_id' => $user_id ] ) );
				case 'magicauth_reverify_required':
					return self::error( 'reverify_required', 403, self::signin_data( 'reverify_required', false, [ 'user_id' => $user_id ] ) );
				default:
					return self::signin_error( 'account', true, [ 'user_id' => $user_id ] );
			}
		}

		// A-10, A-11.
		$counter = self::apply_counter_policy( $cred, (int) $ad->getSignCount(), (bool) $ad->getIsBackup() );
		if ( $counter instanceof WP_Error ) {
			return $counter;
		}

		return [
			'user' => $user,
			'row'  => $cred,
		];
	}

	/**
	 * Step-up assertion (7.4 last paragraph): A-1 with an optional
	 * userHandle, A-2, A-3 on a reauth challenge bound to user and session,
	 * A-4 (NOT_FOUND flagged), A-5, owner and allow list and snapshot and
	 * the rule M backstop, A-6
	 * only with a userHandle, A-7, A-8, A-10, A-11. No preflight and no auth
	 * cookie: the user is signed in.
	 *
	 * The allow list is recomputed here: the rows reauth_options lists are the
	 * user's credentials for this RP ID with the current snapshot and no
	 * counter anomaly, and the reauth row has no column to store them.
	 *
	 * @param string  $credential   The credential field (toJSON() string, unslashed).
	 * @param WP_User $user         Signed-in user.
	 * @param string  $session_hash Freshness::session_hash().
	 * @return object|WP_Error The credential row, or reauth_failed (400, optional flag, blocked_now) / retry (503).
	 */
	public static function verify_step_up( string $credential, WP_User $user, string $session_hash ) {
		$fail = self::error( 'reauth_failed', 400, [ 'blocked_now' => false ] );

		// A-1, userHandle optional.
		$parsed = self::parse_credential( $credential );
		if ( null === $parsed ) {
			return $fail;
		}
		$raw_id   = $parsed['raw_id'];
		$response = $parsed['json']['response'] ?? null;
		if ( ! is_array( $response ) ) {
			return $fail;
		}
		$auth_data = self::field( $response, 'authenticatorData', self::MIN_AUTH_DATA, self::MAX_AUTH_DATA );
		$signature = self::field( $response, 'signature', 1, self::MAX_SIGNATURE );
		$cdj       = self::field( $response, 'clientDataJSON', 1, self::MAX_CLIENT_DATA );
		if ( null === $auth_data || null === $signature || null === $cdj ) {
			return $fail;
		}
		$handle = $response['userHandle'] ?? null;
		if ( null !== $handle && ( ! is_string( $handle ) || null === Base64Url::decode( $handle, 1, 64 ) ) ) {
			return $fail;
		}
		if ( 0 !== ( ord( $auth_data[32] ) & self::FLAG_AT ) ) {
			return $fail;
		}

		// A-2.
		$client = self::client_data( $cdj, 'webauthn.get' );
		if ( null === $client ) {
			return $fail;
		}

		// A-3: consumed whatever the outcome; bound to user and session.
		$reason = null;
		$row    = ChallengeStore::consume( 'reauth', $client['challenge'], $reason );
		if ( null === $row ) {
			return 'error' === $reason ? self::retry() : $fail;
		}
		if ( ! ChallengeStore::binding_matches( (string) $row->user_id, (string) $user->ID ) || ! ChallengeStore::binding_matches( (string) $row->session_hash, $session_hash ) ) {
			return $fail;
		}

		// A-4: a confirmed not-found carries the flag.
		$cred = CredentialStore::find_by_raw_id( $raw_id );
		if ( $cred instanceof WP_Error ) {
			return self::retry();
		}
		if ( ! is_object( $cred ) ) {
			return self::error(
				'reauth_failed',
				400,
				[
					'unknown_credential' => true,
					'blocked_now'        => false,
				]
			);
		}

		// A-5.
		$rp_id = RelyingParty::id();
		if ( '' === $rp_id || (string) $cred->rp_id !== $rp_id ) {
			return $fail;
		}

		// Owner, allow list (no counter anomaly) and the user_registered snapshot (A-9 rule).
		$snapshot = (string) $cred->user_registered;
		if ( (int) $cred->user_id !== (int) $user->ID || null !== $cred->counter_anomaly_at
			|| '' === $snapshot || ! hash_equals( $snapshot, (string) $user->user_registered ) ) {
			return $fail;
		}
		// Rule M backstop (7.6), as A-9.
		if ( CredentialStore::revoked( $cred ) ) {
			CredentialStore::purge_revoked( (int) $user->ID );
			return $fail;
		}

		// A-6, only when the authenticator returned a handle.
		if ( null !== $handle && ! hash_equals( (string) $cred->user_handle, $handle ) ) {
			return $fail;
		}

		// A-7.
		try {
			$ok = ( new WebAuthn( $rp_id, $rp_id, true ) )->processGet( $cdj, $auth_data, $signature, (string) $cred->public_key, $client['challenge'], null, true, true );
		} catch ( \Throwable $e ) {
			$ok = false;
		}
		if ( true !== $ok ) {
			return $fail;
		}

		// A-8.
		try {
			$ad = new AuthenticatorData( $auth_data );
		} catch ( \Throwable $e ) {
			return $fail;
		}
		$be = (bool) $ad->getIsBackupEligible();
		if ( true !== $ad->getUserPresent() || true !== $ad->getUserVerified() || ( (bool) $ad->getIsBackup() && ! $be ) || (int) $be !== (int) $cred->backup_eligible ) {
			return $fail;
		}

		// A-10, A-11. Sign-in failures map to reauth_failed; blocked_now is kept.
		$counter = self::apply_counter_policy( $cred, (int) $ad->getSignCount(), (bool) $ad->getIsBackup() );
		if ( $counter instanceof WP_Error ) {
			if ( 'retry' === $counter->get_error_code() ) {
				return $counter;
			}
			$data = (array) $counter->get_error_data();
			return self::error(
				'reauth_failed',
				400,
				[
					'blocked_now' => ! empty( $data['blocked_now'] ),
					'row_id'      => (int) ( $data['row_id'] ?? 0 ),
				]
			);
		}
		return $cred;
	}

	/**
	 * R-3 to R-12. On failure $reason holds consume()'s reason when the
	 * challenge step ran (the flag depends on it).
	 *
	 * @param array<string,mixed> $json
	 * @return array<string,mixed>|WP_Error
	 */
	private static function registration_checks( array $json, string $raw_id, WP_User $user, string $session_hash, string $name, string $platform, string $user_agent, ?string &$reason ) {
		$fail = self::error( 'registration_failed', 400 );

		// R-3.
		$response = $json['response'] ?? null;
		if ( ! is_array( $response ) ) {
			return $fail;
		}
		$cdj = self::field( $response, 'clientDataJSON', 1, self::MAX_CLIENT_DATA );
		$att = self::field( $response, 'attestationObject', 1, self::MAX_ATTESTATION );
		if ( null === $cdj || null === $att ) {
			return $fail;
		}

		// R-4.
		$client = self::client_data( $cdj, 'webauthn.create' );
		if ( null === $client ) {
			return $fail;
		}

		// R-5: consumed whatever the outcome; binding compared after.
		$row = ChallengeStore::consume( 'register', $client['challenge'], $reason );
		if ( null === $row ) {
			return 'error' === $reason ? self::retry() : $fail;
		}
		if ( ! ChallengeStore::binding_matches( (string) $row->user_id, (string) $user->ID ) || ! ChallengeStore::binding_matches( (string) $row->session_hash, $session_hash ) ) {
			return $fail;
		}

		// R-6.
		$rp_id = RelyingParty::id();
		if ( '' === $rp_id ) {
			return $fail;
		}
		try {
			$data = ( new WebAuthn( $rp_id, $rp_id, true ) )->processCreate( $cdj, $att, $client['challenge'], true, true );
		} catch ( \Throwable $e ) {
			return $fail;
		}

		// R-7.
		if ( ! is_string( $data->credentialId ?? null ) || ! hash_equals( $data->credentialId, $raw_id ) ) {
			return $fail;
		}

		// R-8: the alg was offered for this challenge.
		$alg     = $data->credentialAlg ?? null;
		$offered = array_map( 'intval', explode( ',', (string) $row->algs ) );
		if ( ! is_int( $alg ) || '' === (string) $row->algs || ! in_array( $alg, $offered, true ) ) {
			return $fail;
		}

		// R-9.
		$pem = $data->credentialPublicKey ?? null;
		if ( ! is_string( $pem ) || ! self::public_key_ok( $pem, $alg ) ) {
			return $fail;
		}

		// R-10: not discoverable. Absent counts as unknown and is accepted.
		$extensions = $json['clientExtensionResults'] ?? null;
		if ( is_array( $extensions ) && isset( $extensions['credProps'] ) && is_array( $extensions['credProps'] )
			&& array_key_exists( 'rk', $extensions['credProps'] ) && false === $extensions['credProps']['rk'] ) {
			return $fail;
		}

		// R-11: account state, limit for this RP ID, email change after the challenge (rule M).
		if ( get_user_meta( (int) $user->ID, 'magicauth_disabled', true ) ) {
			return $fail;
		}
		$rows = CredentialStore::for_user( $user );
		if ( null === $rows ) {
			return self::retry();
		}
		$here = 0;
		foreach ( $rows as $existing ) {
			if ( (string) $existing->rp_id === $rp_id ) {
				++$here;
			}
		}
		if ( $here >= Module::max_per_user() ) {
			return self::error( 'limit_reached', 409 );
		}
		$issued_at = strtotime( (string) $row->created_at . ' UTC' );
		if ( false === $issued_at || CredentialStore::email_changed_at( (int) $user->ID ) >= $issued_at ) {
			return $fail;
		}
		self::$issued[ Base64Url::encode( $raw_id ) ] = $issued_at;

		// R-12.
		$registered = (string) $user->user_registered;
		$handle     = (string) $row->user_handle;
		$aaguid     = Aaguids::uuid( is_string( $data->AAGUID ?? null ) ? $data->AAGUID : '' );
		$count      = $data->signatureCounter ?? 0; // A fresh instance: null means 0 (W6).
		if ( 1 !== preg_match( '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $registered ) || null === Base64Url::decode( $handle, 1, 64 ) || '' === $aaguid || ! is_int( $count ) ) {
			return $fail;
		}
		$names = [];
		foreach ( $rows as $existing ) {
			$names[] = (string) $existing->name;
		}
		$chosen = Presenter::sanitize_name( $name );
		if ( '' === $chosen ) {
			$chosen = Presenter::default_name( $aaguid, $platform, $user_agent, $names );
		} else {
			foreach ( $names as $taken ) {
				if ( Presenter::name_key( $taken ) === Presenter::name_key( $chosen ) ) {
					return self::error( 'duplicate_name', 400 );
				}
			}
		}

		return [
			'user_id'         => (int) $user->ID,
			'rp_id'           => $rp_id,
			'credential_id'   => Base64Url::encode( $raw_id ),
			'user_handle'     => $handle,
			'public_key'      => $pem,
			'alg'             => $alg,
			'sign_count'      => $count,
			'backup_eligible' => (bool) ( $data->isBackupEligible ?? false ),
			'backup_state'    => (bool) ( $data->isBackedUp ?? false ),
			'transports'      => self::transports( $response['transports'] ?? null ),
			'aaguid'          => $aaguid,
			'name'            => $chosen,
			'user_registered' => $registered,
		];
	}

	/**
	 * Orphan flag rule (7.3): never for retry, never for a replayed challenge,
	 * and only when a final SELECT proved the credential absent; a failed
	 * final SELECT turns the failure into 503 retry without the flag.
	 */
	private static function registration_failure( WP_Error $error, string $raw_id, ?string $reason ): WP_Error {
		if ( 'retry' === $error->get_error_code() || 'replayed' === $reason ) {
			return $error;
		}
		$absent = self::absent( $raw_id );
		if ( $absent instanceof WP_Error ) {
			return self::retry();
		}
		if ( true === $absent ) {
			$data                       = (array) $error->get_error_data();
			$data['unknown_credential'] = true;
			return new WP_Error( $error->get_error_code(), '', $data );
		}
		return $error;
	}

	/**
	 * Final SELECT: true when no row has this credential ID.
	 *
	 * @return bool|WP_Error
	 */
	private static function absent( string $raw_id ) {
		$found = CredentialStore::find_by_raw_id( $raw_id );
		if ( $found instanceof WP_Error ) {
			return $found;
		}
		return CredentialStore::NOT_FOUND === $found;
	}

	/**
	 * Counter policy and persistence (7.6, A-10, A-11).
	 *
	 * @return true|WP_Error
	 */
	private static function apply_counter_policy( object $cred, int $received, bool $backup_state ) {
		$id      = (int) $cred->id;
		$user_id = (int) $cred->user_id;
		if ( null !== $cred->counter_anomaly_at ) {
			return self::signin_error( 'blocked', true, [ 'user_id' => $user_id ] );
		}
		$stored = (int) $cred->sign_count; // A DB string '0' must compare as 0.
		$synced = 1 === (int) $cred->backup_eligible;

		if ( $received > $stored ) {
			$changed = CredentialStore::advance_counter( $id, $received );
			if ( ! $synced ) {
				if ( false === $changed ) {
					return self::retry();
				}
				if ( 1 !== $changed ) {
					// A concurrent assertion with a higher counter won.
					return self::signin_error( 'counter', true, [ 'user_id' => $user_id ] );
				}
			}
		} elseif ( 0 !== $stored || 0 !== $received ) {
			if ( ! $synced ) {
				$blocked = CredentialStore::block( $id );
				return self::signin_error(
					'counter',
					true,
					[
						'user_id'     => $user_id,
						'blocked_now' => 1 === $blocked,
						'row_id'      => $id,
					]
				);
			}
			// Synced: accept, never lower the stored counter.
		}

		CredentialStore::record_use( $id, $backup_state );
		return true;
	}

	/**
	 * R-1 and R-2 (W1, W2): size cap, JSON object, type, id and rawId strict
	 * base64url of 16 to 1023 bytes and equal.
	 *
	 * @return array{json:array<string,mixed>,raw_id:string}|null
	 */
	private static function parse_credential( string $credential ): ?array {
		if ( '' === $credential || strlen( $credential ) > self::MAX_CREDENTIAL ) {
			return null;
		}
		$json = json_decode( $credential, true, self::JSON_DEPTH_CREDENTIAL );
		if ( ! is_array( $json ) || 'public-key' !== ( $json['type'] ?? null ) ) {
			return null;
		}
		$id     = $json['id'] ?? null;
		$raw_id = $json['rawId'] ?? null;
		if ( ! is_string( $id ) || ! is_string( $raw_id ) ) {
			return null;
		}
		$from_id  = Base64Url::decode( $id, 16, 1023 );
		$from_raw = Base64Url::decode( $raw_id, 16, 1023 );
		if ( null === $from_id || null === $from_raw || ! hash_equals( $from_raw, $from_id ) ) {
			return null;
		}
		return [
			'json'   => $json,
			'raw_id' => $from_raw,
		];
	}

	/**
	 * One strict base64url response member, decoded, within [$min, $max] bytes.
	 *
	 * @param array<string,mixed> $response
	 */
	private static function field( array $response, string $key, int $min, int $max ): ?string {
		$value = $response[ $key ] ?? null;
		if ( ! is_string( $value ) || strlen( $value ) > intdiv( $max * 4 + 2, 3 ) ) {
			return null;
		}
		return Base64Url::decode( $value, $min, $max );
	}

	/**
	 * R-9: -7 and -257 load as an EC or RSA public key (catches off-curve
	 * points); -8 is a 44-byte Ed25519 SubjectPublicKeyInfo.
	 */
	private static function public_key_ok( string $pem, int $alg ): bool {
		if ( -8 === $alg ) {
			if ( 1 !== preg_match( '/^-----BEGIN PUBLIC KEY-----\s+([A-Za-z0-9+\/=\s]+?)\s*-----END PUBLIC KEY-----\s*$/', $pem, $m ) ) {
				return false;
			}
			$der = base64_decode( (string) preg_replace( '/\s+/', '', $m[1] ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- PEM body.
			return is_string( $der ) && 44 === strlen( $der ) && 0 === strpos( bin2hex( $der ), self::ED25519_SPKI_PREFIX );
		}
		$key = openssl_pkey_get_public( $pem );
		while ( false !== openssl_error_string() ) {
			// Drain OpenSSL's error queue.
		}
		if ( false === $key ) {
			return false;
		}
		$details = openssl_pkey_get_details( $key );
		if ( ! is_array( $details ) ) {
			return false;
		}
		return -7 === $alg ? OPENSSL_KEYTYPE_EC === $details['type'] : OPENSSL_KEYTYPE_RSA === $details['type'];
	}

	/**
	 * Transports (W6): the first 8 inputs, allowlisted, unique, comma-joined.
	 *
	 * @param mixed $input response.transports.
	 */
	private static function transports( $input ): string {
		if ( ! is_array( $input ) ) {
			return '';
		}
		$out = [];
		foreach ( array_slice( array_values( $input ), 0, self::MAX_TRANSPORT_INPUTS ) as $value ) {
			if ( is_string( $value ) && in_array( $value, self::TRANSPORTS, true ) && ! in_array( $value, $out, true ) ) {
				$out[] = $value;
			}
		}
		return implode( ',', $out );
	}

	/**
	 * Generic sign-in failure: 400 passkey_failed.
	 *
	 * @param string              $reason  For magicauth_passkey_signin_failed.
	 * @param bool                $counted Counts toward passkey_fail_ip.
	 * @param array<string,mixed> $extra   More data (user_id, unknown_credential, blocked_now).
	 */
	private static function signin_error( string $reason, bool $counted, array $extra = [] ): WP_Error {
		return self::error( 'passkey_failed', 400, self::signin_data( $reason, $counted, $extra ) );
	}

	/**
	 * Error data of a sign-in failure.
	 *
	 * @param string              $reason  For magicauth_passkey_signin_failed.
	 * @param bool                $counted Counts toward passkey_fail_ip.
	 * @param array<string,mixed> $extra   More data.
	 * @return array<string,mixed>
	 */
	private static function signin_data( string $reason, bool $counted, array $extra = [] ): array {
		return array_merge(
			[
				'reason'      => $reason,
				'counted'     => $counted,
				'user_id'     => 0,
				'blocked_now' => false,
			],
			$extra
		);
	}

	/** Database error: 503 retry, no flag, never counted (6.1, invariant 8). */
	private static function retry(): WP_Error {
		return self::error(
			'retry',
			503,
			[
				'reason'  => 'error',
				'counted' => false,
			]
		);
	}

	/**
	 * Failure with its response code (6.10) and HTTP status; no message (the endpoint picks it).
	 *
	 * @param string              $code   Response code.
	 * @param int                 $status HTTP status.
	 * @param array<string,mixed> $data   More data.
	 */
	private static function error( string $code, int $status, array $data = [] ): WP_Error {
		return new WP_Error(
			$code,
			'',
			array_merge(
				[
					'status'             => $status,
					'unknown_credential' => false,
				],
				$data
			)
		);
	}
}
