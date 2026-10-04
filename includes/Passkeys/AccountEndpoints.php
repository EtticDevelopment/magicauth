<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Passkeys;

defined( 'ABSPATH' ) || exit;

use MagicAuth\Auth\Login;
use MagicAuth\Auth\Throttle;
use MagicAuth\Email\Mailer;
use WP_Error;
use WP_User;

/**
 * Signed-in passkey endpoints (SPEC 6.4 to 6.8, 6.14): registration options
 * and verification, the step-up by email code or an existing passkey, the
 * list actions and the prompt choice.
 * wp_ajax_ only (never nopriv), registered by Module::register() while the
 * module is enabled; every handler re-checks the session, the nonce, the
 * Origin and the module itself.
 *
 * These two registration handlers are the only code path that writes a
 * credential row (invariant 1), and only for the signed-in user with a fresh
 * session (3.3), bound to this session through the register challenge.
 *
 * Every handler ends in Http::ok() or Http::fail(), which end the request.
 */
final class AccountEndpoints {

	/** Nonce action of every account endpoint (6.11). */
	public const NONCE = 'magicauth_passkeys';

	/** Optional register fields, bytes before sanitising (6.5). */
	private const MAX_NAME = 256;

	private const MAX_PLATFORM = 16;

	private const MAX_USER_AGENT = 512;

	/** Step-up code field (6.7); reauth_id is 16 bytes, 22 base64url characters. */
	private const MAX_CODE = 16;

	private const REAUTH_ID_CHARS = 22;

	/** magicauth_passkey_register_options (6.4). */
	public static function register_options(): void {
		Http::require_post();
		$user = Http::require_session( self::NONCE );
		self::require_account( $user );
		$uid = (int) $user->ID;

		// Freshness before passkey_reg_user, so a stale cookie cannot spend the owner's quota.
		if ( ! Freshness::is_fresh() ) {
			if ( ! self::allow( Throttle::ACTION_PASSKEY_STALE_USER, $uid ) ) {
				self::fail( 'throttled', 429 );
			}
			$methods = self::reauth_methods( $user );
			if ( null === $methods ) {
				self::fail( 'retry', 503 );
			}
			Http::fail( 'reauth_required', self::message( 'reauth_required' ), 403, [ 'methods' => $methods ] );
		}

		$rows = CredentialStore::for_user( $user, RelyingParty::id() );
		if ( null === $rows ) {
			self::fail( 'retry', 503 );
		}
		if ( count( $rows ) >= Module::max_per_user() ) {
			self::fail( 'limit_reached', 409 );
		}
		if ( ! self::allow( Throttle::ACTION_PASSKEY_REG_USER, $uid ) ) {
			self::fail( 'throttled', 429 );
		}

		$handle = CredentialStore::user_handle( $uid, true );
		if ( null === $handle ) {
			self::fail( 'retry', 503 );
		}
		$algs      = Module::supported_algs();
		$challenge = ChallengeStore::issue( 'register', $uid, Freshness::session_hash(), '', implode( ',', $algs ), ChallengeStore::TTL['register'], $handle );
		if ( $challenge instanceof WP_Error ) {
			self::fail( 'retry', 503 );
		}

		Http::ok( [ 'publicKey' => Options::creation( $user, $handle, $challenge, $algs, $rows ) ] );
	}

	/** magicauth_passkey_register (6.5, 7.3). */
	public static function register(): void {
		Http::require_post();
		$user = Http::require_session( self::NONCE );
		self::require_account( $user );
		$uid = (int) $user->ID;

		$credential = Http::body_too_large() ? null : Http::field( 'credential', Verifier::MAX_CREDENTIAL );
		if ( null === $credential ) {
			self::registration_failed( self::error( 'registration_failed' ), $uid );
		}

		// passkey_regfail_user: peeked here, counted per failure below.
		[ $max ] = Throttle::PASSKEY_USER_LIMITS[ Throttle::ACTION_PASSKEY_REGFAIL_USER ];
		if ( Throttle::passkey_user_exhausted( Throttle::ACTION_PASSKEY_REGFAIL_USER, $uid, $max ) ) {
			$flag = Verifier::unknown_credential_flag( $credential, $user, Freshness::session_hash() );
			if ( $flag instanceof WP_Error ) {
				self::fail( 'retry', 503 );
			}
			self::fail( 'throttled', 429, true === $flag );
		}

		$record = Verifier::verify_registration(
			$credential,
			$user,
			Freshness::session_hash(),
			(string) Http::field( 'name', self::MAX_NAME ),
			(string) Http::field( 'platform', self::MAX_PLATFORM ),
			self::user_agent()
		);
		if ( $record instanceof WP_Error ) {
			self::registration_failed( $record, $uid );
		}
		$id = Verifier::store_registration( $record );
		if ( $id instanceof WP_Error ) {
			self::registration_failed( $id, $uid );
		}

		self::after_registration( $user, $id );

		$items = self::items( $user, true );
		$item  = null;
		foreach ( (array) $items as $entry ) {
			if ( $entry['id'] === $id ) {
				$item = $entry;
			}
		}
		if ( null === $item ) {
			// The list could not be read: the stored record as an item.
			$item = Presenter::item( self::stored_row( $record, $id ), true );
		}

		// create() gave the new passkey the details 7.2 sends, the payload's own (8.7).
		$signal = Signals::payload( $user, false );
		if ( null !== $signal ) {
			Signals::record( $uid, $signal );
		}

		Http::ok(
			array_merge(
				[ 'passkey' => $item ],
				self::list_fields( $items ),
				[ 'signal' => $signal ]
			)
		);
	}

	/** magicauth_passkey_reauth_email (6.7): send a step-up code. */
	public static function reauth_email(): void {
		Http::require_post();
		$user = Http::require_session( self::NONCE );
		self::require_account( $user );
		$uid          = (int) $user->ID;
		$session_hash = self::require_session_state();

		// A code would only prove a mailbox set inside this session (7.6 rule M).
		if ( ! self::email_code_allowed( $user ) ) {
			self::fail( 'reauth_unavailable', 403 );
		}
		if ( ! Throttle::allow_passkey_reauth_cooldown( $uid ) ) {
			$wait = max( 1, Throttle::passkey_reauth_cooldown_remaining( $uid ) );
			Http::fail(
				'cooldown',
				sprintf(
					/* translators: %d: seconds to wait */
					_n( 'Please wait %d second before you send another code.', 'Please wait %d seconds before you send another code.', $wait, 'magicauth' ),
					$wait
				),
				429,
				[ 'retry_after' => $wait ]
			);
		}
		if ( ! self::allow( Throttle::ACTION_PASSKEY_REAUTH_MAIL_USER, $uid ) ) {
			self::fail( 'throttled', 429 );
		}

		$issued = ChallengeStore::issue_code( $uid, $session_hash );
		if ( $issued instanceof WP_Error ) {
			self::fail( 'retry', 503 );
		}
		[ $reauth_id, $code ] = $issued;

		magicauth_dispatch_after_response(
			static function () use ( $uid, $code ): void {
				Mailer::send_confirm_code( $uid, $code );
			}
		);

		Http::ok(
			[
				'reauth_id'  => Base64Url::encode( $reauth_id ),
				'expires_in' => ChallengeStore::TTL['reauth_code'],
				'sent_to'    => self::mask_email( (string) $user->user_email ),
			]
		);
	}

	/** magicauth_passkey_reauth_code (6.7): verify the code, stamp the step-up. */
	public static function reauth_code(): void {
		magicauth_jitter(); // Secret input: once, before any response (6.1).
		Http::require_post();
		$user = Http::require_session( self::NONCE );
		self::require_account( $user );
		$uid          = (int) $user->ID;
		$session_hash = self::require_session_state();

		if ( ! self::email_code_allowed( $user ) ) {
			self::fail( 'reauth_unavailable', 403 );
		}
		if ( ! self::allow( Throttle::ACTION_PASSKEY_REAUTH_TRY_USER, $uid ) ) {
			self::fail( 'throttled', 429 );
		}

		$id_field  = Http::body_too_large() ? null : Http::field( 'reauth_id', self::REAUTH_ID_CHARS );
		$code      = Http::field( 'code', self::MAX_CODE );
		$reauth_id = null !== $id_field ? Base64Url::decode( $id_field, 16, 16 ) : null;
		$issued_at = 0;
		$verified  = null === $reauth_id || null === $code ? false : ChallengeStore::verify_code( $reauth_id, $code, $uid, $session_hash, $issued_at );
		if ( $verified instanceof WP_Error ) {
			self::fail( 'retry', 503 );
		}
		if ( true !== $verified ) {
			self::fail( 'code_invalid', 400 );
		}

		// The cookie is sent only once the stamp is stored.
		if ( ! SessionState::stamp_reauth( 'email_code' ) ) {
			self::fail( 'retry', 503 );
		}
		update_user_meta( $uid, 'magicauth_email_verified_at', Clock::now() );

		// Rule M (7.6) judged by when the mailbox was proven, not when the
		// stamps were written: an email change at or after the code was sent
		// (to the old address) undoes both. Read after the writes, from the
		// database: rule M writes changed_at before it clears, so a change
		// that this read misses clears the stamps itself.
		wp_cache_delete( $uid, 'user_meta' );
		$changed = CredentialStore::email_changed_at( $uid );
		if ( $issued_at <= 0 || ( $changed > 0 && $changed >= $issued_at ) ) {
			SessionState::clear_reauth_for_user( $uid );
			delete_user_meta( $uid, 'magicauth_email_verified_at' );
			self::fail( 'reauth_unavailable', 403 );
		}

		Http::ok( [ 'fresh_until' => Clock::now() + Freshness::window() ] );
	}

	/** magicauth_passkey_reauth_options (6.7): request options for a passkey step-up. */
	public static function reauth_options(): void {
		Http::require_post();
		$user = Http::require_session( self::NONCE );
		self::require_account( $user );
		$uid          = (int) $user->ID;
		$session_hash = self::require_session_state();

		$usable = self::usable_credentials( $user );
		if ( null === $usable ) {
			self::fail( 'retry', 503 );
		}
		if ( [] === $usable ) {
			self::fail( 'no_passkey', 409 );
		}
		// Counted only now: each call inserts a challenge row.
		if ( ! self::allow( Throttle::ACTION_PASSKEY_REAUTH_OPTS_USER, $uid ) ) {
			self::fail( 'throttled', 429 );
		}

		$challenge = ChallengeStore::issue( 'reauth', $uid, $session_hash, '', '', ChallengeStore::TTL['reauth'] );
		if ( $challenge instanceof WP_Error ) {
			self::fail( 'retry', 503 );
		}

		Http::ok( [ 'publicKey' => Options::request( $challenge, $usable ) ] );
	}

	/** magicauth_passkey_reauth_passkey (6.7, 7.4 step-up): verify, stamp the step-up. */
	public static function reauth_passkey(): void {
		magicauth_jitter(); // Cryptographic input: once, before any response (6.1).
		Http::require_post();
		$user = Http::require_session( self::NONCE );
		self::require_account( $user );
		$uid          = (int) $user->ID;
		$session_hash = self::require_session_state();

		if ( ! self::allow( Throttle::ACTION_PASSKEY_REAUTH_TRY_USER, $uid ) ) {
			self::fail( 'throttled', 429 );
		}

		$credential = Http::body_too_large() ? null : Http::field( 'credential', Verifier::MAX_CREDENTIAL );
		if ( null === $credential ) {
			self::fail( 'reauth_failed', 400 );
		}
		// Proof time: before the row and revoked() checks (7.6 rule M).
		$proven_at = Clock::now();
		$verified  = Verifier::verify_step_up( $credential, $user, $session_hash );
		if ( $verified instanceof WP_Error ) {
			$data = (array) $verified->get_error_data();
			if ( 'retry' === $verified->get_error_code() ) {
				self::fail( 'retry', 503 );
			}
			if ( ! empty( $data['blocked_now'] ) ) {
				AccountEvents::send_blocked( $uid, (int) ( $data['row_id'] ?? 0 ) );
			}
			self::fail( 'reauth_failed', 400, ! empty( $data['unknown_credential'] ) );
		}

		if ( ! SessionState::stamp_reauth( 'passkey', $proven_at ) ) {
			self::fail( 'retry', 503 );
		}

		// Rule M (7.6) between the checks and the stamp: the passkey was
		// revoked with the old mailbox. Read after the write, from the
		// database, as reauth_code does; the stamp's own time already keeps
		// the session from being fresh (3.4 step 6).
		wp_cache_delete( $uid, 'user_meta' );
		$changed = CredentialStore::email_changed_at( $uid );
		if ( $changed > 0 && $changed >= $proven_at ) {
			SessionState::clear_reauth_for_user( $uid );
			self::fail( 'reauth_unavailable', 403 );
		}

		Http::ok( [ 'fresh_until' => Clock::now() + Freshness::window() ] );
	}

	/**
	 * magicauth_passkey_rename (6.6). No freshness: a rename cannot add access
	 * (D-15). Success is the row existing for ( id, user ), never the
	 * affected-rows count.
	 */
	public static function rename(): void {
		Http::require_post();
		$user = Http::require_session( self::NONCE );
		$uid  = self::require_manage( $user );

		$id   = self::posted_id();
		$name = Http::field( 'name', self::MAX_NAME );
		$name = null !== $name ? Presenter::sanitize_name( $name ) : '';
		if ( '' === $name ) {
			self::fail( 'invalid_name', 400 );
		}
		$done = CredentialStore::rename( $uid, $id, $name );
		if ( $done instanceof WP_Error ) {
			$code = $done->get_error_code();
			if ( 'magicauth_db_error' === $code ) {
				self::manage_retry();
			}
			if ( 'magicauth_invalid_name' === $code || 'magicauth_duplicate_name' === $code ) {
				self::fail( 'magicauth_invalid_name' === $code ? 'invalid_name' : 'duplicate_name', 400 );
			}
			// Not found, also another user's id (IDOR): the row is untouched.
			self::fail( 'not_found', 404 );
		}

		$items = self::items( $user, true );
		$item  = null;
		foreach ( (array) $items as $entry ) {
			if ( $entry['id'] === $id ) {
				$item = $entry;
			}
		}
		Http::ok(
			array_merge(
				[ 'passkey' => $item ],
				self::list_fields( $items ),
				[ 'signal' => Signals::payload( $user, false ) ]
			)
		);
	}

	/**
	 * magicauth_passkey_delete (6.6). No freshness (D-15); from a session that
	 * is not fresh the removal email goes out (10.4), the one silent action a
	 * session thief could take otherwise. signout_others (default 1) ends
	 * every other session of the user (D-34).
	 */
	public static function delete(): void {
		Http::require_post();
		$user = Http::require_session( self::NONCE );
		$uid  = self::require_manage( $user );

		$id    = self::posted_id();
		$fresh = Freshness::is_fresh();
		$done  = CredentialStore::delete( $uid, $id );
		if ( $done instanceof WP_Error ) {
			if ( 'magicauth_db_error' === $done->get_error_code() ) {
				self::manage_retry();
			}
			self::fail( 'not_found', 404 );
		}
		ChallengeStore::delete_completions_for_user( $uid );

		$signed_out = self::signout_requested( 'signout_others' ) ? self::destroy_other_sessions( $uid ) : 0;
		if ( ! $fresh ) {
			AccountEvents::send_removed( $uid, 1, 'self', 'removed' );
		}
		do_action( 'magicauth_passkey_removed', $uid, $id, 'user' );

		Http::ok(
			array_merge(
				self::list_fields( self::items( $user, true ) ),
				[
					'signal'     => Signals::payload( $user, false ),
					'signed_out' => $signed_out,
				]
			)
		);
	}

	/** magicauth_passkey_signout_others (6.14): core's wp_destroy_other_sessions(). */
	public static function signout_others(): void {
		Http::require_post();
		$user = Http::require_session( self::NONCE );
		self::require_manage( $user );

		wp_destroy_other_sessions();
		Http::ok( [] );
	}

	/**
	 * magicauth_passkey_prompt (6.8): the prompt choice. later, dismiss and
	 * failed update the account's cadence; device sets magicauth_pk_shared
	 * and leaves the account alone. Shares passkey_manage_user (each call
	 * writes user meta or sends Set-Cookie). Never creates anything.
	 */
	public static function prompt_choice(): void {
		Http::require_post();
		$user = Http::require_session( self::NONCE );
		$uid  = self::require_manage( $user );

		$choice = Http::field( 'choice', 8 );
		if ( null === $choice || ! in_array( $choice, Prompt::CHOICES, true ) ) {
			self::fail( 'bad_request', 400 );
		}
		if ( 'device' === $choice ) {
			Prompt::set_shared_cookie();
		} else {
			Prompt::record_choice( $uid, $choice );
		}
		Http::ok( [] );
	}

	/**
	 * The user's passkeys as Items (6.5), every RP ID (usable_here tells them
	 * apart), oldest first; null on a failed query.
	 *
	 * @internal Shared by the account and admin endpoints and the renders.
	 * @param WP_User $user  Owner.
	 * @param bool    $owner The response goes to the owner (credential_id included).
	 * @return array<int,array<string,mixed>>|null
	 */
	public static function items( WP_User $user, bool $owner ): ?array {
		$rows = CredentialStore::for_user( $user );
		if ( null === $rows ) {
			return null;
		}
		$items = [];
		foreach ( $rows as $row ) {
			$items[] = Presenter::item( $row, $owner );
		}
		return $items;
	}

	/**
	 * The list fields of a response: passkeys, or passkeys null with
	 * list_error true when the list could not be read, so the client keeps
	 * what it shows (MX) instead of rendering "no passkeys" (6.5, 6.6).
	 *
	 * @internal Shared with the admin endpoints.
	 * @param array<int,array<string,mixed>>|null $items From items().
	 * @return array<string,mixed>
	 */
	public static function list_fields( ?array $items ): array {
		return null === $items ? [ 'passkeys' => null, 'list_error' => true ] : [ 'passkeys' => $items ];
	}

	/**
	 * Step-up methods offered with reauth_required (3.5): email_code unless
	 * the email changed at or after this session's creation; passkey when the
	 * user has a usable credential for this RP ID. Null on a failed query.
	 *
	 * @internal Also the account config's reauth.methods (8.1).
	 * @return array<int,string>|null
	 */
	public static function reauth_methods( WP_User $user ): ?array {
		$usable = self::usable_credentials( $user );
		if ( null === $usable ) {
			return null;
		}
		$methods = [];
		if ( self::email_code_allowed( $user ) ) {
			$methods[] = 'email_code';
		}
		if ( [] !== $usable ) {
			$methods[] = 'passkey';
		}
		return $methods;
	}

	/**
	 * The user's credentials for this RP ID without a counter anomaly (7.6),
	 * the step-up allow list. Null on a failed query.
	 *
	 * @return array<int,object>|null
	 */
	private static function usable_credentials( WP_User $user ): ?array {
		$rows = CredentialStore::for_user( $user, RelyingParty::id() );
		if ( null === $rows ) {
			return null;
		}
		return array_values(
			array_filter(
				$rows,
				static function ( $row ): bool {
					return null === $row->counter_anomaly_at;
				}
			)
		);
	}

	/**
	 * False when the account's email changed at or after this session was
	 * created (3.5, 7.6 rule M). The creation time is the MagicAuth stamp, or
	 * core's login time for a session MagicAuth did not create.
	 */
	private static function email_code_allowed( WP_User $user ): bool {
		$changed = (int) get_user_meta( (int) $user->ID, 'magicauth_email_changed_at', true );
		if ( $changed <= 0 ) {
			return true;
		}
		$session = Freshness::session();
		if ( null === $session ) {
			return false;
		}
		$created = $session['magicauth_auth_at'] ?? ( $session['login'] ?? null );
		return is_int( $created ) && $changed < $created;
	}

	/**
	 * Step-up endpoints need the session's hash and its core record (5.2:
	 * session-bound rows are refused without them); else 403
	 * reauth_unavailable.
	 */
	private static function require_session_state(): string {
		$hash = Freshness::session_hash();
		if ( '' === $hash || null === Freshness::session() ) {
			self::fail( 'reauth_unavailable', 403 );
		}
		return $hash;
	}

	/** Module enabled, else 404 unavailable; user not disabled (7.6 rule D), else 403 disabled_user. */
	private static function require_account( WP_User $user ): void {
		if ( ! Module::enabled() ) {
			self::fail( 'unavailable', 404 );
		}
		if ( get_user_meta( (int) $user->ID, 'magicauth_disabled', true ) ) {
			self::fail( 'disabled_user', 403 );
		}
	}

	/**
	 * Owner endpoints (6.6, 6.14): module enabled, else 404 unavailable; then
	 * passkey_manage_user (rename, delete, sign-out and the prompt choice
	 * share it), else 429. A disabled user may still remove (rule D blocks
	 * adding and signing in only).
	 */
	private static function require_manage( WP_User $user ): int {
		if ( ! Module::enabled() ) {
			self::fail( 'unavailable', 404 );
		}
		$uid = (int) $user->ID;
		if ( ! self::allow( Throttle::ACTION_PASSKEY_MANAGE_USER, $uid ) ) {
			self::fail( 'throttled', 429 );
		}
		return $uid;
	}

	/**
	 * 503 retry of a list action (the create flow's message names creating).
	 *
	 * @return never
	 */
	private static function manage_retry(): void {
		Http::fail( 'retry', __( 'Something went wrong. Please try again.', 'magicauth' ), 503 );
	}

	/** Posted row id, 0 when absent or not a positive integer. */
	private static function posted_id(): int {
		$id = Http::field( 'id', 20 );
		return null !== $id && 1 === preg_match( '/^[1-9][0-9]{0,18}$/', $id ) ? (int) $id : 0;
	}

	/**
	 * A sign-out flag: '0' turns it off, anything else (absent included)
	 * leaves the default on (D-34).
	 *
	 * @internal Also read by AdminEndpoints.
	 */
	public static function signout_requested( string $field ): bool {
		return '0' !== Http::field( $field, 1 );
	}

	/**
	 * wp_destroy_other_sessions() for the signed-in user; the number of
	 * sessions it ended.
	 *
	 * @internal Also used by AdminEndpoints for a self-removal.
	 */
	public static function destroy_other_sessions( int $uid ): int {
		$manager = \WP_Session_Tokens::get_instance( $uid );
		$before  = count( $manager->get_all() );
		wp_destroy_other_sessions();
		return max( 0, $before - count( $manager->get_all() ) );
	}

	/**
	 * R-14 (7.3): passkey-added email after the response, prompt cadence
	 * reset, rule E initialisation from a mailbox-proving session, action.
	 */
	private static function after_registration( WP_User $user, int $id ): void {
		$uid = (int) $user->ID;

		magicauth_dispatch_after_response(
			static function () use ( $uid, $id ): void {
				Mailer::send_passkey_added( $uid, $id );
			}
		);

		update_user_meta(
			$uid,
			'magicauth_passkey_prompt',
			[
				'declines' => 0,
				'next_at'  => 0,
			]
		);

		if ( (int) magicauth_get_setting( 'passkeys_email_reverify_days', 0 ) > 0
			&& '' === get_user_meta( $uid, 'magicauth_email_verified_at', true ) ) {
			// The proof's own time decides (7.6 rule M): the link or code
			// sign-in's stamp, else the email-code step-up's.
			$session = Freshness::session();
			$method  = is_array( $session ) ? ( $session['magicauth_method'] ?? '' ) : '';
			$state   = SessionState::get();
			$proven  = 0;
			if ( in_array( $method, [ 'link', 'code' ], true ) && is_int( $session['magicauth_auth_at'] ?? null ) ) {
				$proven = (int) $session['magicauth_auth_at'];
			}
			if ( null !== $state && 'email_code' === (string) $state->reauth_method ) {
				$proven = max( $proven, (int) $state->reauth_at );
			}
			if ( $proven > 0 ) {
				Login::record_mailbox_proof( $uid, $proven );
			}
		}

		do_action( 'magicauth_passkey_added', $uid, $id );
	}

	/**
	 * Registration failure response: counts passkey_regfail_user (never for a
	 * database error), keeps the orphan flag the verifier decided.
	 *
	 * @return never
	 */
	private static function registration_failed( WP_Error $error, int $uid ): void {
		$code = $error->get_error_code();
		$data = (array) $error->get_error_data();
		if ( 'retry' === $code ) {
			self::fail( 'retry', 503 );
		}
		self::allow( Throttle::ACTION_PASSKEY_REGFAIL_USER, $uid );
		$status = isset( $data['status'] ) ? (int) $data['status'] : 400;
		self::fail( (string) $code, $status, ! empty( $data['unknown_credential'] ) );
	}

	/**
	 * Failure response with the code's message; unknown_credential only when
	 * flagged (never the key otherwise, T-REG 29b).
	 *
	 * @return never
	 */
	private static function fail( string $code, int $status, bool $unknown_credential = false ): void {
		Http::fail( $code, self::message( $code ), $status, $unknown_credential ? [ 'unknown_credential' => true ] : [] );
	}

	/** Translated fallback messages; JS shows its own strings for known codes (6.10). */
	private static function message( string $code ): string {
		switch ( $code ) {
			case 'reauth_required':
				return __( 'For your security, confirm it is you before you add a passkey.', 'magicauth' );
			case 'reauth_unavailable':
				return __( 'Sign out and sign in again with your email to add a passkey.', 'magicauth' );
			case 'limit_reached':
				$max = Module::max_per_user();
				/* translators: %d: maximum number of passkeys per account */
				return sprintf( _n( 'You have %d passkey, which is the maximum. Remove one before you add another.', 'You have %d passkeys, which is the maximum. Remove one before you add another.', $max, 'magicauth' ), $max );
			case 'registration_failed':
				return __( 'The passkey could not be saved. Please try again.', 'magicauth' );
			case 'duplicate_name':
				return __( 'You already have a passkey with this name. Choose another name.', 'magicauth' );
			case 'code_invalid':
				return __( 'That code is not correct or has expired. Check the code, or send a new one.', 'magicauth' );
			case 'reauth_failed':
			case 'no_passkey':
				return __( 'That did not work. Try again, or confirm with a code from your email.', 'magicauth' );
			case 'throttled':
				return __( 'Too many attempts. Please try again later.', 'magicauth' );
			case 'retry':
				return __( 'Something went wrong while creating the passkey. Please try again.', 'magicauth' );
			case 'invalid_name':
				return __( 'Enter a name of up to 64 characters.', 'magicauth' );
			case 'not_found':
				return __( 'This passkey no longer exists. Reload this page.', 'magicauth' );
			case 'bad_request':
				return __( 'Something went wrong. Please try again.', 'magicauth' );
			default: // unavailable, disabled_user.
				return __( 'Passkeys are not available on this site right now.', 'magicauth' );
		}
	}

	/** One per-user bucket with its PASSKEY_USER_LIMITS. */
	private static function allow( string $bucket, int $uid ): bool {
		[ $max, $window ] = Throttle::PASSKEY_USER_LIMITS[ $bucket ];
		return Throttle::allow_passkey_user( $bucket, $uid, $max, $window );
	}

	private static function error( string $code ): WP_Error {
		return new WP_Error( $code, '', [ 'status' => 400 ] );
	}

	/** "l***@example.com" for the step-up response (3.5). */
	private static function mask_email( string $email ): string {
		$at = strrpos( $email, '@' );
		if ( false === $at || 0 === $at ) {
			return '***';
		}
		return mb_substr( $email, 0, 1, 'UTF-8' ) . '***' . substr( $email, $at );
	}

	/** HTTP_USER_AGENT for the default passkey name only (4.8), capped. */
	private static function user_agent(): string {
		if ( ! isset( $_SERVER['HTTP_USER_AGENT'] ) || ! is_string( $_SERVER['HTTP_USER_AGENT'] ) ) {
			return '';
		}
		$ua = (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- matched against fixed substrings only, never stored or output.
		return substr( $ua, 0, self::MAX_USER_AGENT );
	}

	/**
	 * The stored record as a row object for Presenter::item(), when the list
	 * cannot be read after the INSERT.
	 *
	 * @param array<string,mixed> $record From Verifier::verify_registration().
	 */
	private static function stored_row( array $record, int $id ): object {
		$raw = (string) Base64Url::decode( (string) $record['credential_id'], 16, 1023 );
		return (object) ( $record + [
			'id'                 => $id,
			'credential_hash'    => hash( 'sha256', $raw ),
			'created_at'         => gmdate( 'Y-m-d H:i:s', Clock::now() ),
			'last_used_at'       => null,
			'counter_anomaly_at' => null,
		] );
	}
}
