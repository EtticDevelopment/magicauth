<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Passkeys;

defined( 'ABSPATH' ) || exit;

use WP_User;

/**
 * Signals API payloads, the details marker and the details record (SPEC
 * 8.7). The client calls signalAllAcceptedCredentials with every payload and
 * signalCurrentUserDetails only when the payload says details; an incomplete
 * list could delete valid passkeys on the authenticator, so a failed read
 * gives no payload at all (invariant 7).
 *
 * When they are sent: the list on the management page and own profile at
 * load, after every list change, and once per session on any page view
 * (decided by Prompt::prepare_front(), committed with signals_at by
 * Prompt::render_footer()). The details only on a page view whose details
 * differ from the record of the last ones delivered: Safari 26 tells the
 * user about every signalCurrentUserDetails, changed or not.
 */
final class Signals {

	/** User meta: when the account details the authenticators show last changed (5.3). */
	public const DETAILS_META = 'magicauth_passkey_details_at';

	/**
	 * User meta: SHA-256 hex of the details the authenticators last got (5.3):
	 * rpId, user handle, name and displayName, from create() or a delivered
	 * signalCurrentUserDetails. A hash of the values, not a change time, so a
	 * change that skips profile_update (a direct table write) is caught too.
	 */
	public const SENT_META = 'magicauth_passkey_details_sent';

	/**
	 * SignalPayload for the user: { rpId, userId (the user handle), allAccepted
	 * (base64url IDs of every credential for the current RP ID, one query),
	 * name, displayName, details }, or null when the list cannot be read or
	 * there is nothing to identify the account by. details is true when the
	 * list is not empty and name or displayName differ from the details last
	 * delivered (SENT_META); the client sends signalCurrentUserDetails only
	 * then.
	 *
	 * @param WP_User $user    The account (never anyone else's credentials).
	 * @param bool    $details Decide details; false: always false (endpoint responses, 6.5, 6.6).
	 * @return array{rpId:string,userId:string,allAccepted:array<int,string>,name:string,displayName:string,details:bool}|null
	 */
	public static function payload( WP_User $user, bool $details = true ): ?array {
		global $wpdb;

		$rp_id  = RelyingParty::id();
		$handle = CredentialStore::user_handle( (int) $user->ID, false );
		if ( '' === $rp_id || null === $handle ) {
			return null;
		}

		// A lagging read replica must never produce a list without a just added credential (B-9).
		if ( method_exists( $wpdb, 'send_reads_to_masters' ) ) {
			$wpdb->send_reads_to_masters();
		}
		$rows = CredentialStore::for_user( $user, $rp_id );
		if ( null === $rows ) {
			return null;
		}

		$ids = [];
		foreach ( $rows as $row ) {
			$ids[] = (string) $row->credential_id;
		}
		$name    = (string) $user->user_email;
		$display = Options::display_name( $user );
		return [
			'rpId'        => $rp_id,
			'userId'      => $handle,
			'allAccepted' => $ids,
			'name'        => $name,
			'displayName' => $display,
			'details'     => $details && [] !== $ids && self::sent( (int) $user->ID ) !== self::fingerprint( $rp_id, $handle, $name, $display ),
		];
	}

	/**
	 * The authenticators may lack the account's current details: the user has
	 * a handle and the details differ from the record. No table read, so
	 * Prompt::signals_due() asks it on every page view after the first of a
	 * session. A difference with no credential for this RP ID is settled by
	 * the page view it causes (delivered()).
	 *
	 * @param WP_User $user The signed-in user.
	 */
	public static function details_pending( WP_User $user ): bool {
		$rp_id  = RelyingParty::id();
		$handle = CredentialStore::user_handle( (int) $user->ID, false );
		if ( '' === $rp_id || null === $handle ) {
			return false;
		}
		return self::sent( (int) $user->ID ) !== self::fingerprint( $rp_id, $handle, (string) $user->user_email, Options::display_name( $user ) );
	}

	/**
	 * A page printed this payload of the user's (Prompt::render_footer(),
	 * after the decision of 8.7): when it carried the details, or the list was
	 * empty (no authenticator holds anything to update), its details are the
	 * record from now on. Nothing else changes the record, so a payload whose
	 * details were not due leaves it alone.
	 *
	 * @param int                 $user_id The signed-in user.
	 * @param array<string,mixed> $payload A payload() result.
	 */
	public static function delivered( int $user_id, array $payload ): void {
		if ( true === ( $payload['details'] ?? null ) || [] === ( $payload['allAccepted'] ?? null ) ) {
			self::record( $user_id, $payload );
		}
	}

	/**
	 * The authenticators hold the payload's details: a page delivered them
	 * (delivered()) or create() just stored them with a new passkey (6.5, 7.2
	 * sends the same values). Written only when it differs.
	 *
	 * @param int                 $user_id The account.
	 * @param array<string,mixed> $payload A payload() result.
	 */
	public static function record( int $user_id, array $payload ): void {
		if ( $user_id <= 0 ) {
			return;
		}
		$fingerprint = self::fingerprint(
			(string) ( $payload['rpId'] ?? '' ),
			(string) ( $payload['userId'] ?? '' ),
			(string) ( $payload['name'] ?? '' ),
			(string) ( $payload['displayName'] ?? '' )
		);
		if ( self::sent( $user_id ) !== $fingerprint ) {
			update_user_meta( $user_id, self::SENT_META, $fingerprint );
		}
	}

	/** The stored record, '' when there is none (an account from before 1.1.1 gets its details once). */
	private static function sent( int $user_id ): string {
		$sent = get_user_meta( $user_id, self::SENT_META, true );
		return is_string( $sent ) ? $sent : '';
	}

	/**
	 * SHA-256 hex of the four values signalCurrentUserDetails carries. NUL
	 * cannot occur in any of them (displayName loses its controls in
	 * Options::display_name(), the email is sanitized, the handle base64url).
	 */
	private static function fingerprint( string $rp_id, string $handle, string $name, string $display_name ): string {
		return hash( 'sha256', implode( "\0", [ $rp_id, $handle, $name, $display_name ] ) );
	}

	/**
	 * profile_update, after AccountEvents (4.6): user.name is the email and
	 * user.displayName the display name (7.2), so a change of either is
	 * recorded as the details change time (exported, 12.2). Whether the
	 * authenticators get the details is decided by the record (SENT_META),
	 * not by this time. Only for an account with a user handle, and not when
	 * rule M ran: every passkey is gone then and there is nothing to update.
	 *
	 * @param WP_User $user     The account after the update.
	 * @param WP_User $old_user The account before it.
	 * @param bool    $revoked  Rule M removed the passkeys.
	 */
	public static function on_profile_update( WP_User $user, WP_User $old_user, bool $revoked ): void {
		if ( $revoked ) {
			return;
		}
		if ( (string) $user->display_name === (string) $old_user->display_name
			&& (string) $user->user_email === (string) $old_user->user_email ) {
			return;
		}
		if ( null === CredentialStore::user_handle( (int) $user->ID, false ) ) {
			return;
		}
		update_user_meta( (int) $user->ID, self::DETAILS_META, Clock::now() );
	}
}
