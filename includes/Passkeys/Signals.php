<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Passkeys;

defined( 'ABSPATH' ) || exit;

use WP_User;

/**
 * Signals API payloads and the details marker (SPEC 8.7). The client calls
 * signalAllAcceptedCredentials and signalCurrentUserDetails with them; an
 * incomplete list could delete valid passkeys on the authenticator, so a
 * failed read gives no payload at all (invariant 7).
 *
 * When they are sent: on the management page and own profile at load, after
 * every list change, and once per session plus once after a details change
 * on any page view (decided by Prompt::prepare_front(), committed with
 * signals_at by Prompt::render_footer()).
 */
final class Signals {

	/** User meta: when the account details the authenticators show last changed (5.3). */
	public const DETAILS_META = 'magicauth_passkey_details_at';

	/**
	 * SignalPayload for the user: { rpId, userId (the user handle), allAccepted
	 * (base64url IDs of every credential for the current RP ID, one query),
	 * name, displayName }, or null when the list cannot be read or there is
	 * nothing to identify the account by.
	 *
	 * @param WP_User $user The account (never anyone else's credentials).
	 * @return array{rpId:string,userId:string,allAccepted:array<int,string>,name:string,displayName:string}|null
	 */
	public static function payload( WP_User $user ): ?array {
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
		return [
			'rpId'        => $rp_id,
			'userId'      => $handle,
			'allAccepted' => $ids,
			'name'        => (string) $user->user_email,
			'displayName' => Options::display_name( $user ),
		];
	}

	/**
	 * profile_update, after AccountEvents (4.6): user.name is the email and
	 * user.displayName the display name (7.2), so a change of either marks the
	 * details for the next page view's signalCurrentUserDetails. Only for an
	 * account with a user handle, and not when rule M ran: every passkey is
	 * gone then and there is nothing to update.
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
