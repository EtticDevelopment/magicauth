<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Passkeys;

defined( 'ABSPATH' ) || exit;

use MagicAuth\Auth\TokenManager;
use MagicAuth\Email\Mailer;
use WP_Error;
use WP_User;

/**
 * Account events (SPEC 7.6 rule M, 10.4, 10.5): an email-address change
 * revokes every passkey of the account, and the removal and blocked security
 * emails go out after the response.
 *
 * on_profile_update() is always registered (Module::setup()): the mailbox is
 * the root of trust whatever the toggle says, and passkeys stored during an
 * earlier "on" period must not survive a change of it.
 */
final class AccountEvents {

	/**
	 * profile_update (4.6): rule M when the email address changed
	 * (case-insensitively) and magicauth_passkey_revoke_on_email_change
	 * allows it: (0, on any change, filter or not) the outstanding sign-in
	 * links and codes of the user and of the old address, (1) every
	 * credential row of the user, (2)
	 * magicauth_email_verified_at, (3) magicauth_email_changed_at = now, (3b)
	 * the user's challenge rows and step-up stamps, (4) the removal email to
	 * the old and the new address when a passkey was removed, (5)
	 * magicauth_passkeys_revoked. A display-name change does none of this.
	 * Then Signals::on_profile_update() (4.6) marks changed account details
	 * when rule M did not run.
	 *
	 * @param int   $user_id  The updated user.
	 * @param mixed $old_user WP_User before the update.
	 * @param mixed $userdata The update (unused).
	 */
	public static function on_profile_update( $user_id, $old_user = null, $userdata = null ): void {
		unset( $userdata );
		$user_id = (int) $user_id;
		if ( $user_id <= 0 || ! $old_user instanceof WP_User ) {
			return;
		}
		$user = get_userdata( $user_id );
		if ( ! $user instanceof WP_User ) {
			return;
		}
		$revoked = self::rule_m( $user, $old_user );
		Signals::on_profile_update( $user, $old_user, $revoked );
	}

	/**
	 * Rule M when the email changed case-insensitively and the filter
	 * allows it; true when it ran.
	 *
	 * @param WP_User $user     The account after the update.
	 * @param WP_User $old_user The account before it.
	 */
	private static function rule_m( WP_User $user, WP_User $old_user ): bool {
		$user_id   = (int) $user->ID;
		$old_email = (string) $old_user->user_email;
		$new_email = (string) $user->user_email;
		if ( strtolower( $old_email ) === strtolower( $new_email ) ) {
			return false;
		}

		// Links and codes sent to the old mailbox die with it, whatever the
		// filter says (core clears user_activation_key the same way).
		TokenManager::invalidate_outstanding_for_user( $user_id );
		TokenManager::invalidate_outstanding_for_email( magicauth_hash_email( $old_email ) );

		if ( true !== (bool) apply_filters( 'magicauth_passkey_revoke_on_email_change', true, $user, $old_user ) ) {
			return false;
		}

		$count = CredentialStore::delete_all_for_user( $user_id );
		if ( $count instanceof WP_Error ) {
			// Logged by the store; the rest still runs so no old-mailbox proof survives.
			$count = 0;
		}
		// changed_at first: a step-up that re-reads it after writing its own
		// stamps (AccountEndpoints::reauth_code) then always sees one or the
		// other of the change and this delete.
		update_user_meta( $user_id, 'magicauth_email_changed_at', Clock::now() );
		delete_user_meta( $user_id, 'magicauth_email_verified_at' );
		ChallengeStore::delete_for_user( $user_id );
		SessionState::clear_reauth_for_user( $user_id );

		if ( $count > 0 ) {
			self::send_removed( $user_id, $count, 'system', 'email_changed', [ $old_email, $new_email ] );
		}
		do_action( 'magicauth_passkeys_revoked', $user_id, get_current_user_id(), $count, 'email_change' );
		return true;
	}

	/**
	 * The passkeys-removed email (10.4), after the response.
	 *
	 * @param int               $user_id Owner.
	 * @param int               $count   Passkeys removed.
	 * @param string            $actor   self | admin | system.
	 * @param string            $reason  removed | email_changed.
	 * @param array<int,string> $to      Recipients; the account's address when empty.
	 */
	public static function send_removed( int $user_id, int $count, string $actor, string $reason, array $to = [] ): void {
		if ( $user_id <= 0 || $count < 1 ) {
			return;
		}
		magicauth_dispatch_after_response(
			static function () use ( $user_id, $count, $actor, $reason, $to ): void {
				Mailer::send_passkeys_removed( $user_id, $count, $actor, $reason, $to );
			}
		);
	}

	/**
	 * The passkey-blocked email (10.5), after the response. Callers send it
	 * only when their block() UPDATE changed the row, so it goes once.
	 *
	 * @param int $user_id Owner.
	 * @param int $row_id  Credential row id.
	 */
	public static function send_blocked( int $user_id, int $row_id ): void {
		if ( $user_id <= 0 || $row_id <= 0 ) {
			return;
		}
		magicauth_dispatch_after_response(
			static function () use ( $user_id, $row_id ): void {
				Mailer::send_passkey_blocked( $user_id, $row_id );
			}
		);
	}
}
