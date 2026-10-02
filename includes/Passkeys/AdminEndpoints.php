<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Passkeys;

defined( 'ABSPATH' ) || exit;

use WP_Error;
use WP_User;

/**
 * Admin passkey removal (SPEC 2.4, 6.12): one passkey or all passkeys of a
 * user, from the wp-admin profile screens. Registered inside is_admin()
 * whatever the toggle says, so stored data can be removed after the module
 * is switched off; the own-profile section uses these too while the module
 * is off (user_id = self).
 *
 * Removal only: no endpoint creates a credential for another user (1.3).
 * Another user's passkeys need magicauth_current_user_can_revoke_passkeys().
 */
final class AdminEndpoints {

	/** Nonce action (6.11), created by ProfileSection::render(). */
	public const NONCE = 'magicauth-passkeys-admin';

	/** magicauth_admin_passkey_delete: one passkey of the target. */
	public static function delete(): void {
		Http::require_post();
		$target = self::require_target();
		$tid    = (int) $target->ID;
		$self   = get_current_user_id() === $tid;

		$id    = Http::field( 'id', 20 );
		$id    = null !== $id && 1 === preg_match( '/^[1-9][0-9]{0,18}$/', $id ) ? (int) $id : 0;
		$fresh = $self && Freshness::is_fresh();
		$done  = CredentialStore::delete( $tid, $id );
		if ( $done instanceof WP_Error ) {
			if ( 'magicauth_db_error' === $done->get_error_code() ) {
				self::retry();
			}
			self::fail( 'not_found', 404 );
		}
		ChallengeStore::delete_completions_for_user( $tid );

		$signed_out = self::sign_out( $tid, $self );
		// Self from a fresh session proved the mailbox or a passkey just now (10.4).
		if ( ! $fresh ) {
			AccountEvents::send_removed( $tid, 1, $self ? 'self' : 'admin', 'removed' );
		}
		do_action( 'magicauth_passkey_removed', $tid, $id, $self ? 'user' : 'admin' );

		Http::ok( array_merge( AccountEndpoints::list_fields( AccountEndpoints::items( $target, $self ) ), [ 'signed_out' => $signed_out ] ) );
	}

	/**
	 * magicauth_admin_passkey_revoke_all: every credential row (all RP IDs),
	 * challenge rows and session state rows of the target; the user handle is
	 * kept (checklist 1.3.3).
	 */
	public static function revoke_all(): void {
		Http::require_post();
		$target = self::require_target();
		$tid    = (int) $target->ID;
		$self   = get_current_user_id() === $tid;

		$count = CredentialStore::delete_all_for_user( $tid );
		if ( $count instanceof WP_Error ) {
			self::retry();
		}
		ChallengeStore::delete_for_user( $tid );
		SessionState::delete_for_user( $tid );

		$signed_out = self::sign_out( $tid, $self );
		if ( $count > 0 ) {
			AccountEvents::send_removed( $tid, $count, $self ? 'self' : 'admin', 'removed' );
		}
		do_action( 'magicauth_passkeys_revoked', $tid, get_current_user_id(), $count, 'admin' );

		Http::ok(
			[
				'count'      => $count,
				/* translators: %d: number of passkeys removed */
				'message'    => sprintf( _n( '%d passkey removed.', '%d passkeys removed.', $count, 'magicauth' ), $count ),
				'signed_out' => $signed_out,
			]
		);
	}

	/**
	 * Gate (6.12): logged in, the admin nonce, the Origin, user_id > 0 of an
	 * existing user; another user's passkeys need
	 * magicauth_current_user_can_revoke_passkeys(). Every refusal is 403
	 * forbidden.
	 */
	private static function require_target(): WP_User {
		if ( ! is_user_logged_in()
			|| false === check_ajax_referer( self::NONCE, '_ajax_nonce', false )
			|| ! Http::origin_ok() ) {
			self::fail( 'forbidden', 403 );
		}
		$raw    = Http::field( 'user_id', 20 );
		$tid    = null !== $raw && 1 === preg_match( '/^[1-9][0-9]{0,18}$/', $raw ) ? (int) $raw : 0;
		$target = $tid > 0 ? get_userdata( $tid ) : false;
		if ( ! $target instanceof WP_User ) {
			self::fail( 'forbidden', 403 );
		}
		if ( get_current_user_id() !== $tid && ! magicauth_current_user_can_revoke_passkeys( $tid ) ) {
			self::fail( 'forbidden', 403 );
		}
		return $target;
	}

	/**
	 * signout (default 1): every session of another user, or every other
	 * session of the actor themself. True when sessions were ended.
	 */
	private static function sign_out( int $tid, bool $is_self ): bool {
		if ( ! AccountEndpoints::signout_requested( 'signout' ) ) {
			return false;
		}
		if ( $is_self ) {
			AccountEndpoints::destroy_other_sessions( $tid );
		} else {
			\WP_Session_Tokens::get_instance( $tid )->destroy_all();
		}
		return true;
	}

	/**
	 * Failure with its message.
	 *
	 * @return never
	 */
	private static function fail( string $code, int $status ): void {
		$message = 'not_found' === $code
			? __( 'This passkey no longer exists. Reload this page.', 'magicauth' )
			: __( 'You are not allowed to do this.', 'magicauth' );
		Http::fail( $code, $message, $status );
	}

	/**
	 * Database error: 503 retry.
	 *
	 * @return never
	 */
	private static function retry(): void {
		Http::fail( 'retry', __( 'Something went wrong. Please try again.', 'magicauth' ), 503 );
	}
}
