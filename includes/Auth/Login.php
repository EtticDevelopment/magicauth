<?php
/**
 * Shared sign-in completion for every method (SPEC 4.3): account-state checks,
 * session creation with the MagicAuth creation stamp, validated landing URL.
 *
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Auth;

defined( 'ABSPATH' ) || exit;

use MagicAuth\Passkeys\Clock;
use MagicAuth\Passkeys\Freshness;
use MagicAuth\Passkeys\Module;
use WP_Error;
use WP_User;

/** Sign-in completion shared by link, code, admin link, password, reset and passkey. */
final class Login {

	public const METHODS = [ 'link', 'code', 'admin_link', 'password', 'reset', 'passkey' ];

	/** Methods blocked by the per-user disable flag; not password/reset. */
	public const DISABLE_BLOCKS = [ 'link', 'code', 'admin_link', 'passkey' ];

	public const SIGNED_IN = 'signed_in';

	public const ALREADY = 'already';

	/**
	 * Account-state checks only; no side effects. Callers that must update other
	 * state before the cookie (passkey counters) call this first, then establish().
	 *
	 * @return true|WP_Error Codes: magicauth_other_account, magicauth_user_disabled,
	 *                       magicauth_login_denied, magicauth_reverify_required (passkey only).
	 */
	public static function preflight( WP_User $user, string $method ) {
		$user_id = (int) $user->ID;

		// Unknown method: fail closed.
		if ( ! in_array( $method, self::METHODS, true ) ) {
			return new WP_Error( 'magicauth_login_denied' );
		}

		// No session swap (B2).
		if ( is_user_logged_in() && get_current_user_id() !== $user_id ) {
			return new WP_Error( 'magicauth_other_account' );
		}

		// Per-user disable at consume time (B3).
		if ( in_array( $method, self::DISABLE_BLOCKS, true ) && get_user_meta( $user_id, 'magicauth_disabled', true ) ) {
			return new WP_Error( 'magicauth_user_disabled' );
		}

		// Core checks this only on authenticate, which MagicAuth does not call.
		if ( is_multisite() && is_user_spammy( $user ) ) {
			return new WP_Error( 'magicauth_login_denied' );
		}

		$allowed = apply_filters( 'magicauth_allow_login', true, $user, $method );
		if ( true !== $allowed ) {
			// A WP_Error from the filter rides along as data for logging, never shown.
			return new WP_Error( 'magicauth_login_denied', '', $allowed instanceof WP_Error ? $allowed : null );
		}

		if ( 'passkey' === $method ) {
			$reverify = self::email_reverify_error( $user );
			if ( null !== $reverify ) {
				return $reverify;
			}
		}

		return true;
	}

	/**
	 * preflight(), then: same user already signed in -> ALREADY (no cookie).
	 * Otherwise end the A->B session, set the auth cookie with the one-shot
	 * creation stamp, record the mailbox proof (link/code), set the current
	 * user, fire wp_login and magicauth_login_completed. A Throwable from the
	 * cookie step gives magicauth_cookie_failed.
	 *
	 * $proven_at is when the caller checked the proof (link or code against
	 * the current address, reset key, passkey completion token issue): the
	 * stamp's magicauth_auth_at is that time, never later, so an email change
	 * (7.6 rule M) between the check and this call leaves the session not
	 * fresh (3.4 step 6). Null means now.
	 *
	 * The mailbox proof is written before wp_login because a wp_login
	 * callback may end the request (a 2FA interstitial prints its form and
	 * exits). For the same reason magicauth_login_completed does not fire
	 * when a wp_login callback exits.
	 *
	 * @param WP_User  $user      Account to sign in.
	 * @param string   $method    One of METHODS.
	 * @param int|null $proven_at Unix time the proof was checked; null for now.
	 * @return string|WP_Error SIGNED_IN | ALREADY
	 */
	public static function establish( WP_User $user, string $method, ?int $proven_at = null ) {
		$pre = self::preflight( $user, $method );
		if ( is_wp_error( $pre ) ) {
			return $pre;
		}
		if ( is_user_logged_in() ) {
			return self::ALREADY; // Same user, guaranteed by preflight.
		}

		$user_id   = (int) $user->ID;
		$proven_at = null === $proven_at ? Clock::now() : max( 0, min( $proven_at, Clock::now() ) );

		Controller::end_session();

		// Module off: no cookie and no magicauth_fresh_hash key.
		$fresh_hash = in_array( $method, Freshness::FRESH_METHODS, true ) && self::fresh_cookie_enabled()
			? Freshness::issue_fresh_cookie()
			: null;

		$stamp = Freshness::stamp_callback( $user_id, $method, $fresh_hash, $proven_at );
		add_filter( 'attach_session_information', $stamp, 10, 2 );
		try {
			do_action( 'magicauth_pre_set_auth_cookie', $user_id, 'shortcode', $method );
			$remember = (bool) apply_filters( 'magicauth_remember_default', true, $method );
			wp_set_auth_cookie( $user_id, $remember, is_ssl() );
			// Before wp_login: a session another callback creates stays unstamped.
			remove_filter( 'attach_session_information', $stamp, 10 );
			// Rule E mailbox proof, before wp_login: a callback there may exit.
			if ( 'link' === $method || 'code' === $method ) {
				self::record_mailbox_proof( $user_id, $proven_at );
			}
			wp_set_current_user( $user_id );
			do_action( 'wp_login', $user->user_login, $user );
		} catch ( \Throwable $e ) {
			magicauth_debug_log( 'wp_set_auth_cookie threw: ' . get_class( $e ) );
			return new WP_Error( 'magicauth_cookie_failed' );
		} finally {
			remove_filter( 'attach_session_information', $stamp, 10 ); // Safety net.
		}

		do_action( 'magicauth_login_completed', $user_id, $method );

		return self::SIGNED_IN;
	}

	/**
	 * Rule E mailbox proof (7.6): magicauth_email_verified_at = now, unless
	 * the email changed at or after $proven_at. Read after the write and from
	 * the database: rule M writes magicauth_email_changed_at before it deletes
	 * the proof, so a change this read misses deletes the proof itself.
	 *
	 * @param int $user_id   Account.
	 * @param int $proven_at Unix time the mailbox was proven.
	 * @return bool Whether the proof stands.
	 */
	public static function record_mailbox_proof( int $user_id, int $proven_at ): bool {
		update_user_meta( $user_id, 'magicauth_email_verified_at', Clock::now() );
		wp_cache_delete( $user_id, 'user_meta' );
		$changed = (int) get_user_meta( $user_id, 'magicauth_email_changed_at', true );
		if ( $proven_at <= 0 || ( $changed > 0 && $changed >= $proven_at ) ) {
			delete_user_meta( $user_id, 'magicauth_email_verified_at' );
			return false;
		}
		return true;
	}

	/**
	 * Validated landing URL: form redirect_to -> redirect_to_default ->
	 * magicauth_redirect_to filter, then validated again against the home host
	 * and wp-login.php targets dropped, so JSON and redirect callers get the
	 * guarantee wp_safe_redirect() gives. admin_url() itself is kept even on
	 * another host (siteurl differs from home): wp_safe_redirect() falls back
	 * to it too, so the dashboard default lands where 1.0.5 sent it.
	 */
	public static function redirect_target( ?WP_User $user, string $redirect_to, string $method ): string {
		$home    = home_url( '/' );
		$default = self::default_redirect_target( $user );
		$target  = $default;

		if ( '' !== $redirect_to ) {
			$validated = wp_validate_redirect( $redirect_to, $default );
			// Reject wp-login.php targets: would re-render the form post-auth.
			if ( '' !== $validated && ! self::is_login_url( $validated ) ) {
				$target = $validated;
			}
		}

		$target = (string) apply_filters( 'magicauth_redirect_to', $target, $user, 'shortcode', $method );

		if ( function_exists( 'admin_url' ) && admin_url() === $target ) {
			return $target;
		}

		$target = wp_validate_redirect( $target, $home );
		if ( '' === $target || self::is_login_url( $target ) ) {
			return $home;
		}
		return $target;
	}

	/** Validate an incoming redirect_to; fall back to home_url('/'). */
	public static function sanitize_redirect( string $candidate ): string {
		$candidate = trim( $candidate );
		$default   = home_url( '/' );
		if ( '' === $candidate ) {
			return $default;
		}
		$validated = wp_validate_redirect( $candidate, '' );
		return '' !== $validated ? $validated : $default;
	}

	/** Default per redirect_to_default setting; 'auto' = admin if user_can read, else home. */
	private static function default_redirect_target( ?WP_User $user ): string {
		$choice = (string) magicauth_get_setting( 'redirect_to_default', 'auto' );
		$home   = home_url( '/' );
		$admin  = function_exists( 'admin_url' ) ? admin_url() : $home;

		switch ( $choice ) {
			case 'home':
				return $home;
			case 'admin':
				return $admin;
			case 'auto':
			default:
				if ( $user instanceof WP_User && function_exists( 'user_can' ) && user_can( $user, 'read' ) ) {
					return $admin;
				}
				return $home;
		}
	}

	private static function is_login_url( string $url ): bool {
		return false !== stripos( $url, '/wp-login.php' );
	}

	/**
	 * Rule E (SPEC 7.6): with passkeys_email_reverify_days N > 0, a passkey
	 * sign-in needs an email sign-in within N days. An address shared with
	 * another account can never reach this one by email, so it fails generic.
	 */
	private static function email_reverify_error( WP_User $user ): ?WP_Error {
		$days = max( 0, min( 730, (int) magicauth_get_setting( 'passkeys_email_reverify_days', 0 ) ) );
		if ( 0 === $days ) {
			return null;
		}
		$verified_at = (int) get_user_meta( (int) $user->ID, 'magicauth_email_verified_at', true );
		if ( Clock::now() - $verified_at <= $days * DAY_IN_SECONDS ) {
			return null;
		}
		$owner = get_user_by( 'email', $user->user_email );
		if ( ! $owner instanceof WP_User || (int) $owner->ID !== (int) $user->ID ) {
			return new WP_Error( 'magicauth_login_denied' );
		}
		return new WP_Error( 'magicauth_reverify_required' );
	}

	/**
	 * Whether a fresh sign-in issues magicauth_pk_fresh: only while the module
	 * is enabled, so a module-off response carries no new cookie (G6).
	 */
	private static function fresh_cookie_enabled(): bool {
		return Module::enabled();
	}
}
