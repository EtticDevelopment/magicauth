<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Passkeys;

defined( 'ABSPATH' ) || exit;

use MagicAuth\Email\Mailer;
use WP_User;

/**
 * Post-login enrollment prompt and session-time signals (SPEC 2.1, 6.8, 6.11,
 * 8.7, 8.11). Registered by Module::register() only while the module is
 * enabled.
 *
 * Decided on template_redirect PHP_INT_MAX (front end, after canonical and
 * theme redirects, headers still sendable) or current_screen (wp-admin
 * dashboard). The decision only prepares: no-store headers, the enqueue and
 * the pending footer render. render_footer() prints the dialog and only then
 * commits prompt_done (and signals_at) to the session state row, so a request
 * that redirects, exits or never reaches the footer consumes nothing.
 *
 * The prompt is offered only to a signed-in session created by an email
 * sign-in (2.6 row 7): check 4 needs a logged-in user, check 5 a creation
 * stamp of link or code in the session record, which only a signed-in session
 * has.
 */
final class Prompt {

	/** Shared-device cookie (5.3): the browser profile never gets the prompt again. */
	public const COOKIE = 'magicauth_pk_shared';

	/** Cadence user meta { declines, next_at } (5.3). */
	public const META = 'magicauth_passkey_prompt';

	/** Choices of magicauth_passkey_prompt (6.8). */
	public const CHOICES = [ 'later', 'dismiss', 'failed', 'device' ];

	/** Check 7: the prompt belongs to the sign-in moment. */
	private const WINDOW = 1800;

	/** Default prompt methods (check 5); the filter cannot add a method that cannot make a session fresh. */
	private const METHODS = [ 'link', 'code' ];

	/** "later" stops the prompt for the account at this many declines. */
	private const MAX_DECLINES = 3;

	/** "later" waits, in days, after decline 1 and 2. */
	private const LATER_DAYS = [ 30, 90 ];

	private const DISMISS_DAYS = 7;

	private const FAILED_DAYS = 30;

	private const SHARED_MAX_AGE = 31536000;

	/**
	 * What prepare_front() / prepare_admin() decided for this request, for
	 * render_footer(); null when nothing is pending.
	 *
	 * @var array{prompt:bool,signals:bool,has_passkeys:bool,user:int}|null
	 */
	private static $pending = null;

	/** @var int|null Credential count for the RP ID from check 10. */
	private static $count = null;

	/** @var array{row:?object,error:bool}|null The session state read of this decision; null: not read yet. */
	private static $row = null;

	/**
	 * Server eligibility (2.1), checks in the spec's order, cheapest first,
	 * stopping at the first failure; check 10 (the COUNT query) runs last.
	 *
	 * @param WP_User $user The signed-in user.
	 */
	public static function eligible( WP_User $user ): bool {
		self::$count = null;
		self::$row   = null;
		$uid         = (int) $user->ID;

		// 1. Module and prompt setting on.
		if ( ! Module::enabled() || empty( magicauth_get_setting( 'passkeys_prompt', true ) ) ) {
			return false;
		}
		// 2. A front-end HTML page that is not a management page, or the dashboard.
		if ( ! self::prompt_request() ) {
			return false;
		}
		// 3. Theme escape hatch.
		if ( ! (bool) apply_filters( 'magicauth_passkey_prompt_eligible', true, $user ) ) {
			return false;
		}
		// 4. Signed in as this user; not disabled.
		if ( $uid <= 0 || ! is_user_logged_in() || get_current_user_id() !== $uid || get_user_meta( $uid, 'magicauth_disabled', true ) ) {
			return false;
		}
		// 5. The core record exists and was created by an email sign-in.
		$session = Freshness::session();
		$method  = null !== $session ? ( $session['magicauth_method'] ?? null ) : null;
		if ( ! is_string( $method ) || ! in_array( $method, self::methods(), true ) ) {
			return false;
		}
		// 6. Not shown in this session yet (no row yet counts as not shown; a failed read does not).
		$state = self::state_row();
		if ( $state['error'] || ( null !== $state['row'] && 0 !== (int) $state['row']->prompt_done ) ) {
			return false;
		}
		// 7. Within 30 minutes of the sign-in.
		$auth_at = $session['magicauth_auth_at'] ?? null;
		if ( ! is_int( $auth_at ) || Clock::now() - $auth_at > self::WINDOW ) {
			return false;
		}
		// 8. Not a device marked shared.
		if ( isset( $_COOKIE[ self::COOKIE ] ) ) {
			return false;
		}
		// 9. Cadence.
		$cadence = self::cadence( $uid );
		if ( $cadence['declines'] >= self::MAX_DECLINES || $cadence['next_at'] > Clock::now() ) {
			return false;
		}
		// 10. Below the per-user maximum for this RP ID (a failed count is not "below").
		$count = CredentialStore::count_for_user( $user, RelyingParty::id() );
		if ( null === $count || $count >= Module::max_per_user() ) {
			return false;
		}
		self::$count = $count;
		return true;
	}

	/**
	 * template_redirect PHP_INT_MAX (2.1, 6.11, 8.7, 8.11): decides the prompt,
	 * the session-time signals and the management-page headers. Any of them
	 * makes the page uncacheable (DONOTCACHEPAGE, no-store) before output
	 * starts. The prompt enqueues the account assets; signals alone enqueue
	 * only the core script with an inline call. A management page gets its
	 * account assets from Assets::enqueue_front().
	 */
	public static function prepare_front(): void {
		self::$pending = null;
		if ( is_admin() || ! is_user_logged_in() || ! Module::enabled() ) {
			return;
		}
		$user    = wp_get_current_user();
		$manage  = ManageShortcode::is_management_page();
		$prompt  = self::eligible( $user );
		$signals = self::html_request() && self::signals_due( $user );
		if ( ! $prompt && ! $signals && ! $manage ) {
			return;
		}

		self::no_store();
		if ( $prompt ) {
			$prompt = Assets::enqueue_account( $user, AccountEndpoints::items( $user, true ), true, $signals );
		} elseif ( $signals && ! $manage ) {
			Assets::enqueue_signals( $user );
		}
		self::$pending = [
			'prompt'       => $prompt,
			'signals'      => $signals,
			'has_passkeys' => (int) self::$count > 0,
			'user'         => (int) $user->ID,
		];
	}

	/**
	 * current_screen (2.1): the prompt on the wp-admin dashboard (Q11). The
	 * account assets are enqueued here; admin_enqueue_scripts prints them.
	 *
	 * @param mixed $screen WP_Screen (check 2 reads get_current_screen()).
	 */
	public static function prepare_admin( $screen = null ): void {
		unset( $screen );
		self::$pending = null;
		if ( ! is_admin() || ! is_user_logged_in() || ! Module::enabled() ) {
			return;
		}
		$user = wp_get_current_user();
		if ( ! self::eligible( $user ) ) {
			return;
		}
		self::no_store();
		if ( ! Assets::enqueue_account( $user, AccountEndpoints::items( $user, true ), true, false ) ) {
			return;
		}
		self::$pending = [
			'prompt'       => true,
			'signals'      => false,
			'has_passkeys' => (int) self::$count > 0,
			'user'         => (int) $user->ID,
		];
	}

	/**
	 * wp_footer 20 and admin_footer 20: prints the prompt dialog, then commits
	 * prompt_done (a printed prompt counts as shown, whatever the client
	 * decides); commits signals_at once a config carried the signals. Runs
	 * once per request.
	 */
	public static function render_footer(): void {
		$pending       = self::$pending;
		self::$pending = null;
		if ( null === $pending || get_current_user_id() !== $pending['user'] ) {
			return;
		}
		if ( $pending['prompt'] ) {
			$user = wp_get_current_user();
			echo self::render_template( $user, $pending['has_passkeys'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- the template escapes every value.
			SessionState::set( 'prompt_done', 1 );
		}
		if ( $pending['signals'] && Assets::signals_delivered() ) {
			SessionState::set( 'signals_at', Clock::now() );
		}
	}

	/**
	 * A prompt choice (6.8, 2.1 cadence) for the account; 'device' is the
	 * cookie and never touches user meta.
	 *
	 * @param int    $user_id The signed-in user.
	 * @param string $choice  later | dismiss | failed.
	 */
	public static function record_choice( int $user_id, string $choice ): void {
		if ( $user_id <= 0 ) {
			return;
		}
		$cadence = self::cadence( $user_id );
		$now     = Clock::now();
		if ( 'later' === $choice ) {
			$declines = $cadence['declines'] + 1;
			$next_at  = $cadence['next_at'];
			if ( $declines < self::MAX_DECLINES ) {
				$next_at = $now + self::LATER_DAYS[ max( 0, $declines - 1 ) ] * DAY_IN_SECONDS;
			}
			$cadence = [
				'declines' => $declines,
				'next_at'  => $next_at,
			];
		} elseif ( 'dismiss' === $choice ) {
			$cadence['next_at'] = max( $cadence['next_at'], $now + self::DISMISS_DAYS * DAY_IN_SECONDS );
		} elseif ( 'failed' === $choice ) {
			$cadence['next_at'] = max( $cadence['next_at'], $now + self::FAILED_DAYS * DAY_IN_SECONDS );
		} else {
			return;
		}
		update_user_meta( $user_id, self::META, $cadence );
	}

	/**
	 * magicauth_pk_shared=1 (2.1, 5.3): Path /, one year, HttpOnly, Secure on
	 * https, SameSite=Lax, COOKIE_DOMAIN honoured as the session cookie.
	 */
	public static function set_shared_cookie(): void {
		Http::set_cookie(
			self::COOKIE,
			'1',
			[
				'expires'  => Clock::now() + self::SHARED_MAX_AGE,
				'path'     => '/',
				'domain'   => defined( 'COOKIE_DOMAIN' ) && COOKIE_DOMAIN ? (string) COOKIE_DOMAIN : '',
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			]
		);
	}

	/**
	 * The account's cadence meta, malformed values read as the default.
	 *
	 * @param int $user_id The account.
	 * @return array{declines:int,next_at:int}
	 */
	public static function cadence( int $user_id ): array {
		$meta = get_user_meta( $user_id, self::META, true );
		$meta = is_array( $meta ) ? $meta : [];
		return [
			'declines' => isset( $meta['declines'] ) && is_numeric( $meta['declines'] ) ? max( 0, (int) $meta['declines'] ) : 0,
			'next_at'  => isset( $meta['next_at'] ) && is_numeric( $meta['next_at'] ) ? max( 0, (int) $meta['next_at'] ) : 0,
		];
	}

	/**
	 * Prompt strings P1 to P19 (9.2), keyed by their IDs; P8 already names
	 * L1. Filter magicauth_passkey_prompt_strings( $strings, $user ): known
	 * keys and strings only.
	 *
	 * @param WP_User $user The signed-in user.
	 * @return array<string,string>
	 */
	public static function strings( WP_User $user ): array {
		$strings = [
			'P1'   => __( 'Sign in faster next time', 'magicauth' ),
			'P1b'  => __( 'Add a passkey for this device', 'magicauth' ),
			'P2'   => __( 'Create a passkey on this device. Next time you can sign in with your fingerprint, face or screen lock instead of an email code.', 'magicauth' ),
			'P3'   => __( 'Your passkey is stored on your device or in your password manager. You can always sign in with your email instead.', 'magicauth' ),
			'P4'   => __( 'Create a passkey', 'magicauth' ),
			'P5'   => __( 'Not now', 'magicauth' ),
			'P6'   => __( 'This is a shared device. Do not ask again on this device.', 'magicauth' ),
			'P7'   => __( 'Follow the steps in your browser.', 'magicauth' ),
			/* translators: %s: the label of the sign-in button, "Sign in with a passkey". */
			'P8'   => __( 'Passkey created. Next time, choose "%s".', 'magicauth' ),
			'P9'   => __( 'Done', 'magicauth' ),
			'P10'  => __( 'No passkey was created. You can try again, or keep signing in with your email.', 'magicauth' ),
			'P10b' => __( 'If you opened this page from an email app, open it in your browser and try again.', 'magicauth' ),
			'P11'  => __( 'This device already has a passkey for your account.', 'magicauth' ),
			'P12'  => __( 'Passkeys are not available on this site right now.', 'magicauth' ),
			'P13'  => __( 'This device or security key cannot create a passkey with a screen lock. Try your phone or another device.', 'magicauth' ),
			'P14'  => __( 'Something went wrong while creating the passkey. Please try again.', 'magicauth' ),
			'P15'  => __( 'The passkey could not be saved. Please try again.', 'magicauth' ),
			'P17'  => __( 'Close', 'magicauth' ),
			'P18'  => __( 'Try again', 'magicauth' ),
			'P19'  => __( 'Manage passkeys', 'magicauth' ),
		];
		$filtered = apply_filters( 'magicauth_passkey_prompt_strings', $strings, $user );
		if ( is_array( $filtered ) ) {
			foreach ( $strings as $key => $value ) {
				if ( isset( $filtered[ $key ] ) && is_string( $filtered[ $key ] ) ) {
					$strings[ $key ] = $filtered[ $key ];
				}
			}
		}
		// No sprintf(): a filtered P8 with more placeholders must not throw.
		$l1            = SignInEndpoints::strings()['L1'];
		$strings['P8'] = strtr(
			$strings['P8'],
			[
				'%1$s' => $l1,
				'%s'   => $l1,
			]
		);
		return $strings;
	}

	/** Test-only: forget the pending decision. No-op outside MAGICAUTH_TESTING. */
	public static function reset_for_tests(): void {
		if ( defined( 'MAGICAUTH_TESTING' ) && MAGICAUTH_TESTING ) {
			self::$pending = null;
			self::$count   = null;
			self::$row     = null;
		}
	}

	/**
	 * The prompt dialog through the theme lookup (8.5, 8.10), with the
	 * step-up view in its own form.
	 *
	 * @param WP_User $user         The signed-in user.
	 * @param bool    $has_passkeys P1b instead of P1.
	 */
	private static function render_template( WP_User $user, bool $has_passkeys ): string {
		return Mailer::render(
			'passkey-prompt.php',
			[
				'strings'      => array_merge( ManageShortcode::strings(), self::strings( $user ) ),
				'has_passkeys' => $has_passkeys,
				'manage_url'   => Module::manage_url( $user ),
				'render'       => Assets::render_key(),
			]
		);
	}

	/**
	 * Methods that get the prompt (check 5): the filtered list, kept only
	 * where the method makes a session fresh (Freshness::FRESH_METHODS), so
	 * admin_link and password never qualify, whatever the filter returns.
	 *
	 * @return array<int,string>
	 */
	private static function methods(): array {
		$filtered = apply_filters( 'magicauth_passkey_prompt_methods', self::METHODS );
		if ( ! is_array( $filtered ) ) {
			return [];
		}
		return array_values( array_intersect( Freshness::FRESH_METHODS, $filtered ) );
	}

	/** Check 2: a front-end HTML page that is not a management page, or the dashboard screen. */
	private static function prompt_request(): bool {
		if ( wp_doing_ajax() ) {
			return false;
		}
		if ( is_admin() ) {
			$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
			return $screen instanceof \WP_Screen && 'dashboard' === $screen->id;
		}
		return self::html_request() && ! ManageShortcode::is_management_page();
	}

	/** A front-end request that renders an HTML page (no ajax, JSON, feed, embed, preview or robots.txt). */
	private static function html_request(): bool {
		return ! is_admin() && ! wp_doing_ajax() && ! wp_is_json_request() && ! is_feed() && ! is_embed() && ! is_customize_preview() && ! is_robots();
	}

	/**
	 * Signals due (8.7): the user has a handle, and this session has not had
	 * them yet, or the account details changed since (details_at >
	 * signals_at). A failed read is not due.
	 *
	 * @param WP_User $user The signed-in user.
	 */
	private static function signals_due( WP_User $user ): bool {
		if ( null === CredentialStore::user_handle( (int) $user->ID, false ) || null === Freshness::session() ) {
			return false;
		}
		$state = self::state_row();
		if ( $state['error'] || null === $state['row'] ) {
			return ! $state['error'];
		}
		$signals_at = (int) $state['row']->signals_at;
		if ( 0 === $signals_at ) {
			return true;
		}
		return (int) get_user_meta( (int) $user->ID, 'magicauth_passkey_details_at', true ) > $signals_at;
	}

	/**
	 * This decision's session state row, read once (eligible() resets it):
	 * no row yet and a failed read are told apart.
	 *
	 * @return array{row:?object,error:bool}
	 */
	private static function state_row(): array {
		global $wpdb;
		if ( null === self::$row ) {
			$row       = SessionState::get();
			self::$row = [
				'row'   => $row,
				'error' => null === $row && '' !== $wpdb->last_error,
			];
		}
		return self::$row;
	}

	/** DONOTCACHEPAGE (Batcache reads it at buffer close) and no-store headers, before output. */
	private static function no_store(): void {
		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			define( 'DONOTCACHEPAGE', true );
		}
		Http::no_store();
	}
}
