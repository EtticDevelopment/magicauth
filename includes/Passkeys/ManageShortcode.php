<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Passkeys;

defined( 'ABSPATH' ) || exit;

use MagicAuth\Email\Mailer;

/**
 * [magicauth_passkeys] (SPEC 2.3, 8.5, 8.11, 6.11): the signed-in user's
 * passkey list with add, rename, remove and "Sign out on all other devices".
 * Registered by Module::setup() whatever the toggle; with the module off it
 * renders '' instead of the literal shortcode text.
 *
 * Logged out it renders nothing at all: decision 2 forbids mentioning
 * creation on logged-out pages (T-OFFER-5). Pages that show the list carry a
 * user-bound nonce and credential IDs, so they are made uncacheable: by
 * Prompt::prepare_front() on template_redirect when the page is detected
 * early (headers still sendable), and by DONOTCACHEPAGE from the render
 * callback itself for a shortcode the detection missed (a theme template,
 * pattern or template part).
 */
final class ManageShortcode {

	public const TAG = 'magicauth_passkeys';

	/** Unique element ids per render. */
	private static int $instance = 0;

	/**
	 * Shortcode callback; '' when logged out or the module is off.
	 *
	 * @param array<string,mixed>|string $atts Unused.
	 */
	public static function render( $atts = [] ): string {
		unset( $atts );
		if ( ! is_user_logged_in() || ! Module::enabled() ) {
			return '';
		}
		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			define( 'DONOTCACHEPAGE', true );
		}
		$user  = wp_get_current_user();
		$items = AccountEndpoints::items( $user, true );

		// Late enqueue: printed in the footer when the early detection missed this page.
		Assets::enqueue_account( $user, $items );

		return self::render_template(
			[
				'mode'               => 'manage',
				'items'              => (array) $items,
				'list_error'         => null === $items,
				'dialogs'            => true,
				'can_add'            => true,
				'can_rename'         => true,
				'can_signout_others' => true,
				'can_remove_all'     => false,
				'own'                => true,
				'module_off'         => false,
				'user_id'            => (int) $user->ID,
				'admin_nonce'        => '',
				'display_name'       => '',
				'heading_tag'        => 'h2',
			]
		);
	}

	/**
	 * Management page (8.11, one definition for 2.1 check 2, 6.11 and the
	 * asset rules): a front-end singular request for the chosen page, or whose
	 * queried post holds the shortcode, or magicauth_force_passkeys_manage_assets.
	 */
	public static function is_management_page(): bool {
		if ( is_admin() ) {
			return false;
		}
		if ( (bool) apply_filters( 'magicauth_force_passkeys_manage_assets', false ) ) {
			return true;
		}
		if ( ! is_singular() ) {
			return false;
		}
		$page_id = absint( magicauth_get_setting( 'passkeys_manage_page_id', 0 ) );
		if ( $page_id > 0 && is_page( $page_id ) ) {
			return true;
		}
		$post = get_queried_object();
		return $post instanceof \WP_Post && has_shortcode( (string) $post->post_content, self::TAG );
	}

	/**
	 * passkeys-manage.php through the theme lookup (8.5 item 5), with the
	 * strings, the request's render key and a unique instance number unless
	 * $args has one.
	 *
	 * @internal Shared with ProfileSection.
	 * @param array<string,mixed> $args Template args.
	 */
	public static function render_template( array $args ): string {
		if ( ! isset( $args['instance'] ) ) {
			$args['instance'] = self::next_instance();
		}
		return Mailer::render(
			'passkeys-manage.php',
			$args + [
				'strings' => self::strings(),
				'part'    => 'section',
				'render'  => Assets::render_key(),
			]
		);
	}

	/**
	 * A new unique instance number; ProfileSection keeps one for its section
	 * and its footer dialogs, so the section can name the dialog ids.
	 *
	 * @internal Shared with ProfileSection.
	 */
	public static function next_instance(): int {
		return ++self::$instance;
	}

	/**
	 * Strings of the management list, step-up view, remove dialogs and the
	 * create flow (9.3, 9.4, 9.5 and the P strings the create flow shows),
	 * keyed by their IDs. Filter magicauth_passkey_manage_strings (8.10).
	 *
	 * @return array<string,string>
	 */
	public static function strings(): array {
		$strings = [
			'M1'   => __( 'Passkeys', 'magicauth' ),
			'M2'   => __( 'A passkey lets you sign in with your fingerprint, face or screen lock instead of an email code. You can always sign in with your email as well.', 'magicauth' ),
			'M3'   => __( 'You have no passkeys yet.', 'magicauth' ),
			'M4'   => __( 'Add a passkey', 'magicauth' ),
			'M5'   => __( 'Do not add a passkey on a device that other people also use.', 'magicauth' ),
			'M6'   => __( 'Synced across your devices', 'magicauth' ),
			'M6b'  => __( 'Can be synced, not synced yet', 'magicauth' ),
			'M7'   => __( 'This device only', 'magicauth' ),
			'M10'  => __( 'Not used yet', 'magicauth' ),
			'M11'  => __( 'Cannot be used on this site address', 'magicauth' ),
			'M12'  => __( 'This passkey was blocked because it may have been copied. Remove it and add a new one.', 'magicauth' ),
			'M13'  => __( 'New', 'magicauth' ),
			'M14v' => __( 'Rename', 'magicauth' ),
			/* translators: Hidden end of the Rename button's accessible name, after "Rename"; %s: passkey name. */
			'M14s' => __( 'passkey %s', 'magicauth' ),
			'M15'  => __( 'Passkey name', 'magicauth' ),
			'M16'  => __( 'Save', 'magicauth' ),
			'M17'  => __( 'Cancel', 'magicauth' ),
			'M18v' => __( 'Remove', 'magicauth' ),
			/* translators: Hidden end of the Remove button's accessible name, after "Remove"; %s: passkey name. */
			'M18s' => _x( 'passkey %s', 'after Remove', 'magicauth' ),
			'M19'  => __( 'Remove this passkey?', 'magicauth' ),
			/* translators: %s: passkey name */
			'M20'  => __( 'You can no longer sign in with "%s" after this. You can still sign in with your email.', 'magicauth' ),
			'M21'  => __( 'Remove passkey', 'magicauth' ),
			'M22'  => __( 'Passkey removed.', 'magicauth' ),
			'M23'  => __( 'Passkey renamed.', 'magicauth' ),
			'M24'  => __( 'Passkey added.', 'magicauth' ),
			'M25'  => __( 'Enter a name of up to 64 characters.', 'magicauth' ),
			'M26'  => __( 'You need JavaScript to manage passkeys. Turn on JavaScript in your browser and reload this page.', 'magicauth' ),
			'M27'  => __( 'This browser cannot create passkeys. You can still remove passkeys here.', 'magicauth' ),
			'M30'  => __( 'Unknown provider', 'magicauth' ),
			/* translators: %s: passkey provider name, as the device reports it. */
			'M31'  => __( '%s (reported by the device)', 'magicauth' ),
			'M32'  => __( 'Sign out on all other devices', 'magicauth' ),
			'M33'  => __( 'Also sign out on all other devices', 'magicauth' ),
			'M35'  => __( 'You already have a passkey with this name. Choose another name.', 'magicauth' ),
			'M36'  => __( 'Blocked', 'magicauth' ),
			'M38'  => __( 'You are signed out on all other devices.', 'magicauth' ),
			'MX'   => __( 'Your passkeys could not be loaded. Reload this page to try again.', 'magicauth' ),
			'MG'   => __( 'Something went wrong. Please try again.', 'magicauth' ),
			'X1'   => __( 'Your session has ended. Sign in again.', 'magicauth' ),
			'R1'   => __( 'Confirm it is you', 'magicauth' ),
			'R2'   => __( 'For your security, confirm it is you before you add a passkey.', 'magicauth' ),
			'R3'   => __( 'Send a code to my email', 'magicauth' ),
			'R4'   => __( 'Use an existing passkey', 'magicauth' ),
			/* translators: %s: masked email address, for example l***@example.com */
			'R5'   => __( 'We sent a 6-character code to %s. The code is valid for 10 minutes.', 'magicauth' ),
			'R6'   => __( 'Confirmation code', 'magicauth' ),
			'R7'   => __( 'Confirm', 'magicauth' ),
			'R8'   => __( 'That code is not correct or has expired. Check the code, or send a new one.', 'magicauth' ),
			'R10'  => __( 'Confirmed. You can now create your passkey.', 'magicauth' ),
			'R11'  => __( 'That did not work. Try again, or confirm with a code from your email.', 'magicauth' ),
			'R12'  => __( 'Too many attempts. Please try again later.', 'magicauth' ),
			'R13'  => __( 'Send a new code', 'magicauth' ),
			'R14'  => __( 'Sign out and sign in again with your email to add a passkey.', 'magicauth' ),
			'P7'   => __( 'Follow the steps in your browser.', 'magicauth' ),
			'P10'  => __( 'No passkey was created. You can try again, or keep signing in with your email.', 'magicauth' ),
			'P11'  => __( 'This device already has a passkey for your account.', 'magicauth' ),
			'P12'  => __( 'Passkeys are not available on this site right now.', 'magicauth' ),
			'P13'  => __( 'This device or security key cannot create a passkey with a screen lock. Try your phone or another device.', 'magicauth' ),
			'P14'  => __( 'Something went wrong while creating the passkey. Please try again.', 'magicauth' ),
			'P15'  => __( 'The passkey could not be saved. Please try again.', 'magicauth' ),
			'A1'   => __( 'Passkeys', 'magicauth' ),
			'A2'   => __( 'Remove all passkeys', 'magicauth' ),
			/* translators: %s: the user's display name */
			'A3'   => __( 'Remove all passkeys for %s? They can still sign in with their email.', 'magicauth' ),
			'A5'   => __( 'This user has no passkeys.', 'magicauth' ),
			'A8'   => __( 'Passkeys are turned off for this site. You can still remove stored passkeys.', 'magicauth' ),
			'A9'   => __( 'Also sign this user out everywhere', 'magicauth' ),
		];
		$filtered = apply_filters( 'magicauth_passkey_manage_strings', $strings );
		if ( ! is_array( $filtered ) ) {
			return $strings;
		}
		// Only known keys, only strings: a filter cannot add markup slots or remove a string.
		foreach ( $strings as $key => $value ) {
			if ( isset( $filtered[ $key ] ) && is_string( $filtered[ $key ] ) ) {
				$strings[ $key ] = $filtered[ $key ];
			}
		}
		return $strings;
	}
}
