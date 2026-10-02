<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Passkeys;

defined( 'ABSPATH' ) || exit;

use WP_User;

/**
 * The wp-admin profile section (SPEC 2.3, 2.4, 8.5): its own registration on
 * show_user_profile and edit_user_profile at 9, after MagicAuth's table at 8,
 * whatever the toggle says (inside is_admin()).
 *
 * Own profile with the module on: the management list with add, rename,
 * remove and sign-out, through the account endpoints. Own profile with the
 * module off: the list read-only plus Remove through the admin endpoint
 * (user_id = self). Another user: only with
 * magicauth_current_user_can_revoke_passkeys(); the list without credential
 * IDs, Remove and "Remove all passkeys"; never Add. Shown while the module is
 * enabled, or when the target has a stored passkey (data stays removable).
 *
 * Core prints these hooks inside <form id="your-profile">, so the section has
 * no <form>, no <dialog> and only type="button" buttons; the dialogs are
 * printed on admin_footer, outside the form (render_dialogs()).
 */
final class ProfileSection {

	/**
	 * The section rendered on this request, for render_dialogs().
	 *
	 * @var array<string,mixed>|null
	 */
	private static ?array $rendered = null;

	/**
	 * Views decided on this request, by target id (enqueue and render share one query).
	 *
	 * @var array<int,array<string,mixed>|null>
	 */
	private static array $views = [];

	/**
	 * show_user_profile / edit_user_profile 9.
	 *
	 * @param mixed $profileuser The user being edited.
	 */
	public static function render( $profileuser ): void {
		if ( ! $profileuser instanceof WP_User ) {
			return;
		}
		$view = self::view( $profileuser );
		if ( null === $view ) {
			return;
		}
		$args = $view + [
			'admin_nonce'  => wp_create_nonce( AdminEndpoints::NONCE ),
			'dialogs'      => false,
			'heading_tag'  => 'h2',
			'display_name' => (string) $profileuser->display_name,
			'instance'     => ManageShortcode::next_instance(),
		];

		self::$rendered = $args;
		echo ManageShortcode::render_template( $args ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- the template escapes every value.
	}

	/**
	 * admin_footer: the remove-confirm dialogs and, for the own profile with
	 * the module on, the step-up dialog with its own form, outside
	 * #your-profile.
	 */
	public static function render_dialogs(): void {
		if ( null === self::$rendered ) {
			return;
		}
		echo ManageShortcode::render_template( [ 'part' => 'dialogs' ] + self::$rendered ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- the template escapes every value.
	}

	/**
	 * What the section shows for $target to the current user, or null for no
	 * section (see the class docblock).
	 *
	 * @internal Shared with Assets::enqueue_admin().
	 * @return array<string,mixed>|null
	 */
	public static function view( WP_User $target ): ?array {
		$tid = (int) $target->ID;
		if ( array_key_exists( $tid, self::$views ) ) {
			return self::$views[ $tid ];
		}
		self::$views[ $tid ] = self::decide( $target );
		return self::$views[ $tid ];
	}

	/** Test-only: forget the per-request state. No-op outside MAGICAUTH_TESTING. */
	public static function reset_for_tests(): void {
		if ( defined( 'MAGICAUTH_TESTING' ) && MAGICAUTH_TESTING ) {
			self::$rendered = null;
			self::$views    = [];
		}
	}

	/** @return array<string,mixed>|null */
	private static function decide( WP_User $target ): ?array {
		$tid = (int) $target->ID;
		if ( $tid <= 0 || ! is_user_logged_in() ) {
			return null;
		}
		$own = get_current_user_id() === $tid;
		if ( ! $own && ! magicauth_current_user_can_revoke_passkeys( $tid ) ) {
			return null;
		}
		$enabled = Module::enabled();
		$items   = AccountEndpoints::items( $target, $own );
		if ( ! $enabled && ( null === $items || [] === $items ) ) {
			return null;
		}
		$manage = $own && $enabled;
		return [
			'mode'               => $manage ? 'manage' : 'admin',
			'items'              => (array) $items,
			'list_error'         => null === $items,
			'can_add'            => $manage,
			'can_rename'         => $manage,
			'can_signout_others' => $manage,
			'can_remove_all'     => ! $own,
			'own'                => $own,
			'module_off'         => ! $enabled,
			'user_id'            => $tid,
		];
	}
}
