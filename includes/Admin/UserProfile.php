<?php
/**
 * Admin user-profile integration: issue/send/reset links per user.
 *
 * Uses magicauth_current_user_can_control_user (edit_user($target) AND
 * same-or-higher-role rank gate) — naive edit_users check would let editors
 * issue admin links.
 *
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Admin;

defined( 'ABSPATH' ) || exit;

use MagicAuth\Auth\Crockford;
use MagicAuth\Auth\TokenManager;
use MagicAuth\Email\Mailer;

final class UserProfile {

	private const NONCE_ACTION = 'magicauth-user-profile';

	public static function setup(): void {
		add_action( 'show_user_profile', [ self::class, 'render_fields' ], 8 );
		add_action( 'edit_user_profile', [ self::class, 'render_fields' ], 8 );
		add_action( 'personal_options_update', [ self::class, 'save_disabled_meta' ] );
		add_action( 'edit_user_profile_update', [ self::class, 'save_disabled_meta' ] );
		add_action( 'admin_enqueue_scripts', [ self::class, 'enqueue' ] );

		add_action( 'wp_ajax_magicauth_create_login_link_for_user', [ self::class, 'ajax_create_link' ] );
		add_action( 'wp_ajax_magicauth_send_link_to_user', [ self::class, 'ajax_send_link' ] );
		add_action( 'wp_ajax_magicauth_reset_user_tokens', [ self::class, 'ajax_reset_tokens' ] );
	}

	public static function render_fields( \WP_User $user ): void {
		if ( ! magicauth_current_user_can_control_user( (int) $user->ID ) ) {
			return;
		}

		$disabled = (bool) get_user_meta( (int) $user->ID, 'magicauth_disabled', true );
		$nonce    = wp_create_nonce( self::NONCE_ACTION );
		?>
		<h2><?php esc_html_e( 'MagicAuth', 'magicauth' ); ?></h2>
		<table class="form-table magicauth-user-fields"
			data-user-id="<?php echo esc_attr( (string) $user->ID ); ?>"
			data-nonce="<?php echo esc_attr( $nonce ); ?>"
			data-ajaxurl="<?php echo esc_url( admin_url( 'admin-ajax.php' ) ); ?>">
			<tr>
				<th scope="row"><?php esc_html_e( 'Per-user controls', 'magicauth' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="magicauth_disabled" value="1" <?php checked( $disabled, true ); ?> />
						<?php esc_html_e( 'Disable magic-link sign-in for this user', 'magicauth' ); ?>
					</label>
					<p class="description">
						<?php esc_html_e( 'Saving with this checked invalidates all outstanding sign-in links for this user immediately.', 'magicauth' ); ?>
					</p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Magic-link actions', 'magicauth' ); ?></th>
				<td>
					<button type="button" class="button" data-magicauth-action="create_login_link_for_user">
						<?php esc_html_e( 'Create magic-link', 'magicauth' ); ?>
					</button>
					<button type="button" class="button" data-magicauth-action="send_link_to_user">
						<?php esc_html_e( 'Send link to user', 'magicauth' ); ?>
					</button>
					<button type="button" class="button" data-magicauth-action="reset_user_tokens">
						<?php esc_html_e( 'Reset all magic-links', 'magicauth' ); ?>
					</button>
					<p id="magicauth-user-status" class="description" aria-live="polite"></p>
					<div id="magicauth-user-link-output" class="magicauth-user-link-output" style="display:none;">
						<input type="text" readonly style="width:100%;" />
						<p class="description">
							<?php esc_html_e( 'Cleared on next page load. Copy now.', 'magicauth' ); ?>
						</p>
					</div>
				</td>
			</tr>
		</table>
		<?php
	}

	/**
	 * Save per-user disable flag. Toggling on burns outstanding tokens immediately.
	 */
	public static function save_disabled_meta( int $user_id ): void {
		if ( ! magicauth_current_user_can_control_user( $user_id ) ) {
			return;
		}

		$want_disabled = ! empty( $_POST['magicauth_disabled'] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing

		if ( $want_disabled ) {
			update_user_meta( $user_id, 'magicauth_disabled', 1 );
			TokenManager::invalidate_outstanding_for_user( $user_id );
		} else {
			delete_user_meta( $user_id, 'magicauth_disabled' );
		}
	}

	/** Enqueue only on user-edit pages where caller can control the target. */
	public static function enqueue( string $hook ): void {
		if ( ! in_array( $hook, [ 'user-edit.php', 'profile.php' ], true ) ) {
			return;
		}
		$target = isset( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : get_current_user_id(); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! magicauth_current_user_can_control_user( $target ) ) {
			return;
		}
		wp_enqueue_style( 'magicauth-admin', MAGICAUTH_URL . 'assets/css/magicauth-admin.css', [], MAGICAUTH_VERSION );
		wp_enqueue_script( 'magicauth-admin', MAGICAUTH_URL . 'assets/js/magicauth-admin.js', [ 'jquery' ], MAGICAUTH_VERSION, true );
	}

	// -------- AJAX endpoints --------

	public static function ajax_create_link(): void {
		[ $target, $email ] = self::ajax_resolve_target();
		$result             = TokenManager::issue( $target, $email );
		if ( ! is_array( $result ) ) {
			wp_send_json_error( [ 'message' => __( 'Could not issue link.', 'magicauth' ) ] );
		}

		wp_send_json_success(
			[
				'message' => __( 'Link created. Copy the URL now. It disappears on reload.', 'magicauth' ),
				'link'    => $result['link_url'],
				'code'    => Crockford::format_for_display( (string) $result['code_plaintext'] ),
				'expires' => $result['expires_at'],
			]
		);
	}

	public static function ajax_send_link(): void {
		[ $target, $email ] = self::ajax_resolve_target();
		$result             = TokenManager::issue( $target, $email );
		if ( ! is_array( $result ) ) {
			wp_send_json_error( [ 'message' => __( 'Could not issue link.', 'magicauth' ) ] );
		}
		$sent = Mailer::send_magic_link( $target, (string) $result['link_url'], (string) $result['code_plaintext'], (string) $result['expires_at'] );
		if ( ! $sent ) {
			wp_send_json_error( [ 'message' => __( 'wp_mail returned false. Check the server\'s mail configuration.', 'magicauth' ) ] );
		}
		wp_send_json_success( [ 'message' => __( 'Link sent.', 'magicauth' ) ] );
	}

	public static function ajax_reset_tokens(): void {
		[ $target ] = self::ajax_resolve_target();
		$count      = TokenManager::invalidate_outstanding_for_user( $target );
		wp_send_json_success(
			[
				'message' => sprintf(
					/* translators: %d: number of tokens reset */
					_n( '%d outstanding link reset.', '%d outstanding links reset.', $count, 'magicauth' ),
					$count
				),
			]
		);
	}

	/**
	 * Shared AJAX preamble: nonce + capability + target. Dies on failure.
	 *
	 * @return array{0:int,1:string} Target user_id and email.
	 */
	private static function ajax_resolve_target(): array {
		check_ajax_referer( self::NONCE_ACTION );

		$target = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
		if ( $target <= 0 ) {
			wp_send_json_error( [ 'message' => __( 'Missing user.', 'magicauth' ) ] );
		}

		if ( ! magicauth_current_user_can_control_user( $target ) ) {
			wp_send_json_error( [ 'message' => __( 'You are not allowed to do this.', 'magicauth' ) ], 403 );
		}

		$user = get_userdata( $target );
		if ( ! $user || empty( $user->user_email ) ) {
			wp_send_json_error( [ 'message' => __( 'User not found.', 'magicauth' ) ] );
		}

		return [ $target, (string) $user->user_email ];
	}
}
