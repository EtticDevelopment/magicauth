<?php
/**
 * Front-end toast renderer. Priority: link-invalid > blocked > error > sent.
 *
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Frontend;

defined( 'ABSPATH' ) || exit;

final class Toast {

	/** Render at most one toast based on $_GET flags. Safe to call unconditionally. */
	public static function maybe_render( string $state ): void {
		if ( isset( $_GET['magicauth_link_invalid'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$msg = ( 'd' === $state || 'e' === $state )
				? __( 'That reset link has expired or already been used. Request a new one below.', 'magicauth' )
				: __( 'That sign-in link has expired or already been used. Request a new code or link below.', 'magicauth' );
			self::render( $msg, 'error' );
			return;
		}

		// Throttle-block envelope. Enumeration-safe: copy never reveals account existence.
		if ( isset( $_GET['magicauth_blocked'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$reason = sanitize_key( (string) wp_unslash( (string) $_GET['magicauth_blocked'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$secs   = isset( $_GET['magicauth_block_secs'] ) ? (int) $_GET['magicauth_block_secs'] : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$msg    = self::blocked_message_for_reason( $reason, $secs );
			if ( '' !== $msg ) {
				self::render( $msg, 'warning' );
				return;
			}
		}

		// Generic error envelope. States A/D never emit magicauth_error — fall through silently.
		if ( isset( $_GET['magicauth_error'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$msg = self::error_message_for_state( $state );
			if ( '' !== $msg ) {
				self::render( $msg, 'error' );
			}
			return;
		}

		if ( isset( $_GET['magicauth_sent'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$msg = ( 'd' === $state )
				? __( 'If an account exists for that email, we sent a password reset link.', 'magicauth' )
				: __( 'Email sent. Check your mail app.', 'magicauth' );
			self::render( $msg, 'success' );
		}
	}

	/** State-aware message for the magicauth_error envelope. */
	private static function error_message_for_state( string $state ): string {
		switch ( $state ) {
			case 'b':
				return __( 'That code is invalid or has expired. Try again, or request a new code.', 'magicauth' );
			case 'c':
				return __( 'Sign-in failed. Check your username and password, or use a magic link instead.', 'magicauth' );
			case 'e':
				return __( 'Could not set a new password. Make sure both fields match and try again.', 'magicauth' );
			default:
				return '';
		}
	}

	/** Reason → copy for the throttle-block toast. Enumeration-safe; $secs=0 for counter-based throttles. */
	private static function blocked_message_for_reason( string $reason, int $secs = 0 ): string {
		switch ( $reason ) {
			case 'email_cooldown':
				if ( $secs > 0 ) {
					return sprintf(
						/* translators: %d: remaining cooldown seconds */
						__( 'Please wait %d seconds before requesting another link for this email.', 'magicauth' ),
						$secs
					);
				}
				return __( 'Please wait a moment before requesting another link for this email.', 'magicauth' );
			case 'ip_link':
				return __( 'Too many sign-in requests from your network. Please try again later, or sign in with a password.', 'magicauth' );
			case 'ip_code':
				return __( 'Too many code attempts from your network. Please request a new sign-in link.', 'magicauth' );
			case 'ip_password':
				return __( 'Too many sign-in attempts. Please wait a few minutes before trying again.', 'magicauth' );
			case 'ip_password_reset':
				return __( 'Too many password-reset requests. Please wait an hour before trying again.', 'magicauth' );
			case 'attempts':
				return __( 'Too many incorrect codes for this link. Please request a new sign-in link.', 'magicauth' );
			default:
				return '';
		}
	}

	/** Emit one toast. Styling/lifecycle live in magicauth.css/js. $variant: success|error|warning. */
	private static function render( string $message, string $variant = 'success' ): void {
		$is_error   = ( 'error' === $variant );
		$is_warning = ( 'warning' === $variant );
		$class      = 'magicauth-toast';
		if ( $is_error ) {
			$class .= ' magicauth-toast--error';
		} elseif ( $is_warning ) {
			$class .= ' magicauth-toast--warning';
		}
		// Error+warning go assertive; success stays polite.
		$role = ( $is_error || $is_warning ) ? 'alert' : 'status';
		$live = ( $is_error || $is_warning ) ? 'assertive' : 'polite';
		?>
		<div class="<?php echo esc_attr( $class ); ?>" id="magicauth-toast" role="<?php echo esc_attr( $role ); ?>" aria-live="<?php echo esc_attr( $live ); ?>">
			<span class="magicauth-toast__icon" aria-hidden="true">
				<?php if ( $is_error ) : ?>
					<svg viewBox="0 0 24 24" width="16" height="16" focusable="false">
						<path d="M19 6.41 17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z" fill="currentColor"/>
					</svg>
				<?php elseif ( $is_warning ) : ?>
					<svg viewBox="0 0 24 24" width="16" height="16" focusable="false">
						<path d="M12 8v5l3.5 2.1.8-1.3-2.8-1.6V8H12zm0-6a10 10 0 100 20 10 10 0 000-20zm0 18a8 8 0 110-16 8 8 0 010 16z" fill="currentColor"/>
					</svg>
				<?php else : ?>
					<svg viewBox="0 0 24 24" width="16" height="16" focusable="false">
						<path d="M9 16.17 4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z" fill="currentColor"/>
					</svg>
				<?php endif; ?>
			</span>
			<span class="magicauth-toast__msg"><?php echo esc_html( $message ); ?></span>
			<button type="button" class="magicauth-toast__close" aria-label="<?php esc_attr_e( 'Dismiss', 'magicauth' ); ?>">&times;</button>
		</div>
		<?php
	}
}
