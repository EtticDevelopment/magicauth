<?php
/**
 * Magic-link plaintext email body.
 *
 * No esc_html / esc_url here — this is plaintext, not HTML. esc_url in
 * particular would HTML-encode `&` to `&#038;` and break the verifier link.
 */

defined( 'ABSPATH' ) || exit;

echo sprintf( __( 'Sign in to %s', 'magicauth' ), $company_name ) . "\n\n";

echo sprintf(
	/* translators: %d: TTL minutes */
	__( 'Use the code below or open the sign-in link. Both expire in %d minutes.', 'magicauth' ),
	$expiry_minutes
) . "\n\n";

echo __( 'Sign-in code:', 'magicauth' ) . ' ' . $code_display . "\n\n";

echo __( 'Sign-in link:', 'magicauth' ) . "\n";
echo $link . "\n\n";

echo __( 'If you didn\'t request this, you can safely ignore this email.', 'magicauth' ) . "\n\n";

echo '-- ' . "\n";
echo $company_name . "\n";

if ( ! empty( $is_test ) ) {
	echo "\n" . __( '(This is a test send from the MagicAuth diagnostics screen.)', 'magicauth' ) . "\n";
}
