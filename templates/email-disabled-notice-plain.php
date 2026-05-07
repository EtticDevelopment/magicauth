<?php
/**
 * Disabled-notice plaintext email body.
 *
 * @var \WP_User $user
 * @var string  $company_name
 * @var string  $site_name
 * @var bool    $allow_password_login
 *
 * @package MagicAuth
 */

defined( 'ABSPATH' ) || exit;

// Plaintext context — no esc_html() (would render `&` as `&amp;`).

echo sprintf( __( 'About your sign-in request for %s', 'magicauth' ), $company_name ) . "\n\n";

echo sprintf(
	/* translators: %s company name */
	__( 'A sign-in code was just requested for your account at %s.', 'magicauth' ),
	$company_name
) . "\n\n";

echo __( 'Magic link and code sign-in is currently turned off for your account, so no code was sent. This is a setting managed by your site administrator and is often part of routine account changes.', 'magicauth' ) . "\n\n";

if ( ! empty( $allow_password_login ) ) {
	echo __( 'You may still be able to sign in with your password through the regular sign-in screen. If you are not sure whether your account should have access, please contact your site administrator.', 'magicauth' ) . "\n\n";
} else {
	echo __( 'If you have questions about your account access, please contact your site administrator.', 'magicauth' ) . "\n\n";
}

echo __( 'If you did not request a sign-in code, you can ignore this message. No further action is needed.', 'magicauth' ) . "\n\n";

echo '-- ' . "\n";
echo $company_name . "\n";
