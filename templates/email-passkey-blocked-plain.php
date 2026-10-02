<?php
/**
 * "A passkey was blocked" plaintext email body (SPEC 10.5). Same rules as the
 * HTML body: no URLs, no user-supplied text, no invitation to create one.
 *
 * @var \WP_User $user
 * @var string   $company_name
 * @var string   $passkey_label
 * @var string   $blocked_at_local
 * @var string   $timezone_label
 * @var string   $manage_location
 *
 * @package MagicAuth
 */

defined( 'ABSPATH' ) || exit;

// Plaintext context: no esc_html() (would render `&` as `&amp;`).
// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped -- Plaintext email body.

echo __( 'A passkey was blocked', 'magicauth' ) . "\n\n";

echo __( 'Hello,', 'magicauth' ) . "\n\n";

echo sprintf(
	/* translators: 1: "Passkey ending in 7F3A", 2: date, time and time zone */
	__( 'A passkey on your account (%1$s) was blocked at %2$s because it may have been copied.', 'magicauth' ),
	$passkey_label,
	$blocked_at_local . ' (' . $timezone_label . ')'
) . "\n\n";

echo __( 'It cannot be used to sign in any more. You can still sign in with your email.', 'magicauth' ) . "\n\n";

if ( '' !== $manage_location ) {
	/* translators: %s: where the person manages passkeys, for example "Account (/account/)" */
	echo sprintf( __( 'Sign in with your email, go to %s, remove the blocked passkey and choose "Sign out on all other devices".', 'magicauth' ), $manage_location ) . "\n\n";
} else {
	echo __( 'Sign in with your email, open your passkey settings, remove the blocked passkey and choose "Sign out on all other devices".', 'magicauth' ) . "\n\n";
}

echo '-- ' . "\n";
echo $company_name . "\n";

// phpcs:enable WordPress.Security.EscapeOutput.OutputNotEscaped
