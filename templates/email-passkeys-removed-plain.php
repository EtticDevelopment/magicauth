<?php
/**
 * "Passkeys were removed" plaintext email body (SPEC 10.4). Same rules as the
 * HTML body: no URLs, no user-supplied text, no invitation to create one.
 *
 * @var \WP_User $user
 * @var string   $company_name
 * @var int      $count
 * @var string   $actor
 * @var string   $reason
 * @var string   $removed_at_local
 * @var string   $timezone_label
 * @var string   $manage_location
 *
 * @package MagicAuth
 */

defined( 'ABSPATH' ) || exit;

// Plaintext context: no esc_html() (would render `&` as `&amp;`).
// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped -- Plaintext email body.

echo _n( 'A passkey was removed', 'Passkeys were removed', $count, 'magicauth' ) . "\n\n";

echo __( 'Hello,', 'magicauth' ) . "\n\n";

if ( 'email_changed' === $reason ) {
	echo __( 'Your passkeys were removed because the email address of your account changed.', 'magicauth' ) . "\n\n";
} elseif ( 'admin' === $actor ) {
	/* translators: 1: number of passkeys, 2: company name, 3: date and time, 4: time zone */
	echo sprintf( _n( 'An administrator removed %1$d passkey from your account at %2$s on %3$s (%4$s).', 'An administrator removed %1$d passkeys from your account at %2$s on %3$s (%4$s).', $count, 'magicauth' ), $count, $company_name, $removed_at_local, $timezone_label ) . "\n\n";
} else {
	/* translators: 1: number of passkeys, 2: company name, 3: date and time, 4: time zone */
	echo sprintf( _n( 'You removed %1$d passkey from your account at %2$s on %3$s (%4$s).', 'You removed %1$d passkeys from your account at %2$s on %3$s (%4$s).', $count, 'magicauth' ), $count, $company_name, $removed_at_local, $timezone_label ) . "\n\n";
}

echo __( 'You can still sign in with your email.', 'magicauth' ) . "\n\n";

if ( '' !== $manage_location ) {
	/* translators: %s: where the person manages passkeys, for example "Account (/account/)" */
	echo sprintf( __( 'If you did not expect this, someone else may have access to your account. Sign in with your email, go to %s and choose "Sign out on all other devices". Then contact your administrator.', 'magicauth' ), $manage_location ) . "\n\n";
} else {
	echo __( 'If you did not expect this, someone else may have access to your account. Sign in with your email, open your passkey settings and choose "Sign out on all other devices". Then contact your administrator.', 'magicauth' ) . "\n\n";
}

echo '-- ' . "\n";
echo $company_name . "\n";

// phpcs:enable WordPress.Security.EscapeOutput.OutputNotEscaped
