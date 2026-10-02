<?php
/**
 * "A passkey was added" plaintext email body (SPEC 10.2). Same rules as the
 * HTML body: no URLs, no user-supplied text, no invitation to create one.
 *
 * @var \WP_User $user
 * @var string   $company_name
 * @var string   $passkey_label
 * @var string   $passkey_suffix
 * @var string   $provider_text
 * @var string   $sync_label
 * @var string   $manage_location
 * @var string   $added_at_local
 * @var string   $timezone_label
 *
 * @package MagicAuth
 */

defined( 'ABSPATH' ) || exit;

// Plaintext context: no esc_html() (would render `&` as `&amp;`).
// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped -- Plaintext email body.

echo __( 'A passkey was added', 'magicauth' ) . "\n\n";

// E3 without the display name: it is user-editable (invariant 12, D-35).
echo __( 'Hello,', 'magicauth' ) . "\n\n";

echo sprintf(
	/* translators: 1: company name, 2: date and time, 3: time zone */
	__( 'A passkey was added to your account at %1$s on %2$s (%3$s).', 'magicauth' ),
	$company_name,
	$added_at_local,
	$timezone_label
) . "\n\n";

/* translators: %s: "Passkey ending in 7F3A" */
echo sprintf( __( 'Passkey: %s', 'magicauth' ), $passkey_label ) . "\n";

echo sprintf(
	/* translators: 1: passkey provider, 2: sync status, for example "This device only" */
	__( 'Stored in: %1$s. %2$s', 'magicauth' ),
	$provider_text,
	$sync_label
) . "\n\n";

echo __( 'If you added this passkey, you do not need to do anything.', 'magicauth' ) . "\n\n";

if ( '' !== $manage_location ) {
	echo sprintf(
		/* translators: 1: where the person manages passkeys, for example "Account (/account/)", 2: last 4 characters of the passkey's identifier */
		__( 'If you did not add this passkey yourself, someone else may have access to your account. Sign in with your email, go to %1$s, remove the passkey ending in %2$s and choose "Sign out on all other devices". Then contact your administrator.', 'magicauth' ),
		$manage_location,
		$passkey_suffix
	) . "\n\n";
} else {
	echo sprintf(
		/* translators: %s: last 4 characters of the passkey's identifier */
		__( 'If you did not add this passkey yourself, someone else may have access to your account. Sign in with your email, open your passkey settings, remove the passkey ending in %s and choose "Sign out on all other devices". Then contact your administrator.', 'magicauth' ),
		$passkey_suffix
	) . "\n\n";
}

echo '-- ' . "\n";
echo $company_name . "\n";

// phpcs:enable WordPress.Security.EscapeOutput.OutputNotEscaped
