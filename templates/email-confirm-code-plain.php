<?php
/**
 * Step-up confirmation code plaintext email body (SPEC 10.3). No link; only
 * E11 names the action the signed-in user started.
 *
 * @var \WP_User $user
 * @var string   $company_name
 * @var string   $code_display
 * @var int      $expiry_minutes
 *
 * @package MagicAuth
 */

defined( 'ABSPATH' ) || exit;

// Plaintext context: no esc_html() (would render `&` as `&amp;`).
// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped -- Plaintext email body.

/* translators: %s: company name */
echo sprintf( __( 'Your confirmation code for %s', 'magicauth' ), $company_name ) . "\n\n";

/* translators: %s: confirmation code, for example ABC-DEF */
echo sprintf( __( 'Use this code to confirm it is you: %s', 'magicauth' ), $code_display ) . "\n\n";

echo sprintf(
	/* translators: %d: minutes the code stays valid */
	_n(
		'The code is valid for %d minute. You asked for it to add a passkey to your account.',
		'The code is valid for %d minutes. You asked for it to add a passkey to your account.',
		(int) $expiry_minutes,
		'magicauth'
	),
	(int) $expiry_minutes
) . "\n\n";

/* translators: %s: company name */
echo sprintf( __( 'Never share this code. Nobody from %s will ask you for it.', 'magicauth' ), $company_name ) . "\n\n";

echo __( 'If you did not ask for this code, someone may be signed in to your account. Contact your administrator.', 'magicauth' ) . "\n\n";

echo '-- ' . "\n";
echo $company_name . "\n";

// phpcs:enable WordPress.Security.EscapeOutput.OutputNotEscaped
