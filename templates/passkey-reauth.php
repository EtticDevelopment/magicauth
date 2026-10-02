<?php
/**
 * Step-up view (SPEC 3.5, 8.5, 8.12): confirm it is you by an email code or
 * an existing passkey before adding a passkey. Signed-in pages only.
 *
 * Override: yourtheme/magicauth/passkey-reauth.php. JS binds only to these
 * attributes, never to classes: data-magicauth-pk-reauth-title,
 * -reauth-none, -reauth-email, -reauth-passkey, -reauth-form, -reauth-sent,
 * -reauth-code, -reauth-confirm, -reauth-resend, -reauth-cancel,
 * -reauth-status, -reauth-alert (persistent live regions, never hidden).
 *
 * Contract: with $in_form_context true (the management list, which can sit
 * inside wp-admin's <form id="your-profile">) this view holds no <form> and
 * Enter in the code input is handled in JS. Otherwise the code input sits in
 * its own <form data-magicauth-pk-reauth-form novalidate> whose only submit
 * button is R7. Every other button is type="button".
 *
 * @var array<string,string> $strings
 * @var bool                 $in_form_context
 * @var string               $title_id
 * @var int                  $instance
 *
 * @package MagicAuth
 */

defined( 'ABSPATH' ) || exit;

$code_id = 'magicauth-pk-code-' . (int) $instance;
$wrapper = $in_form_context ? 'div' : 'form';
?>
<h3 id="<?php echo esc_attr( $title_id ); ?>" class="magicauth-pk-reauth__title" tabindex="-1" data-magicauth-pk-reauth-title><?php echo esc_html( $strings['R1'] ); ?></h3>
<p class="magicauth-pk-reauth__text"><?php echo esc_html( $strings['R2'] ); ?></p>
<p class="magicauth-pk-reauth__text" data-magicauth-pk-reauth-none hidden><?php echo esc_html( $strings['R14'] ); ?></p>
<div class="magicauth-pk-actions">
	<button type="button" class="magicauth-pk-btn magicauth-pk-btn--primary" data-magicauth-pk-reauth-email hidden><?php echo esc_html( $strings['R3'] ); ?></button>
	<button type="button" class="magicauth-pk-btn" data-magicauth-pk-reauth-passkey hidden><?php echo esc_html( $strings['R4'] ); ?></button>
</div>
<<?php echo esc_html( $wrapper ); ?> class="magicauth-pk-reauth__code" data-magicauth-pk-reauth-form<?php echo $in_form_context ? '' : ' novalidate'; ?> hidden>
	<p class="magicauth-pk-reauth__text" data-magicauth-pk-reauth-sent></p>
	<label class="magicauth-pk-label" for="<?php echo esc_attr( $code_id ); ?>"><?php echo esc_html( $strings['R6'] ); ?></label>
	<input id="<?php echo esc_attr( $code_id ); ?>" class="magicauth-pk-input" type="text" data-magicauth-pk-reauth-code autocomplete="one-time-code" inputmode="text" autocapitalize="characters" spellcheck="false" dir="ltr" maxlength="16">
	<div class="magicauth-pk-actions">
		<button type="<?php echo $in_form_context ? 'button' : 'submit'; ?>" class="magicauth-pk-btn magicauth-pk-btn--primary" data-magicauth-pk-reauth-confirm><?php echo esc_html( $strings['R7'] ); ?></button>
		<button type="button" class="magicauth-pk-link" data-magicauth-pk-reauth-resend><?php echo esc_html( $strings['R13'] ); ?></button>
	</div>
</<?php echo esc_html( $wrapper ); ?>>
<div class="magicauth-pk-actions">
	<button type="button" class="magicauth-pk-btn" data-magicauth-pk-reauth-cancel><?php echo esc_html( $strings['M17'] ); ?></button>
</div>
<p class="magicauth-pk-sr-only" data-magicauth-pk-reauth-status role="status"></p>
<p class="magicauth-pk-alert" data-magicauth-pk-reauth-alert role="alert"></p>
