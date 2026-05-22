<?php
/**
 * Branded login-shell wrapper for wp-login.php replacement.
 *
 * @var string $state         'a' or 'b'.
 * @var string $action_url
 * @var string $redirect_to
 * @var string $error
 * @var string $session_email
 * @var string $logo_url
 * @var string $brand_color
 * @var string $company_name
 * @var string $site_name
 * @var string $form_path     Path to login-form.php to include.
 *
 * @package MagicAuth
 */

defined( 'ABSPATH' ) || exit;
?>
<?php
// Re-validate at output — esc_attr is HTML-context, not CSS.
$shell_brand = function_exists( 'sanitize_hex_color' ) ? (string) sanitize_hex_color( (string) $brand_color ) : '';
if ( '' === $shell_brand ) {
	$shell_brand = '#2271b1';
}
$shell_brand_txt = magicauth_yiq_text_color( $shell_brand );
?>
<style id="magicauth-shell-vars">
:root {
	--magicauth-color-primary: <?php echo esc_attr( $shell_brand ); ?>;
	--magicauth-color-primary-text: <?php echo esc_attr( $shell_brand_txt ); ?>;
}
/* Vertical-center the card; flex avoids fighting WP's default top-padding.
   Column direction keeps WP core's body-level siblings (the login language
   switcher) stacked under the card instead of floating beside it. min-height
   (not height) lets a tall card+switcher scroll instead of clipping. */
html {
	height: 100%;
}
body.login {
	display: flex;
	flex-direction: column;
	align-items: center;
	justify-content: center;
	min-height: 100%;
	margin: 0;
	padding: 24px 16px;
	box-sizing: border-box;
	background: var(--magicauth-color-page, #eeeeee);
}
body.login #login {
	width: 100%;
	max-width: 520px;
	margin: 0;
	padding: 0;
}
/* WP core's login language switcher renders only on multilingual sites, as a
   sibling of #login. Keep it usable but stack it neatly below the card. The
   "Hide language switcher" setting suppresses it before it ever renders. */
body.login .language-switcher {
	margin: 16px 0 0;
	text-align: center;
}
/* Hide WP's logo h1; :not() guard preserves our heading. */
body.login h1:not(.magicauth-heading) {
	display: none;
}
/* Hide WP's default forms and nav links. */
body.login #loginform,
body.login #lostpasswordform,
body.login #registerform,
body.login #resetpassform,
body.login #nav,
body.login #backtoblog {
	display: none;
}
/* Reset WP's `#login form` box so our form sits flat (no double border). */
body.login .magicauth-form {
	margin: 0;
	padding: 0;
	background: transparent;
	border: 0;
	box-shadow: none;
	overflow: visible;
}
body.login.magicauth-page .magicauth-card {
	display: block;
}
</style>

<?php
if ( isset( $form_path ) && is_readable( (string) $form_path ) ) {
	include (string) $form_path;
}

$credit = function_exists( 'magicauth_get_agency_credit' ) ? magicauth_get_agency_credit() : null;
if ( null !== $credit ) {
	$credit_tpl = MAGICAUTH_DIR . 'templates/agency-credit.php';
	if ( is_readable( $credit_tpl ) ) {
		include $credit_tpl;
	}
}
