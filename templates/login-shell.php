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
// Re-validate at output — esc_attr is HTML-context padding, not CSS sanitization.
// Actual safety comes from: sanitize_hex_color() narrowing to [#0-9A-Fa-f],
// (int) casts on numerics, and a hardcoded PHP allowlist map for font stacks
// (the user-supplied value is a short key; the emitted CSS string is hardcoded).
$shell_brand = function_exists( 'sanitize_hex_color' ) ? (string) sanitize_hex_color( (string) $brand_color ) : '';
if ( '' === $shell_brand ) {
	$shell_brand = '#2271b1';
}
$shell_brand_txt = magicauth_yiq_text_color( $shell_brand );

$shell_page = function_exists( 'sanitize_hex_color' ) ? (string) sanitize_hex_color( (string) magicauth_get_setting( 'page_color', '#eeeeee' ) ) : '';
if ( '' === $shell_page ) {
	$shell_page = '#eeeeee';
}
$shell_radius = max( 0, min( 32, (int) magicauth_get_setting( 'card_radius', 6 ) ) );
$shell_width  = max( 360, min( 640, (int) magicauth_get_setting( 'card_width', 480 ) ) );

// Stored value is the KEY only; emitted CSS string is the hardcoded map value.
// Every value must avoid '<' / '>' or a future maintainer can break the <style> block.
$shell_font_stacks = [
	'system'      => '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif',
	'sans-modern' => 'Inter, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", sans-serif',
	'serif'       => 'Georgia, "Times New Roman", Times, serif',
	'mono'        => 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace',
	'rounded'     => 'ui-rounded, "SF Pro Rounded", "Hiragino Maru Gothic ProN", Quicksand, Comfortaa, system-ui, sans-serif',
];
$shell_font_key   = (string) magicauth_get_setting( 'font_stack', 'system' );
$shell_font_stack = $shell_font_stacks[ $shell_font_key ] ?? $shell_font_stacks['system'];
?>
<style id="magicauth-shell-vars">
:root {
	--magicauth-color-primary: <?php echo esc_attr( $shell_brand ); ?>;
	--magicauth-color-primary-text: <?php echo esc_attr( $shell_brand_txt ); ?>;
	--magicauth-color-page: <?php echo esc_attr( $shell_page ); ?>;
	--magicauth-radius-card: <?php echo (int) $shell_radius; ?>px;
	--magicauth-card-max-width: <?php echo (int) $shell_width; ?>px;
	--magicauth-font-family: <?php echo esc_attr( $shell_font_stack ); ?>;
}
/* Vertical-center the card; flex avoids fighting WP's default top-padding. */
html, body.login {
	height: 100%;
}
body.login {
	display: flex;
	align-items: center;
	justify-content: center;
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
