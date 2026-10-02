<?php
/**
 * /account-tpl/: a theme template that prints [magicauth_passkeys] itself, so
 * the post content holds no shortcode and the early management-page detection
 * (SPEC 8.11) misses it; the shortcode's late enqueue has to carry it (E22).
 *
 * @package MagicAuth\Tests
 */

defined( 'ABSPATH' ) || exit;
?><!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
<meta charset="<?php bloginfo( 'charset' ); ?>">
<meta name="viewport" content="width=device-width, initial-scale=1">
<?php wp_head(); ?>
</head>
<body <?php body_class( 'e2e-account-template' ); ?>>
<?php wp_body_open(); ?>
<main class="e2e-account">
	<h1>Your account</h1>
	<?php echo do_shortcode( '[magicauth_passkeys]' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- shortcode output. ?>
</main>
<?php wp_footer(); ?>
</body>
</html>
