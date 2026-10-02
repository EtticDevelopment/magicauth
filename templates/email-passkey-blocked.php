<?php
/**
 * "A passkey was blocked" HTML email body (SPEC 10.5). Sent once, when the
 * counter check blocks a device-bound passkey (7.6). No clickable URLs, no
 * passkey name or other user-supplied text, no invitation to create one.
 *
 * @var \WP_User $user
 * @var string   $company_name
 * @var string   $brand_color
 * @var string   $passkey_label    "Passkey ending in XXXX" (M34).
 * @var string   $blocked_at_local
 * @var string   $timezone_label
 * @var string   $manage_location  Plain text, may be ''.
 *
 * @package MagicAuth
 */

defined( 'ABSPATH' ) || exit;

$page_bg    = '#eeeeee';
$surface_bg = '#ffffff';
$text_color = '#101517';
$muted      = '#505753';
$is_rtl     = function_exists( 'is_rtl' ) ? is_rtl() : false;
$dir        = $is_rtl ? 'rtl' : 'ltr';
$line_style = 'padding:0 56px 8px 56px;font-size:16px;line-height:1.5;color:' . $text_color . ';';

if ( '' !== $manage_location ) {
	/* translators: %s: where the person manages passkeys, for example "Account (/account/)" */
	$advice = sprintf( __( 'Sign in with your email, go to %s, remove the blocked passkey and choose "Sign out on all other devices".', 'magicauth' ), $manage_location );
} else {
	$advice = __( 'Sign in with your email, open your passkey settings, remove the blocked passkey and choose "Sign out on all other devices".', 'magicauth' );
}
?>
<!doctype html>
<html lang="<?php echo esc_attr( str_replace( '_', '-', (string) get_locale() ) ); ?>" dir="<?php echo esc_attr( $dir ); ?>">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title><?php esc_html_e( 'A passkey was blocked', 'magicauth' ); ?></title>
</head>
<body style="margin:0;padding:0;background:<?php echo esc_attr( $page_bg ); ?>;color:<?php echo esc_attr( $text_color ); ?>;-webkit-font-smoothing:antialiased;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',sans-serif;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:<?php echo esc_attr( $page_bg ); ?>;padding:40px 0;">
	<tr>
		<td align="center">
			<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="600" style="max-width:600px;background:<?php echo esc_attr( $surface_bg ); ?>;border-radius:8px;">
				<tr>
					<td style="padding:48px 56px 24px 56px;font-size:18px;font-weight:700;color:<?php echo esc_attr( $brand_color ); ?>;">
						<?php echo esc_html( $company_name ); ?>
					</td>
				</tr>
				<tr>
					<td style="padding:0 56px 24px 56px;font-size:24px;line-height:1.25;font-weight:700;color:<?php echo esc_attr( $text_color ); ?>;">
						<?php esc_html_e( 'A passkey was blocked', 'magicauth' ); ?>
					</td>
				</tr>
				<tr>
					<td style="<?php echo esc_attr( $line_style ); ?>">
						<?php esc_html_e( 'Hello,', 'magicauth' ); ?>
					</td>
				</tr>
				<tr>
					<td style="<?php echo esc_attr( $line_style ); ?>">
						<?php
						echo esc_html(
							sprintf(
								/* translators: 1: "Passkey ending in 7F3A", 2: date, time and time zone */
								__( 'A passkey on your account (%1$s) was blocked at %2$s because it may have been copied.', 'magicauth' ),
								$passkey_label,
								$blocked_at_local . ' (' . $timezone_label . ')'
							)
						);
						?>
					</td>
				</tr>
				<tr>
					<td style="<?php echo esc_attr( $line_style ); ?>">
						<?php esc_html_e( 'It cannot be used to sign in any more. You can still sign in with your email.', 'magicauth' ); ?>
					</td>
				</tr>
				<tr>
					<td style="padding:16px 56px 48px 56px;font-size:16px;line-height:1.5;color:<?php echo esc_attr( $text_color ); ?>;">
						<?php echo esc_html( $advice ); ?>
					</td>
				</tr>
			</table>
			<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="600" style="max-width:600px;background:#f5f5f5;border-radius:0 0 8px 8px;margin-top:8px;">
				<tr>
					<td style="padding:16px 56px;font-size:12px;color:<?php echo esc_attr( $muted ); ?>;text-align:center;">
						<?php echo esc_html( $company_name ); ?>
					</td>
				</tr>
			</table>
		</td>
	</tr>
</table>
</body>
</html>
