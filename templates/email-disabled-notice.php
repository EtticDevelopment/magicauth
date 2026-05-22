<?php
/** Disabled-notice HTML email body. No clickable URLs — anti-phishing. */

defined( 'ABSPATH' ) || exit;

$page_bg    = '#eeeeee';
$surface_bg = '#ffffff';
$text_color = '#101517';
$muted      = '#505753';
$is_rtl     = function_exists( 'is_rtl' ) ? is_rtl() : false;
$dir        = $is_rtl ? 'rtl' : 'ltr';
?>
<!doctype html>
<html lang="<?php echo esc_attr( str_replace( '_', '-', (string) get_locale() ) ); ?>" dir="<?php echo esc_attr( $dir ); ?>">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title><?php
/* translators: %s: company name */
echo esc_html( sprintf( __( 'About your sign-in request for %s', 'magicauth' ), $company_name ) );
?></title>
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
					<td style="padding:0 56px;font-size:24px;line-height:1.25;font-weight:700;color:<?php echo esc_attr( $text_color ); ?>;">
						<?php
						echo esc_html(
							sprintf(
								/* translators: %s: company name */
								__( 'About your sign-in request for %s', 'magicauth' ),
								$company_name
							)
						);
						?>
					</td>
				</tr>
				<tr>
					<td style="padding:24px 56px 8px 56px;font-size:16px;line-height:1.5;color:<?php echo esc_attr( $text_color ); ?>;">
						<?php
						echo esc_html(
							sprintf(
								/* translators: %s: company name */
								__( 'A sign-in code was just requested for your account at %s.', 'magicauth' ),
								$company_name
							)
						);
						?>
					</td>
				</tr>
				<tr>
					<td style="padding:0 56px 8px 56px;font-size:16px;line-height:1.5;color:<?php echo esc_attr( $text_color ); ?>;">
						<?php esc_html_e( 'Magic link and code sign-in is currently turned off for your account, so no code was sent. This is a setting managed by your site administrator and is often part of routine account changes.', 'magicauth' ); ?>
					</td>
				</tr>
				<?php if ( ! empty( $allow_password_login ) ) : ?>
				<tr>
					<td style="padding:0 56px 8px 56px;font-size:16px;line-height:1.5;color:<?php echo esc_attr( $text_color ); ?>;">
						<?php esc_html_e( 'You may still be able to sign in with your password through the regular sign-in screen. If you are not sure whether your account should have access, please contact your site administrator.', 'magicauth' ); ?>
					</td>
				</tr>
				<?php else : ?>
				<tr>
					<td style="padding:0 56px 8px 56px;font-size:16px;line-height:1.5;color:<?php echo esc_attr( $text_color ); ?>;">
						<?php esc_html_e( 'If you have questions about your account access, please contact your site administrator.', 'magicauth' ); ?>
					</td>
				</tr>
				<?php endif; ?>
				<tr>
					<td style="padding:8px 56px 48px 56px;font-size:14px;line-height:1.5;color:<?php echo esc_attr( $muted ); ?>;">
						<?php esc_html_e( 'If you did not request a sign-in code, you can ignore this message. No further action is needed.', 'magicauth' ); ?>
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
