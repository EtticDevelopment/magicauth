<?php
/**
 * Magic-link HTML email. Inline-styled tables, no images, <102KB (Gmail clip). Override at yourtheme/magicauth/email-magic-link.php.
 *
 * @var \WP_User $user
 * @var string  $link
 * @var string  $code
 * @var string  $code_display
 * @var int     $expiry_minutes
 * @var string  $brand_color
 * @var string  $brand_text
 * @var string  $company_name
 * @var string  $site_name    Back-compat alias; new code uses $company_name.
 * @var bool    $is_test
 *
 * @package MagicAuth
 */

defined( 'ABSPATH' ) || exit;

$page_bg    = '#eeeeee';
$surface_bg = '#ffffff';
$code_bg    = '#f5f5f5';
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
<title><?php echo esc_html( sprintf( __( 'Sign in to %s', 'magicauth' ), $company_name ) ); ?></title>
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
					<td style="padding:0 56px;font-size:28px;line-height:1.2;font-weight:700;color:<?php echo esc_attr( $text_color ); ?>;">
						<?php echo esc_html( sprintf( __( 'Sign in to %s', 'magicauth' ), $company_name ) ); ?>
					</td>
				</tr>
				<tr>
					<td style="padding:24px 56px 16px 56px;font-size:16px;line-height:1.5;color:<?php echo esc_attr( $text_color ); ?>;">
						<?php
						echo esc_html(
							sprintf(
								/* translators: %d: TTL minutes */
								__( 'Use the code below or click the button to sign in. Both expire in %d minutes.', 'magicauth' ),
								$expiry_minutes
							)
						);
						?>
					</td>
				</tr>
				<tr>
					<td style="padding:8px 56px 24px 56px;">
						<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" dir="ltr">
							<tr>
								<td align="center" style="background:<?php echo esc_attr( $code_bg ); ?>;padding:20px 0;border-radius:6px;font-family:ui-monospace,SFMono-Regular,'SF Mono',Menlo,monospace;font-size:28px;letter-spacing:8px;font-weight:700;color:<?php echo esc_attr( $text_color ); ?>;">
									<?php echo esc_html( $code_display ); ?>
								</td>
							</tr>
						</table>
					</td>
				</tr>
				<tr>
					<td align="center" style="padding:0 56px 32px 56px;">
						<!--[if mso]>
						<v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" xmlns:w="urn:schemas-microsoft-com:office:word" href="<?php echo esc_url( $link ); ?>" style="height:48px;v-text-anchor:middle;width:240px;" arcsize="13%" stroke="f" fillcolor="<?php echo esc_attr( $brand_color ); ?>">
							<w:anchorlock/>
							<center style="color:<?php echo esc_attr( $brand_text ); ?>;font-family:sans-serif;font-size:16px;font-weight:bold;"><?php echo esc_html__( 'Sign in', 'magicauth' ); ?></center>
						</v:roundrect>
						<![endif]-->
						<!--[if !mso]> <!-- -->
						<a href="<?php echo esc_url( $link ); ?>" style="display:inline-block;background:<?php echo esc_attr( $brand_color ); ?>;color:<?php echo esc_attr( $brand_text ); ?>;padding:14px 28px;border-radius:6px;font-size:16px;font-weight:600;text-decoration:none;">
							<?php echo esc_html__( 'Sign in', 'magicauth' ); ?>
						</a>
						<!-- <![endif]-->
					</td>
				</tr>
				<tr>
					<td style="padding:0 56px 48px 56px;font-size:14px;color:<?php echo esc_attr( $muted ); ?>;line-height:1.5;">
						<?php esc_html_e( 'If you didn\'t request this, you can safely ignore this email.', 'magicauth' ); ?>
					</td>
				</tr>
			</table>
			<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="600" style="max-width:600px;background:<?php echo esc_attr( $code_bg ); ?>;border-radius:0 0 8px 8px;margin-top:8px;">
				<tr>
					<td style="padding:16px 56px;font-size:12px;color:<?php echo esc_attr( $muted ); ?>;text-align:center;">
						<?php echo esc_html( $company_name ); ?>
						<?php if ( $is_test ) : ?>
							&middot; <?php esc_html_e( 'Test send', 'magicauth' ); ?>
						<?php endif; ?>
					</td>
				</tr>
			</table>
		</td>
	</tr>
</table>
</body>
</html>
