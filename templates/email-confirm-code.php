<?php
/**
 * Step-up confirmation code HTML email body (SPEC 10.3). Not a login email:
 * no link of any kind; only E11 names the action the signed-in user started.
 *
 * @var \WP_User $user
 * @var string   $company_name
 * @var string   $brand_color
 * @var string   $brand_text
 * @var string   $code_display
 * @var int      $expiry_minutes
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
/* translators: %s: company name */
$heading = sprintf( __( 'Your confirmation code for %s', 'magicauth' ), $company_name );
?>
<!doctype html>
<html lang="<?php echo esc_attr( str_replace( '_', '-', (string) get_locale() ) ); ?>" dir="<?php echo esc_attr( $dir ); ?>">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title><?php echo esc_html( $heading ); ?></title>
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
						<?php echo esc_html( $heading ); ?>
					</td>
				</tr>
				<tr>
					<td style="padding:0 56px 24px 56px;font-size:16px;line-height:1.5;color:<?php echo esc_attr( $text_color ); ?>;">
						<?php
						// Format and code are escaped separately; only the <strong> wrapper is markup.
						printf( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- both parts escaped.
							/* translators: %s: confirmation code, for example ABC-DEF */
							esc_html__( 'Use this code to confirm it is you: %s', 'magicauth' ),
							'<strong style="font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:22px;letter-spacing:2px;white-space:nowrap;">' . esc_html( $code_display ) . '</strong>'
						);
						?>
					</td>
				</tr>
				<tr>
					<td style="padding:0 56px 8px 56px;font-size:16px;line-height:1.5;color:<?php echo esc_attr( $text_color ); ?>;">
						<?php
						echo esc_html(
							sprintf(
								/* translators: %d: minutes the code stays valid */
								_n(
									'The code is valid for %d minute. You asked for it to add a passkey to your account.',
									'The code is valid for %d minutes. You asked for it to add a passkey to your account.',
									(int) $expiry_minutes,
									'magicauth'
								),
								(int) $expiry_minutes
							)
						);
						?>
					</td>
				</tr>
				<tr>
					<td style="padding:0 56px 8px 56px;font-size:16px;line-height:1.5;color:<?php echo esc_attr( $text_color ); ?>;">
						<?php
						/* translators: %s: company name */
						echo esc_html( sprintf( __( 'Never share this code. Nobody from %s will ask you for it.', 'magicauth' ), $company_name ) );
						?>
					</td>
				</tr>
				<tr>
					<td style="padding:8px 56px 48px 56px;font-size:14px;line-height:1.5;color:<?php echo esc_attr( $muted ); ?>;">
						<?php esc_html_e( 'If you did not ask for this code, someone may be signed in to your account. Contact your administrator.', 'magicauth' ); ?>
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
