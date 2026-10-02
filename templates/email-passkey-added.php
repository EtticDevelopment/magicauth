<?php
/**
 * "A passkey was added" HTML email body (SPEC 10.2). Security notice: no
 * clickable URLs, no passkey name or other user-supplied text, and no line
 * that invites creating a passkey (D-41). E3 greets without the display name:
 * it is user-editable (invariant 12, D-35).
 *
 * @var \WP_User $user
 * @var string   $company_name
 * @var string   $brand_color
 * @var string   $passkey_label   "Passkey ending in XXXX" (M34).
 * @var string   $passkey_suffix  The XXXX of the label.
 * @var string   $provider_text   M31 or M30.
 * @var string   $sync_label      M6, M6b or M7.
 * @var string   $manage_location Plain text, may be ''.
 * @var string   $added_at_local
 * @var string   $timezone_label
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
?>
<!doctype html>
<html lang="<?php echo esc_attr( str_replace( '_', '-', (string) get_locale() ) ); ?>" dir="<?php echo esc_attr( $dir ); ?>">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title><?php esc_html_e( 'A passkey was added', 'magicauth' ); ?></title>
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
						<?php esc_html_e( 'A passkey was added', 'magicauth' ); ?>
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
								/* translators: 1: company name, 2: date and time, 3: time zone */
								__( 'A passkey was added to your account at %1$s on %2$s (%3$s).', 'magicauth' ),
								$company_name,
								$added_at_local,
								$timezone_label
							)
						);
						?>
					</td>
				</tr>
				<tr>
					<td style="<?php echo esc_attr( $line_style ); ?>">
						<?php
						/* translators: %s: "Passkey ending in 7F3A" */
						echo esc_html( sprintf( __( 'Passkey: %s', 'magicauth' ), $passkey_label ) );
						?>
					</td>
				</tr>
				<tr>
					<td style="<?php echo esc_attr( $line_style ); ?>">
						<?php
						echo esc_html(
							sprintf(
								/* translators: 1: passkey provider, 2: sync status, for example "This device only" */
								__( 'Stored in: %1$s. %2$s', 'magicauth' ),
								$provider_text,
								$sync_label
							)
						);
						?>
					</td>
				</tr>
				<tr>
					<td style="padding:16px 56px 8px 56px;font-size:16px;line-height:1.5;color:<?php echo esc_attr( $text_color ); ?>;">
						<?php esc_html_e( 'If you added this passkey, you do not need to do anything.', 'magicauth' ); ?>
					</td>
				</tr>
				<tr>
					<td style="padding:0 56px 48px 56px;font-size:16px;line-height:1.5;color:<?php echo esc_attr( $text_color ); ?>;">
						<?php
						if ( '' !== $manage_location ) {
							echo esc_html(
								sprintf(
									/* translators: 1: where the person manages passkeys, for example "Account (/account/)", 2: last 4 characters of the passkey's identifier */
									__( 'If you did not add this passkey yourself, someone else may have access to your account. Sign in with your email, go to %1$s, remove the passkey ending in %2$s and choose "Sign out on all other devices". Then contact your administrator.', 'magicauth' ),
									$manage_location,
									$passkey_suffix
								)
							);
						} else {
							echo esc_html(
								sprintf(
									/* translators: %s: last 4 characters of the passkey's identifier */
									__( 'If you did not add this passkey yourself, someone else may have access to your account. Sign in with your email, open your passkey settings, remove the passkey ending in %s and choose "Sign out on all other devices". Then contact your administrator.', 'magicauth' ),
									$passkey_suffix
								)
							);
						}
						?>
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
