<?php
/**
 * "Built by [Brand]" agency-credit box.
 *
 * @var array{name:string,url:string,icon_url:string,icon_alt:string,label:string} $credit
 *
 * @package MagicAuth
 */

defined( 'ABSPATH' ) || exit;

if ( empty( $credit['name'] ) || empty( $credit['url'] ) || empty( $credit['icon_url'] ) ) {
	return;
}

$custom_label = isset( $credit['label'] ) ? trim( (string) $credit['label'] ) : '';
$brand_html   = '<span class="magicauth-credit__brand">' . esc_html( $credit['name'] ) . '</span>';
$line_html    = '' !== $custom_label
	? esc_html( $custom_label ) . ' ' . $brand_html
	/* translators: %s agency brand name (rendered bold) */
	: sprintf( __( 'Built by %s', 'magicauth' ), $brand_html );
?>
<div class="magicauth-credit">
	<a class="magicauth-credit__link" href="<?php echo esc_url( $credit['url'] ); ?>" target="_blank" rel="noopener noreferrer">
		<img class="magicauth-credit__icon" src="<?php echo esc_url( $credit['icon_url'] ); ?>" alt="<?php echo esc_attr( $credit['icon_alt'] ); ?>" width="16" height="16" />
		<span class="magicauth-credit__label">
			<?php echo wp_kses( $line_html, [ 'span' => [ 'class' => true ] ] ); ?>
		</span>
	</a>
</div>
