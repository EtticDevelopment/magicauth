<?php
/**
 * In-page admin footer for MagicAuth screens.
 *
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Admin;

defined( 'ABSPATH' ) || exit;

final class Footer {

	private const URL_DOCS     = 'https://docs.ettic.nl/docs/magicauth';
	private const URL_GITHUB   = 'https://github.com/EtticDevelopment/magicauth';
	private const URL_SUPPORT  = 'https://wordpress.org/support/plugin/magicauth/';
	private const URL_REVIEW   = 'https://wordpress.org/support/plugin/magicauth/reviews/';
	private const URL_SECURITY = 'https://docs.ettic.nl/docs/security';

	/** Emit the footer block. Caller must place it inside .magicauth-admin. */
	public static function render(): void {
		?>
		<footer class="magicauth-footer" role="contentinfo">
			<div class="magicauth-footer__inner">
				<div class="magicauth-footer__top">
					<div class="magicauth-footer__lead">
						<strong class="magicauth-footer__brand"><?php esc_html_e( 'MagicAuth by Ettic.', 'magicauth' ); ?></strong>
						<span class="magicauth-footer__tagline"><?php esc_html_e( 'Focused, open-source WordPress plugins.', 'magicauth' ); ?></span>
					</div>
					<span class="magicauth-footer__version">MagicAuth <span class="magicauth-footer__version-num">v<?php echo esc_html( MAGICAUTH_VERSION ); ?></span></span>
				</div>
				<nav class="magicauth-footer__nav" aria-label="<?php esc_attr_e( 'MagicAuth resources', 'magicauth' ); ?>">
					<a href="<?php echo esc_url( self::URL_DOCS ); ?>"><?php esc_html_e( 'Docs', 'magicauth' ); ?></a>
					<span class="magicauth-footer__sep" aria-hidden="true">&middot;</span>
					<a href="<?php echo esc_url( self::URL_GITHUB ); ?>"><?php esc_html_e( 'GitHub', 'magicauth' ); ?></a>
					<span class="magicauth-footer__sep" aria-hidden="true">&middot;</span>
					<a href="<?php echo esc_url( self::URL_SUPPORT ); ?>"><?php esc_html_e( 'Support', 'magicauth' ); ?></a>
					<span class="magicauth-footer__sep" aria-hidden="true">&middot;</span>
					<a href="<?php echo esc_url( self::URL_SECURITY ); ?>"><?php esc_html_e( 'Report a vulnerability', 'magicauth' ); ?></a>
					<span class="magicauth-footer__sep" aria-hidden="true">&middot;</span>
					<a href="<?php echo esc_url( self::URL_REVIEW ); ?>" title="<?php esc_attr_e( 'Like MagicAuth? Leave a review and help us keep building open source.', 'magicauth' ); ?>"><?php esc_html_e( 'Leave a review', 'magicauth' ); ?></a>
				</nav>
			</div>
		</footer>
		<?php
	}
}
