<?php
/**
 * Post-login passkey prompt (SPEC 2.1, 8.5, 8.12): a closed modal <dialog>,
 * printed once in the footer of a signed-in page after an email sign-in. The
 * account script opens it with showModal() only when the client gate passes;
 * without JavaScript it stays closed.
 *
 * Override: yourtheme/magicauth/passkey-prompt.php. JS binds only to these
 * attributes, never to classes: data-magicauth-pk-prompt, -render (must be
 * $render: the script ignores a prompt without this request's key), -title,
 * -view="offer|reauth|success|error", -create (P4 and P18), -later (P5),
 * -shared (P6), -close (P17), -done (P9), -success, -error-text, -status,
 * -alert (persistent live regions, never hidden), and the step-up view's
 * attributes (passkey-reauth.php).
 *
 * Contract: no <form method="dialog"> (Enter in the code input would close
 * the dialog); every <button> is type="button" except R7, the only submit
 * button of the step-up view's own form. Never printed on a logged-out
 * response (2.6 row 7).
 *
 * @var array<string,string> $strings      ManageShortcode::strings() + Prompt::strings().
 * @var bool                 $has_passkeys P1b instead of P1.
 * @var string               $manage_url   Module::manage_url(), '' for none.
 * @var string               $render       Assets::render_key().
 *
 * @package MagicAuth
 */

defined( 'ABSPATH' ) || exit;

$render = isset( $render ) ? (string) $render : '';
?>
<dialog class="magicauth-pk-dialog magicauth-pk-prompt" data-magicauth-pk-prompt data-magicauth-pk-render="<?php echo esc_attr( $render ); ?>" aria-labelledby="magicauth-pk-title" aria-describedby="magicauth-pk-desc">
	<div class="magicauth-pk-dialog__inner">
		<h2 id="magicauth-pk-title" class="magicauth-pk-dialog__title" tabindex="-1" data-magicauth-pk-title><?php echo esc_html( $has_passkeys ? $strings['P1b'] : $strings['P1'] ); ?></h2>
		<div data-magicauth-pk-view="offer">
			<p id="magicauth-pk-desc" class="magicauth-pk-dialog__text"><?php echo esc_html( $strings['P2'] ); ?></p>
			<p class="magicauth-pk-note"><?php echo esc_html( $strings['P3'] ); ?></p>
			<div class="magicauth-pk-actions">
				<button type="button" class="magicauth-pk-btn magicauth-pk-btn--primary" data-magicauth-pk-create><?php echo esc_html( $strings['P4'] ); ?></button>
				<button type="button" class="magicauth-pk-btn" data-magicauth-pk-later><?php echo esc_html( $strings['P5'] ); ?></button>
			</div>
			<button type="button" class="magicauth-pk-link" data-magicauth-pk-shared><?php echo esc_html( $strings['P6'] ); ?></button>
		</div>
		<div data-magicauth-pk-view="reauth" hidden>
			<?php
			$magicauth_pk_reauth = \MagicAuth\Email\Mailer::render(
				'passkey-reauth.php',
				[
					'strings'         => $strings,
					'in_form_context' => false,
					'title_id'        => 'magicauth-pk-prompt-reauth-title',
					'instance'        => 0,
				]
			);
			echo $magicauth_pk_reauth; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- the template escapes every value.
			?>
		</div>
		<div data-magicauth-pk-view="success" hidden>
			<p class="magicauth-pk-dialog__text" data-magicauth-pk-success tabindex="-1"><?php echo esc_html( $strings['P8'] ); ?></p>
			<div class="magicauth-pk-actions">
				<button type="button" class="magicauth-pk-btn magicauth-pk-btn--primary" data-magicauth-pk-done><?php echo esc_html( $strings['P9'] ); ?></button>
				<?php if ( '' !== $manage_url ) : ?>
					<a class="magicauth-pk-link" href="<?php echo esc_url( $manage_url ); ?>"><?php echo esc_html( $strings['P19'] ); ?></a>
				<?php endif; ?>
			</div>
		</div>
		<div data-magicauth-pk-view="error" hidden>
			<p class="magicauth-pk-dialog__text" data-magicauth-pk-error-text tabindex="-1"></p>
			<div class="magicauth-pk-actions">
				<button type="button" class="magicauth-pk-btn magicauth-pk-btn--primary" data-magicauth-pk-create><?php echo esc_html( $strings['P18'] ); ?></button>
				<button type="button" class="magicauth-pk-btn" data-magicauth-pk-later><?php echo esc_html( $strings['P5'] ); ?></button>
			</div>
		</div>
		<button type="button" class="magicauth-pk-close" data-magicauth-pk-close aria-label="<?php echo esc_attr( $strings['P17'] ); ?>">&times;</button>
		<p class="magicauth-pk-sr-only" data-magicauth-pk-status role="status"></p>
		<p class="magicauth-pk-sr-only" data-magicauth-pk-alert role="alert"></p>
	</div>
</dialog>
