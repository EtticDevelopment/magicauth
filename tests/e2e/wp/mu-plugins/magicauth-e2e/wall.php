<?php
/**
 * Theme-style login wall (SPEC 8.9 contract), the academy's shape: the theme's
 * own email form posting to MagicAuth, one input with "username webauthn", a
 * passkey button and the optional status regions. No redirect_to input, so the
 * passkey destination is the current URL, fragment included (E6). The page
 * renders errors itself: it cancels magicauth:passkey:error (E22).
 *
 * @package MagicAuth\Tests
 */

defined( 'ABSPATH' ) || exit;
?>
<div class="e2e-wall" data-e2e-wall>
	<h2 class="e2e-wall__title">Members only</h2>
	<form class="e2e-wall__form" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" novalidate>
		<input type="hidden" name="action" value="magicauth_request">
		<?php wp_nonce_field( 'magicauth_request', 'magicauth_nonce' ); ?>
		<?php
		if ( class_exists( '\MagicAuth\Auth\Controller' ) ) {
			\MagicAuth\Auth\Controller::render_hygiene_fields();
		}
		?>
		<label class="e2e-wall__label" for="e2e-wall-email">Your email</label>
		<input id="e2e-wall-email" class="e2e-wall__input" type="email" name="magicauth_email" autocomplete="username webauthn">
		<button type="submit" class="e2e-wall__submit">Email me a sign-in link</button>
		<div class="e2e-wall__passkey-wrap" data-magicauth-passkey-root hidden>
			<button type="button" class="e2e-wall__passkey" data-magicauth-passkey-signin hidden>Use your passkey</button>
		</div>
		<p class="e2e-wall__status" data-magicauth-passkey-status role="status"></p>
		<p class="e2e-wall__error" data-magicauth-passkey-error role="alert"></p>
	</form>
	<p class="e2e-wall__message" data-e2e-wall-message role="alert"></p>
	<script>
	document.addEventListener( 'magicauth:passkey:error', function ( e ) {
		e.preventDefault();
		var box = document.querySelector( '[data-e2e-wall-message]' );
		box.textContent = 'Wall: ' + e.detail.message;
		box.setAttribute( 'data-code', String( e.detail.code ) );
	} );
	</script>
</div>
