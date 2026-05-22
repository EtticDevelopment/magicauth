<?php
/**
 * Sign-in form: A (email), B (code), C (password), D (lostpassword), E (set new password).
 *
 * Override via yourtheme/magicauth/login-form.php.
 *
 * @var string $state            'a' | 'b' | 'c' | 'd' | 'e'.
 * @var string $action_url       admin-post.php URL.
 * @var string $redirect_to      Post-auth landing URL.
 * @var bool   $has_error        Drives aria-invalid; toast itself comes from Frontend\Toast.
 * @var string $session_email    State B hint ("we sent code to you@x.com").
 * @var string $session_id       State B hidden field for URL-handoff (cookie-less) sessions.
 * @var string $password_url     State-C URL.
 * @var string $lostpassword_url State-D URL.
 * @var string $magic_link_url   State-A URL.
 * @var string $reset_key        State E: reset key from email.
 * @var string $reset_login      State E: user_login from email.
 *
 * @package MagicAuth
 */

defined( 'ABSPATH' ) || exit;

$is_state_b   = 'b' === $state;
$is_state_c   = 'c' === $state;
$is_state_d   = 'd' === $state;
$is_state_e   = 'e' === $state;
$has_error    = ! empty( $has_error );
$site_name    = function_exists( 'get_bloginfo' ) ? get_bloginfo( 'name' ) : '';
$company_name = function_exists( 'magicauth_get_company_name' ) ? magicauth_get_company_name() : $site_name;
$show_pw      = (bool) magicauth_get_setting( 'allow_password_login', true );
$logo_url     = isset( $logo_url ) ? (string) $logo_url : '';

// Optional vars (shortcode passes a partial set).
$password_url     = isset( $password_url ) ? (string) $password_url : '';
$lostpassword_url = isset( $lostpassword_url ) ? (string) $lostpassword_url : '';
$magic_link_url   = isset( $magic_link_url ) ? (string) $magic_link_url : '';
$reset_key        = isset( $reset_key ) ? (string) $reset_key : '';
$reset_login      = isset( $reset_login ) ? (string) $reset_login : '';

// Only the branded wp-login screen sets this (LoginScreen::build_context);
// the shortcode never does, so the switcher stays off front-end pages.
$language_switcher = isset( $language_switcher ) && is_array( $language_switcher ) ? $language_switcher : null;

// Prefer company name; else strip taglines off site name ("Ettic » Tagline" → "Ettic").
if ( '' !== $company_name ) {
	$brand = $company_name;
} else {
	$brand = $site_name;
	if ( '' !== $site_name && preg_match( '/^(.*?)\s*[»|\x{2013}\x{2014}\-\x{00B7}:]\s*/u', $site_name, $m ) ) {
		$brand = trim( $m[1] );
	}
}

$heading_default = '';
switch ( $state ) {
	case 'b':
		$heading_default = __( 'Check your email', 'magicauth' );
		break;
	case 'c':
		$heading_default = '' !== $brand
			? sprintf( /* translators: %s site brand */ __( 'Sign in to %s', 'magicauth' ), $brand )
			: __( 'Sign in', 'magicauth' );
		break;
	case 'd':
		$heading_default = __( 'Reset your password', 'magicauth' );
		break;
	case 'e':
		$heading_default = __( 'Set a new password', 'magicauth' );
		break;
	case 'a':
	default:
		$heading_default = '' !== $brand
			? sprintf( /* translators: %s site brand */ __( 'Sign in to %s', 'magicauth' ), $brand )
			: __( 'Sign in', 'magicauth' );
		break;
}
$heading = function_exists( 'apply_filters' )
	? (string) apply_filters( 'magicauth_login_heading', $heading_default, $state, $brand, $site_name )
	: $heading_default;

// Map state → admin_post_* handler. A/B share magicauth_request.
switch ( $state ) {
	case 'c':
		$post_action  = 'magicauth_password';
		$nonce_action = 'magicauth_password';
		break;
	case 'd':
		$post_action  = 'magicauth_lostpassword';
		$nonce_action = 'magicauth_lostpassword';
		break;
	case 'e':
		$post_action  = 'magicauth_resetpass';
		$nonce_action = 'magicauth_resetpass';
		break;
	default:
		$post_action  = 'magicauth_request';
		$nonce_action = 'magicauth_request';
		break;
}
?>
<div class="magicauth-card" role="region" aria-labelledby="magicauth-heading">
	<?php do_action( 'magicauth_form_before', $state ); ?>

	<?php if ( '' !== $logo_url ) : ?>
		<div class="magicauth-logo">
			<img src="<?php echo esc_url( $logo_url ); ?>" alt="<?php echo esc_attr( '' !== $company_name ? $company_name : $site_name ); ?>" />
		</div>
	<?php endif; ?>

	<h1 id="magicauth-heading" class="magicauth-heading">
		<?php echo esc_html( $heading ); ?>
	</h1>

	<?php if ( $is_state_b ) : ?>
		<p class="magicauth-helper magicauth-helper--lead">
			<?php if ( '' !== $session_email ) : ?>
				<?php
				echo wp_kses(
					sprintf(
						/* translators: %s email address */
						__( 'Enter the verification code we sent to %s.', 'magicauth' ),
						'<strong>' . esc_html( $session_email ) . '</strong>'
					),
					[ 'strong' => [] ]
				);
				?>
			<?php else : ?>
				<?php esc_html_e( 'Enter the 6-character code we just emailed you.', 'magicauth' ); ?>
			<?php endif; ?>
		</p>
	<?php elseif ( $is_state_d ) : ?>
		<p class="magicauth-helper magicauth-helper--lead">
			<?php esc_html_e( 'Enter your username or email and we will send a link to set a new password.', 'magicauth' ); ?>
		</p>
	<?php elseif ( $is_state_e ) : ?>
		<p class="magicauth-helper magicauth-helper--lead">
			<?php esc_html_e( 'Choose a strong password. You will be signed in once it is saved.', 'magicauth' ); ?>
		</p>
	<?php endif; ?>

	<form
		class="magicauth-form"
		method="post"
		action="<?php echo esc_url( $action_url ); ?>"
		novalidate
		<?php
		if ( function_exists( 'apply_filters' ) ) {
			// data-* only — blocks `on*` event handlers a buggy filter might pass.
			$attrs = apply_filters( 'magicauth_form_attributes', [], $state );
			foreach ( (array) $attrs as $attr_key => $attr_val ) {
				$key = strtolower( (string) $attr_key );
				if ( 0 !== strpos( $key, 'data-' ) ) {
					continue;
				}
				echo ' ' . esc_attr( $key ) . '="' . esc_attr( (string) $attr_val ) . '"';
			}
		}
		?>
	>
		<input type="hidden" name="action" value="<?php echo esc_attr( $post_action ); ?>" />
		<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect_to ); ?>" />
		<?php if ( $is_state_b && ! empty( $session_id ) ) : ?>
			<input type="hidden" name="magicauth_sid" value="<?php echo esc_attr( (string) $session_id ); ?>" />
		<?php endif; ?>
		<?php if ( $is_state_e ) : ?>
			<input type="hidden" name="key" value="<?php echo esc_attr( $reset_key ); ?>" />
			<input type="hidden" name="login" value="<?php echo esc_attr( $reset_login ); ?>" />
		<?php endif; ?>
		<?php wp_nonce_field( $nonce_action, 'magicauth_nonce' ); ?>
		<?php \MagicAuth\Auth\Controller::render_hygiene_fields(); ?>

		<?php if ( $is_state_b ) : ?>

			<div class="magicauth-field magicauth-field--code">
				<label for="magicauth-code" class="magicauth-sr-only">
					<?php esc_html_e( '6-character verification code', 'magicauth' ); ?>
				</label>
				<input
					type="text"
					id="magicauth-code"
					name="magicauth_code"
					inputmode="text"
					autocomplete="one-time-code"
					pattern="[A-Za-z0-9]{3}-?[A-Za-z0-9]{3}"
					maxlength="7"
					spellcheck="false"
					autocapitalize="characters"
					dir="ltr"
					placeholder="XXX - XXX"
					required
					aria-required="true"
					<?php echo $has_error ? 'aria-invalid="true"' : ''; ?>
				/>
			</div>

			<button type="submit" class="magicauth-button">
				<span class="magicauth-button__label">
					<?php
					echo esc_html(
						(string) apply_filters( 'magicauth_form_button_label', __( 'Sign in', 'magicauth' ), $state )
					);
					?>
				</span>
				<span class="magicauth-button__spinner" aria-hidden="true"></span>
			</button>

			<p class="magicauth-helper magicauth-helper--small">
				<a class="magicauth-link" href="<?php echo esc_url( remove_query_arg( [ 'magicauth_step', 'magicauth_error', 'magicauth_sent', 'magicauth_link_invalid', 'magicauth_sid' ] ) ); ?>">
					<?php esc_html_e( 'Use a different email', 'magicauth' ); ?>
				</a>
			</p>

		<?php elseif ( $is_state_c ) : ?>

			<div class="magicauth-field">
				<label for="magicauth-log" class="magicauth-sr-only">
					<?php esc_html_e( 'Username or email', 'magicauth' ); ?>
				</label>
				<input
					type="text"
					id="magicauth-log"
					name="log"
					autocomplete="username"
					placeholder="<?php esc_attr_e( 'Username or email', 'magicauth' ); ?>"
					required
					aria-required="true"
					<?php echo $has_error ? 'aria-invalid="true"' : ''; ?>
				/>
			</div>

			<div class="magicauth-field">
				<label for="magicauth-pwd" class="magicauth-sr-only">
					<?php esc_html_e( 'Password', 'magicauth' ); ?>
				</label>
				<input
					type="password"
					id="magicauth-pwd"
					name="pwd"
					autocomplete="current-password"
					placeholder="<?php esc_attr_e( 'Password', 'magicauth' ); ?>"
					required
					aria-required="true"
					<?php echo $has_error ? 'aria-invalid="true"' : ''; ?>
				/>
			</div>

			<label class="magicauth-field magicauth-field--inline">
				<input type="checkbox" name="rememberme" value="1" checked />
				<span><?php esc_html_e( 'Remember me', 'magicauth' ); ?></span>
			</label>

			<button type="submit" class="magicauth-button">
				<span class="magicauth-button__label">
					<?php
					echo esc_html(
						(string) apply_filters( 'magicauth_form_button_label', __( 'Sign in', 'magicauth' ), $state )
					);
					?>
				</span>
				<span class="magicauth-button__spinner" aria-hidden="true"></span>
			</button>

			<p class="magicauth-helper magicauth-helper--small">
				<?php if ( '' !== $lostpassword_url ) : ?>
					<a class="magicauth-link" href="<?php echo esc_url( $lostpassword_url ); ?>">
						<?php esc_html_e( 'Forgot password?', 'magicauth' ); ?>
					</a>
				<?php endif; ?>
			</p>

			<p class="magicauth-helper magicauth-helper--small">
				<a class="magicauth-link" href="<?php echo esc_url( '' !== $magic_link_url ? $magic_link_url : remove_query_arg( [ 'magicauth_step', 'magicauth_error', 'magicauth_sent', 'magicauth_link_invalid', 'magicauth_sid' ] ) ); ?>">
					<?php esc_html_e( 'Use a magic link instead', 'magicauth' ); ?>
				</a>
			</p>

		<?php elseif ( $is_state_d ) : ?>

			<div class="magicauth-field">
				<label for="magicauth-userlogin" class="magicauth-sr-only">
					<?php esc_html_e( 'Username or email', 'magicauth' ); ?>
				</label>
				<input
					type="text"
					id="magicauth-userlogin"
					name="user_login"
					autocomplete="username"
					placeholder="<?php esc_attr_e( 'Username or email', 'magicauth' ); ?>"
					required
					aria-required="true"
				/>
			</div>

			<button type="submit" class="magicauth-button">
				<span class="magicauth-button__label">
					<?php
					echo esc_html(
						(string) apply_filters( 'magicauth_form_button_label', __( 'Send Reset Link', 'magicauth' ), $state )
					);
					?>
				</span>
				<span class="magicauth-button__spinner" aria-hidden="true"></span>
			</button>

			<p class="magicauth-helper magicauth-helper--small">
				<a class="magicauth-link" href="<?php echo esc_url( '' !== $magic_link_url ? $magic_link_url : remove_query_arg( [ 'magicauth_step', 'magicauth_error', 'magicauth_sent', 'magicauth_link_invalid', 'magicauth_sid' ] ) ); ?>">
					<?php esc_html_e( 'Back to sign in', 'magicauth' ); ?>
				</a>
			</p>

		<?php elseif ( $is_state_e ) : ?>

			<div class="magicauth-field">
				<label for="magicauth-pass1" class="magicauth-sr-only">
					<?php esc_html_e( 'New password', 'magicauth' ); ?>
				</label>
				<input
					type="password"
					id="magicauth-pass1"
					name="pass1"
					autocomplete="new-password"
					placeholder="<?php esc_attr_e( 'New password', 'magicauth' ); ?>"
					required
					aria-required="true"
					<?php echo $has_error ? 'aria-invalid="true"' : ''; ?>
				/>
			</div>

			<div class="magicauth-field">
				<label for="magicauth-pass2" class="magicauth-sr-only">
					<?php esc_html_e( 'Confirm new password', 'magicauth' ); ?>
				</label>
				<input
					type="password"
					id="magicauth-pass2"
					name="pass2"
					autocomplete="new-password"
					placeholder="<?php esc_attr_e( 'Confirm new password', 'magicauth' ); ?>"
					required
					aria-required="true"
					<?php echo $has_error ? 'aria-invalid="true"' : ''; ?>
				/>
			</div>

			<button type="submit" class="magicauth-button">
				<span class="magicauth-button__label">
					<?php
					echo esc_html(
						(string) apply_filters( 'magicauth_form_button_label', __( 'Save and sign in', 'magicauth' ), $state )
					);
					?>
				</span>
				<span class="magicauth-button__spinner" aria-hidden="true"></span>
			</button>

		<?php else : ?>

			<div class="magicauth-field">
				<label for="magicauth-email" class="magicauth-sr-only">
					<?php esc_html_e( 'Email address', 'magicauth' ); ?>
				</label>
				<input
					type="email"
					id="magicauth-email"
					name="magicauth_email"
					inputmode="email"
					autocomplete="email"
					placeholder="<?php esc_attr_e( 'you@example.com', 'magicauth' ); ?>"
					required
					aria-required="true"
					<?php echo $has_error ? 'aria-invalid="true"' : ''; ?>
				/>
			</div>

			<button type="submit" class="magicauth-button" disabled aria-disabled="true">
				<span class="magicauth-button__label">
					<?php
					echo esc_html(
						(string) apply_filters( 'magicauth_form_button_label', __( 'Send Link', 'magicauth' ), $state )
					);
					?>
				</span>
				<span class="magicauth-button__spinner" aria-hidden="true"></span>
			</button>

		<?php endif; ?>

		<?php
		// Card footer: password fallback (state A only — C is the password
		// screen; D/E have their own back-links) on the left, compact language
		// switcher on the right. Both sit inside the form; the switcher is <a>
		// links (never a nested <form>), so a click is a plain GET that core
		// turns into a wp_lang cookie + locale switch.
		$pw_fallback = ( ! $is_state_b && ! $is_state_c && ! $is_state_d && ! $is_state_e && $show_pw && '' !== $password_url );
		if ( $pw_fallback || null !== $language_switcher ) :
			?>
			<div class="magicauth-cardfoot<?php echo $pw_fallback ? ' magicauth-cardfoot--divided' : ''; ?>">
				<?php if ( $pw_fallback ) : ?>
					<a class="magicauth-link magicauth-cardfoot__link" href="<?php echo esc_url( $password_url ); ?>">
						<?php esc_html_e( 'Sign in with password', 'magicauth' ); ?>
					</a>
				<?php endif; ?>

				<?php if ( null !== $language_switcher ) : ?>
					<details class="magicauth-lang">
						<summary class="magicauth-lang__summary">
							<svg class="magicauth-lang__icon" viewBox="0 0 24 24" width="16" height="16" aria-hidden="true" focusable="false">
								<path fill="currentColor" d="M12.87 15.07l-2.54-2.51.03-.03c1.74-1.94 2.98-4.17 3.71-6.53H17V4h-7V2H8v2H1v1.99h11.17C11.5 7.92 10.44 9.75 9 11.35 8.07 10.32 7.3 9.19 6.69 8h-2c.73 1.63 1.73 3.17 2.98 4.56l-5.09 5.02L4 19l5-5 3.11 3.11.76-2.04zM18.5 10h-2L12 22h2l1.12-3h4.75L21 22h2l-4.5-12zm-2.62 7l1.62-4.33L19.12 17h-3.24z"/>
							</svg>
							<span class="magicauth-sr-only"><?php esc_html_e( 'Change language. Current:', 'magicauth' ); ?></span>
							<span class="magicauth-lang__code"><?php echo esc_html( $language_switcher['current_code'] ); ?></span>
							<svg class="magicauth-lang__caret" viewBox="0 0 24 24" width="12" height="12" aria-hidden="true" focusable="false">
								<path fill="currentColor" d="M7 10l5 5 5-5z"/>
							</svg>
						</summary>
						<ul class="magicauth-lang__menu" role="list">
							<?php foreach ( $language_switcher['options'] as $opt ) : ?>
								<li>
									<a class="magicauth-lang__opt<?php echo $opt['active'] ? ' is-active' : ''; ?>" href="<?php echo esc_url( $opt['url'] ); ?>"<?php echo $opt['active'] ? ' aria-current="true"' : ''; ?>>
										<span class="magicauth-lang__opt-code"><?php echo esc_html( $opt['code'] ); ?></span>
										<span class="magicauth-lang__opt-name"><?php echo esc_html( $opt['name'] ); ?></span>
									</a>
								</li>
							<?php endforeach; ?>
						</ul>
					</details>
				<?php endif; ?>
			</div>
		<?php endif; ?>
	</form>

	<?php do_action( 'magicauth_form_after', $state ); ?>
</div>

<div class="magicauth-sr-only" aria-live="polite" id="magicauth-status"></div>
