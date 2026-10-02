<?php
/**
 * Passkey management (SPEC 2.3, 8.5, 8.12): the list, add, rename, remove,
 * "Sign out on all other devices", and the remove-confirm and step-up views.
 * Shared by [magicauth_passkeys] and the wp-admin profile section. Signed-in
 * pages only.
 *
 * Override: yourtheme/magicauth/passkeys-manage.php. JS binds only to
 * data-magicauth-pk-* attributes, never to classes: -manage, -mode, -user,
 * -admin-nonce, -render, -dialogs, -title, -list, -item (with data-id),
 * -name, -actions, -rename, -remove, -empty, -add, -nocreate,
 * -signout-others, -remove-all, -status, -alert, -view="reauth",
 * -reauth-dialog, -remove-dialog, -remove-text, -remove-name, -signout,
 * -remove-confirm, -remove-cancel, -remove-all-dialog, -remove-all-confirm,
 * -remove-all-cancel.
 *
 * The section and every dialog must carry data-magicauth-pk-render="$render"
 * (this request's key, also in the account config): the script ignores any
 * section or dialog without it, so look-alike markup in post content is never
 * bound. With $dialogs false the section names the ids of its dialogs in
 * data-magicauth-pk-dialogs; the script finds dialogs outside the section
 * only through those ids.
 *
 * After the first add, rename or removal the script rebuilds the list items
 * from the response with the markup and classes of $magicauth_pk_item below;
 * an override that changes the item markup gets that markup back then, so
 * restyle items through these classes rather than restructuring them.
 *
 * Contract: this template contains no <form> element (the profile section
 * renders inside core's <form id="your-profile">, and a nested form start
 * tag is dropped by the parser), and every <button> is type="button". With
 * $part 'section' and $dialogs true (the shortcode) the step-up view and the
 * remove dialog are inside the section; with $dialogs false (wp-admin) the
 * section has neither, and ProfileSection::render_dialogs() prints $part
 * 'dialogs' on admin_footer, outside the profile form.
 *
 * Action controls are rendered hidden and shown by the account script: without
 * JavaScript the list is visible and M26 explains why nothing can be done.
 *
 * @var string                         $part               section | dialogs.
 * @var string                         $mode               manage (account endpoints) | admin (admin endpoints).
 * @var array<int,array<string,mixed>> $items              Presenter::item() arrays.
 * @var bool                           $list_error         The list could not be read.
 * @var array<string,string>           $strings            ManageShortcode::strings().
 * @var bool                           $dialogs            Dialogs inside the section.
 * @var bool                           $can_add
 * @var bool                           $can_rename
 * @var bool                           $can_signout_others
 * @var bool                           $can_remove_all
 * @var bool                           $own                The list is the viewer's own.
 * @var bool                           $module_off
 * @var int                            $user_id            Whose passkeys.
 * @var string                         $admin_nonce        For the admin endpoints ('' in the shortcode).
 * @var string                         $display_name       For A3 (another user).
 * @var string                         $heading_tag        h2.
 * @var int                            $instance           Unique id suffix.
 * @var string                         $render             Assets::render_key().
 *
 * @package MagicAuth
 */

defined( 'ABSPATH' ) || exit;

$heading_tag = in_array( $heading_tag, [ 'h2', 'h3' ], true ) ? $heading_tag : 'h2';
$title_id    = 'magicauth-pk-manage-title-' . (int) $instance;
$render      = isset( $render ) ? (string) $render : '';

// Ids of the dialogs printed for this instance (the section names them when they sit outside it).
$magicauth_pk_dialog_ids = [ 'magicauth-pk-remove-dialog-' . (int) $instance ];
if ( $can_remove_all ) {
	$magicauth_pk_dialog_ids[] = 'magicauth-pk-remove-all-dialog-' . (int) $instance;
}
if ( 'manage' === $mode && ! $dialogs ) {
	$magicauth_pk_dialog_ids[] = 'magicauth-pk-reauth-dialog-' . (int) $instance;
}

// "passkey %s" around a <bdi>, so the accessible name starts with the visible text (8.5).
$magicauth_pk_suffix = static function ( string $pattern, string $name ): string {
	$parts = explode( '%s', $pattern, 2 );
	return esc_html( ' ' . $parts[0] ) . '<bdi>' . esc_html( $name ) . '</bdi>' . esc_html( $parts[1] ?? '' );
};

$magicauth_pk_item = static function ( array $item ) use ( $strings, $can_rename, $magicauth_pk_suffix ): void {
	$name     = (string) ( $item['name'] ?? '' );
	$blocked  = ! empty( $item['blocked'] );
	$provider = is_string( $item['provider'] ?? null ) && '' !== $item['provider'] ? sprintf( $strings['M31'], $item['provider'] ) : $strings['M30'];
	if ( ! empty( $item['synced'] ) ) {
		$sync = $strings['M6'];
	} elseif ( ! empty( $item['sync_possible'] ) ) {
		$sync = $strings['M6b'];
	} else {
		$sync = $strings['M7'];
	}
	?>
	<li class="magicauth-pk-item" data-magicauth-pk-item data-id="<?php echo esc_attr( (string) (int) ( $item['id'] ?? 0 ) ); ?>">
		<div class="magicauth-pk-item__body">
			<p class="magicauth-pk-item__name"><bdi data-magicauth-pk-name><?php echo esc_html( $name ); ?></bdi></p>
			<p class="magicauth-pk-item__label"><?php echo esc_html( (string) ( $item['label'] ?? '' ) ); ?></p>
			<p class="magicauth-pk-item__meta"><span><?php echo esc_html( $provider ); ?></span> <span><?php echo esc_html( $sync ); ?></span></p>
			<p class="magicauth-pk-item__meta">
				<time datetime="<?php echo esc_attr( (string) ( $item['created'] ?? '' ) ); ?>"><?php echo esc_html( (string) ( $item['created_label'] ?? '' ) ); ?></time>
				<?php if ( is_string( $item['last_used'] ?? null ) ) : ?>
					<time datetime="<?php echo esc_attr( $item['last_used'] ); ?>"><?php echo esc_html( (string) ( $item['last_used_label'] ?? '' ) ); ?></time>
				<?php else : ?>
					<span><?php echo esc_html( $strings['M10'] ); ?></span>
				<?php endif; ?>
			</p>
			<?php if ( ! empty( $item['is_new'] ) || $blocked ) : ?>
				<p class="magicauth-pk-badges">
					<?php if ( ! empty( $item['is_new'] ) ) : ?>
						<span class="magicauth-pk-badge"><?php echo esc_html( $strings['M13'] ); ?></span>
					<?php endif; ?>
					<?php if ( $blocked ) : ?>
						<span class="magicauth-pk-badge magicauth-pk-badge--warning"><?php echo esc_html( $strings['M36'] ); ?></span>
					<?php endif; ?>
				</p>
			<?php endif; ?>
			<?php if ( empty( $item['usable_here'] ) ) : ?>
				<p class="magicauth-pk-item__note"><?php echo esc_html( $strings['M11'] ); ?></p>
			<?php endif; ?>
			<?php if ( $blocked ) : ?>
				<p class="magicauth-pk-item__warning"><?php echo esc_html( $strings['M12'] ); ?></p>
			<?php endif; ?>
		</div>
		<div class="magicauth-pk-item__actions" data-magicauth-pk-actions>
			<?php if ( $can_rename && ! $blocked ) : ?>
				<button type="button" class="magicauth-pk-btn" data-magicauth-pk-rename hidden><?php echo esc_html( $strings['M14v'] ); ?><span class="magicauth-pk-sr-only"><?php echo $magicauth_pk_suffix( $strings['M14s'], $name ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in the closure. ?></span></button>
			<?php endif; ?>
			<button type="button" class="magicauth-pk-btn" data-magicauth-pk-remove hidden><?php echo esc_html( $strings['M18v'] ); ?><span class="magicauth-pk-sr-only"><?php echo $magicauth_pk_suffix( $strings['M18s'], $name ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in the closure. ?></span></button>
		</div>
	</li>
	<?php
};

$magicauth_pk_reauth = static function ( bool $in_form_context ) use ( $strings, $instance ): void {
	$view = \MagicAuth\Email\Mailer::render(
		'passkey-reauth.php',
		[
			'strings'         => $strings,
			'in_form_context' => $in_form_context,
			'title_id'        => 'magicauth-pk-reauth-title-' . (int) $instance,
			'instance'        => (int) $instance,
		]
	);
	echo $view; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- the template escapes every value.
};

$magicauth_pk_dialogs = static function () use ( $strings, $own, $mode, $can_remove_all, $display_name, $dialogs, $instance, $render, $magicauth_pk_reauth ): void {
	$remove_id = 'magicauth-pk-remove-title-' . (int) $instance;
	?>
	<dialog class="magicauth-pk-dialog" id="<?php echo esc_attr( 'magicauth-pk-remove-dialog-' . (int) $instance ); ?>" data-magicauth-pk-remove-dialog data-magicauth-pk-render="<?php echo esc_attr( $render ); ?>" aria-labelledby="<?php echo esc_attr( $remove_id ); ?>">
		<div class="magicauth-pk-dialog__inner">
			<h2 id="<?php echo esc_attr( $remove_id ); ?>" class="magicauth-pk-dialog__title" tabindex="-1"><?php echo esc_html( $strings['M19'] ); ?></h2>
			<?php if ( $own ) : ?>
				<p class="magicauth-pk-dialog__text" data-magicauth-pk-remove-text></p>
			<?php else : ?>
				<p class="magicauth-pk-dialog__text"><bdi data-magicauth-pk-remove-name></bdi></p>
			<?php endif; ?>
			<p class="magicauth-pk-dialog__text"><label class="magicauth-pk-check"><input type="checkbox" data-magicauth-pk-signout checked> <?php echo esc_html( $own ? $strings['M33'] : $strings['A9'] ); ?></label></p>
			<div class="magicauth-pk-actions">
				<button type="button" class="magicauth-pk-btn" data-magicauth-pk-remove-cancel><?php echo esc_html( $strings['M17'] ); ?></button>
				<button type="button" class="magicauth-pk-btn magicauth-pk-btn--danger" data-magicauth-pk-remove-confirm><?php echo esc_html( $strings['M21'] ); ?></button>
			</div>
		</div>
	</dialog>
	<?php if ( $can_remove_all ) : ?>
		<?php $all_id = 'magicauth-pk-remove-all-title-' . (int) $instance; ?>
		<dialog class="magicauth-pk-dialog" id="<?php echo esc_attr( 'magicauth-pk-remove-all-dialog-' . (int) $instance ); ?>" data-magicauth-pk-remove-all-dialog data-magicauth-pk-render="<?php echo esc_attr( $render ); ?>" aria-labelledby="<?php echo esc_attr( $all_id ); ?>">
			<div class="magicauth-pk-dialog__inner">
				<h2 id="<?php echo esc_attr( $all_id ); ?>" class="magicauth-pk-dialog__title" tabindex="-1"><?php echo esc_html( sprintf( $strings['A3'], $display_name ) ); ?></h2>
				<p class="magicauth-pk-dialog__text"><label class="magicauth-pk-check"><input type="checkbox" data-magicauth-pk-signout checked> <?php echo esc_html( $strings['A9'] ); ?></label></p>
				<div class="magicauth-pk-actions">
					<button type="button" class="magicauth-pk-btn" data-magicauth-pk-remove-all-cancel><?php echo esc_html( $strings['M17'] ); ?></button>
					<button type="button" class="magicauth-pk-btn magicauth-pk-btn--danger" data-magicauth-pk-remove-all-confirm><?php echo esc_html( $strings['A2'] ); ?></button>
				</div>
			</div>
		</dialog>
	<?php endif; ?>
	<?php if ( 'manage' === $mode && ! $dialogs ) : ?>
		<dialog class="magicauth-pk-dialog" id="<?php echo esc_attr( 'magicauth-pk-reauth-dialog-' . (int) $instance ); ?>" data-magicauth-pk-reauth-dialog data-magicauth-pk-render="<?php echo esc_attr( $render ); ?>" aria-labelledby="<?php echo esc_attr( 'magicauth-pk-reauth-title-' . (int) $instance ); ?>">
			<div class="magicauth-pk-dialog__inner">
				<div data-magicauth-pk-view="reauth" hidden>
					<?php $magicauth_pk_reauth( false ); ?>
				</div>
			</div>
		</dialog>
	<?php endif; ?>
	<?php
};

if ( 'dialogs' === $part ) {
	$magicauth_pk_dialogs();
	return;
}
?>
<section class="magicauth-pk-manage" data-magicauth-pk-manage data-magicauth-pk-mode="<?php echo esc_attr( 'manage' === $mode ? 'manage' : 'admin' ); ?>" data-magicauth-pk-user="<?php echo esc_attr( (string) (int) $user_id ); ?>" data-magicauth-pk-render="<?php echo esc_attr( $render ); ?>"<?php echo $dialogs ? '' : ' data-magicauth-pk-dialogs="' . esc_attr( implode( ' ', $magicauth_pk_dialog_ids ) ) . '"'; ?><?php echo '' !== $admin_nonce ? ' data-magicauth-pk-admin-nonce="' . esc_attr( $admin_nonce ) . '"' : ''; ?> aria-labelledby="<?php echo esc_attr( $title_id ); ?>">
	<<?php echo esc_html( $heading_tag ); ?> id="<?php echo esc_attr( $title_id ); ?>" class="magicauth-pk-manage__title" tabindex="-1" data-magicauth-pk-title><?php echo esc_html( $strings['M1'] ); ?></<?php echo esc_html( $heading_tag ); ?>>
	<?php if ( $own && ! $module_off ) : ?>
		<p class="magicauth-pk-intro"><?php echo esc_html( $strings['M2'] ); ?></p>
	<?php endif; ?>
	<?php if ( $module_off ) : ?>
		<p class="magicauth-pk-notice"><?php echo esc_html( $strings['A8'] ); ?></p>
	<?php endif; ?>
	<?php if ( $list_error ) : ?>
		<p class="magicauth-pk-notice magicauth-pk-notice--error"><?php echo esc_html( $strings['MX'] ); ?></p>
	<?php endif; ?>
	<p class="magicauth-pk-empty" data-magicauth-pk-empty<?php echo ( [] !== $items || $list_error ) ? ' hidden' : ''; ?>><?php echo esc_html( $own ? $strings['M3'] : $strings['A5'] ); ?></p>
	<ul class="magicauth-pk-list" data-magicauth-pk-list>
		<?php
		foreach ( $items as $item ) {
			$magicauth_pk_item( $item );
		}
		?>
	</ul>
	<?php if ( $can_add ) : ?>
		<div class="magicauth-pk-actions">
			<button type="button" class="magicauth-pk-btn magicauth-pk-btn--primary" data-magicauth-pk-add hidden><?php echo esc_html( $strings['M4'] ); ?></button>
		</div>
		<p class="magicauth-pk-note" data-magicauth-pk-nocreate hidden><?php echo esc_html( $strings['M27'] ); ?></p>
		<p class="magicauth-pk-warning"><?php echo esc_html( $strings['M5'] ); ?></p>
		<?php if ( $dialogs ) : ?>
			<div class="magicauth-pk-reauth" data-magicauth-pk-view="reauth" hidden>
				<?php $magicauth_pk_reauth( true ); ?>
			</div>
		<?php endif; ?>
	<?php endif; ?>
	<?php if ( $can_signout_others ) : ?>
		<div class="magicauth-pk-actions">
			<button type="button" class="magicauth-pk-btn" data-magicauth-pk-signout-others hidden><?php echo esc_html( $strings['M32'] ); ?></button>
		</div>
	<?php endif; ?>
	<?php if ( $can_remove_all ) : ?>
		<div class="magicauth-pk-actions">
			<button type="button" class="magicauth-pk-btn magicauth-pk-btn--danger" data-magicauth-pk-remove-all hidden><?php echo esc_html( $strings['A2'] ); ?></button>
		</div>
	<?php endif; ?>
	<noscript><p class="magicauth-pk-notice"><?php echo esc_html( $strings['M26'] ); ?></p></noscript>
	<p class="magicauth-pk-sr-only" data-magicauth-pk-status role="status"></p>
	<p class="magicauth-pk-alert" data-magicauth-pk-alert role="alert"></p>
	<?php
	if ( $dialogs ) {
		$magicauth_pk_dialogs();
	}
	?>
</section>
