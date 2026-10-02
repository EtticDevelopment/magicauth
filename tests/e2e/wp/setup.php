<?php
/**
 * E2E site setup (SPEC 14.2 blueprint), run once by the blueprint's runPHP step
 * after MagicAuth is activated: users, pages, settings with passkeys on.
 * Idempotent. Test-only; never shipped.
 *
 * @package MagicAuth\Tests
 */

require_once '/wordpress/wp-load.php';

$magicauth_e2e_users = [
	'student-a' => [ 'Student A', 'subscriber' ],
	'student-b' => [ 'Student B', 'subscriber' ],
	'editor'    => [ 'Editor', 'editor' ],
];
foreach ( $magicauth_e2e_users as $login => [ $name, $role ] ) {
	if ( ! username_exists( $login ) ) {
		wp_insert_user(
			[
				'user_login'   => $login,
				'user_pass'    => 'password',
				'user_email'   => $login . '@example.com',
				'display_name' => $name,
				'role'         => $role,
			]
		);
	}
}
$admin = get_user_by( 'login', 'admin' );
if ( $admin ) {
	wp_update_user(
		[
			'ID'         => $admin->ID,
			'user_email' => 'admin@example.com',
			'user_pass'  => 'password',
		]
	);
}

/** Create a published page once; returns its ID. */
function magicauth_e2e_page( string $slug, string $title, string $content, int $parent = 0 ): int {
	$existing = get_page_by_path( $parent ? get_post_field( 'post_name', $parent ) . '/' . $slug : $slug );
	if ( $existing ) {
		return (int) $existing->ID;
	}
	return (int) wp_insert_post(
		[
			'post_type'    => 'page',
			'post_status'  => 'publish',
			'post_name'    => $slug,
			'post_title'   => $title,
			'post_content' => $content,
			'post_parent'  => $parent,
		]
	);
}

magicauth_e2e_page( 'login', 'Sign in', '<!-- wp:shortcode -->[magicauth_login]<!-- /wp:shortcode -->' );
$magicauth_e2e_account = magicauth_e2e_page( 'account', 'Account', '<!-- wp:shortcode -->[magicauth_passkeys]<!-- /wp:shortcode -->' );
$magicauth_e2e_deep    = magicauth_e2e_page( 'deep', 'Deep', '<!-- wp:paragraph --><p>Section index.</p><!-- /wp:paragraph -->' );
magicauth_e2e_page(
	'link',
	'Deep link',
	'<!-- wp:paragraph --><p data-e2e-private>Deep link content for members.</p><!-- /wp:paragraph -->'
	. '<!-- wp:spacer {"height":"1600px"} --><div style="height:1600px" aria-hidden="true" class="wp-block-spacer"></div><!-- /wp:spacer -->'
	. '<!-- wp:heading --><h2 class="wp-block-heading" id="part-2">Part 2</h2><!-- /wp:heading -->',
	$magicauth_e2e_deep
);
magicauth_e2e_page( 'wall', 'Wall', '<!-- wp:paragraph --><p>Wall placeholder.</p><!-- /wp:paragraph -->' );
magicauth_e2e_page( 'account-tpl', 'Account template', '' );
magicauth_e2e_page( 'terms', 'Terms', '<!-- wp:paragraph --><p data-e2e-terms>Accept the terms to continue.</p><!-- /wp:paragraph -->' );

update_option( 'permalink_structure', '/%postname%/' );
flush_rewrite_rules();

$magicauth_e2e_settings = get_option( 'magicauth_settings', [] );
$magicauth_e2e_settings = is_array( $magicauth_e2e_settings ) ? $magicauth_e2e_settings : [];
$magicauth_e2e_settings = array_merge(
	$magicauth_e2e_settings,
	[
		'passkeys_enabled'        => true,
		'passkeys_prompt'         => true,
		'passkeys_manage_page_id' => $magicauth_e2e_account,
	]
);
update_option( 'magicauth_settings', $magicauth_e2e_settings );
update_option( 'magicauth_e2e_flags', [] );
update_option( 'magicauth_e2e_setup', time() );

echo 'magicauth-e2e setup done';
