<?php
/**
 * MagicAuth uninstall handler.
 *
 * Unless MAGICAUTH_KEEP_DATA is defined: drops the requests and passkey
 * tables and removes the plugin's options, user meta, transients and cron
 * event, on every site of a multisite network. WordPress runs this file
 * without loading the plugin, so it uses core functions only.
 *
 * @package MagicAuth
 */

declare( strict_types=1 );

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

if ( defined( 'MAGICAUTH_KEEP_DATA' ) && MAGICAUTH_KEEP_DATA ) {
	return;
}

global $wpdb;

// Per site: tables, options, transients and the cron event. On multisite
// every site of the network (core runs this file in the main site's context
// only), each under its own prefix; user meta is network-wide, one pass below.
$magicauth_sites = is_multisite() ? get_sites(
	[
		'fields' => 'ids',
		'number' => 0,
	]
) : [ 0 ];
foreach ( (array) $magicauth_sites as $magicauth_site ) {
	$magicauth_site_id = is_object( $magicauth_site ) ? (int) $magicauth_site->blog_id : (int) $magicauth_site;
	$magicauth_switch  = is_multisite() && $magicauth_site_id > 0;
	if ( $magicauth_switch ) {
		switch_to_blog( $magicauth_site_id );
	}

	$magicauth_tables = [
		'magicauth_requests',
		'magicauth_passkeys',
		'magicauth_passkey_challenges',
		'magicauth_passkey_sessions',
	];
	foreach ( $magicauth_tables as $magicauth_table ) {
		$magicauth_table = $wpdb->prefix . $magicauth_table;
		$wpdb->query( "DROP TABLE IF EXISTS {$magicauth_table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.NoCaching
	}

	$magicauth_options = [
		'magicauth_settings',
		'magicauth_db_version',
		'magicauth_upgrade_lock',
		'magicauth_upgrade_retry',
		'magicauth_throttle_registry',
		'magicauth_salt_notice_dismissed',
	];
	foreach ( $magicauth_options as $magicauth_option ) {
		delete_option( $magicauth_option );
	}

	// Transient value and timeout rows, one statement. esc_like() escapes with a
	// backslash, MySQL's default LIKE escape character, as core relies on. No
	// explicit ESCAPE: the WordPress SQLite driver appends its own to every LIKE,
	// so a second one is a syntax error there.
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
			$wpdb->esc_like( '_transient_magicauth_' ) . '%',
			$wpdb->esc_like( '_transient_timeout_magicauth_' ) . '%'
		)
	);

	wp_clear_scheduled_hook( 'magicauth_daily_cleanup' );

	if ( $magicauth_switch ) {
		restore_current_blog();
	}
}

// All users.
$magicauth_meta_keys = [
	'magicauth_disabled',
	'magicauth_passkey_user_handle',
	'magicauth_passkey_prompt',
	'magicauth_passkey_details_at',
	'magicauth_passkey_details_sent',
	'magicauth_email_verified_at',
	'magicauth_email_changed_at',
];
foreach ( $magicauth_meta_keys as $magicauth_meta_key ) {
	delete_metadata( 'user', 0, $magicauth_meta_key, '', true );
}
