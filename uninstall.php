<?php
/**
 * MagicAuth uninstall handler.
 *
 * Drops the requests table and removes options unless MAGICAUTH_KEEP_DATA is defined.
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

$table = $wpdb->prefix . 'magicauth_requests';
$wpdb->query( "DROP TABLE IF EXISTS {$table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.DirectDatabaseQuery.NoCaching

delete_option( 'magicauth_settings' );
delete_option( 'magicauth_db_version' );
delete_metadata( 'user', 0, 'magicauth_disabled', '', true );

wp_clear_scheduled_hook( 'magicauth_daily_cleanup' );
