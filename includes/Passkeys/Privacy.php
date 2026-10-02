<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Passkeys;

defined( 'ABSPATH' ) || exit;

use WP_Error;
use WP_Session_Tokens;
use WP_User;

/**
 * Personal data exporter and eraser for passkeys (SPEC 12.2), registered as
 * `magicauth-passkeys` next to the login-activity entry whatever the module
 * toggle says: data may exist from an earlier "on" period.
 *
 * Export follows the per-user read rule (7.6 rule X): rows of a former holder
 * of a reused user ID are not this person's data and are not exported; the
 * eraser deletes by user ID, so they go too. A failed query is a WP_Error
 * (core reports it and the request can be retried), never a silently short
 * export or a "nothing to erase" (D-32). Without the passkey tables (schema
 * never created) no rows can exist: only the user meta is exported or erased,
 * so a missing table never aborts every privacy request of the site.
 *
 * On multisite the eraser keeps magicauth_email_changed_at (reported as
 * retained): it is network-wide and the rule M backstop (7.6) needs it while
 * another site's table may hold rows created before the change. It goes with
 * the user (wpmu_delete_user).
 */
final class Privacy {

	public const KEY = 'magicauth-passkeys';

	private const GROUP = 'magicauth_passkeys';

	/** Rule M change time (7.6), kept by the eraser on multisite. */
	private const CHANGED_META = 'magicauth_email_changed_at';

	/** User meta erased with the passkeys (12.2), in export order. */
	private const META = [
		Prompt::META,
		'magicauth_email_verified_at',
		self::CHANGED_META,
		Signals::DETAILS_META,
		CredentialStore::HANDLE_META,
	];

	/** magicauth_db_version that created the passkey tables (5.4). */
	private const PASSKEY_SCHEMA = 2;

	/** Core session keys of the creation stamp (3.2); never rewritten here. */
	private const STAMP_KEYS = [ 'magicauth_method', 'magicauth_auth_at', 'magicauth_fresh_hash' ];

	/**
	 * Exporter callback: one item per credential, one for the user handle,
	 * one for the passkey settings meta and one per live session state row.
	 * The public key is not exported. done is true: a user holds at most 25
	 * credentials (Module::max_per_user() cap).
	 *
	 * @param string $email_address Address of the request.
	 * @param int    $page          Unused, one page.
	 * @return array{data:array<int,array<string,mixed>>,done:bool}|WP_Error
	 */
	public static function export( string $email_address, int $page = 1 ) {
		unset( $page );
		$user = get_user_by( 'email', $email_address );
		if ( ! $user instanceof WP_User ) {
			return [
				'data' => [],
				'done' => true,
			];
		}
		$uid = (int) $user->ID;

		// No passkey tables (schema never created, 5.4): no rows can exist.
		$tables   = self::has_tables();
		$rows     = $tables ? CredentialStore::for_user( $user, '', true ) : [];
		$sessions = $tables ? self::live_state_rows( $uid ) : [];
		if ( null === $rows || null === $sessions ) {
			return self::db_error();
		}

		$data = [];
		foreach ( $rows as $row ) {
			$data[] = self::item( 'magicauth-passkey-' . (int) $row->id, self::credential_fields( $row ) );
		}

		$handle = CredentialStore::user_handle( $uid, false );
		if ( null !== $handle ) {
			$data[] = self::item(
				'magicauth-passkey-user-handle',
				[
					[ __( 'Passkey user handle', 'magicauth' ), $handle ],
				]
			);
		}

		if ( self::has_settings_meta( $uid ) ) {
			$cadence = Prompt::cadence( $uid );
			$data[]  = self::item(
				'magicauth-passkey-settings',
				[
					[ __( 'Prompt declines', 'magicauth' ), (string) $cadence['declines'] ],
					[ __( 'Next prompt (UTC)', 'magicauth' ), self::meta_time( $cadence['next_at'] ) ],
					[ __( 'Email last verified (UTC)', 'magicauth' ), self::meta_time( get_user_meta( $uid, 'magicauth_email_verified_at', true ) ) ],
					[ __( 'Email changed (UTC)', 'magicauth' ), self::meta_time( get_user_meta( $uid, 'magicauth_email_changed_at', true ) ) ],
					[ __( 'Account details changed (UTC)', 'magicauth' ), self::meta_time( get_user_meta( $uid, Signals::DETAILS_META, true ) ) ],
				]
			);
		}

		foreach ( $sessions as $n => $session ) {
			$data[] = self::item(
				'magicauth-passkey-session-' . ( $n + 1 ),
				[
					[ __( 'Step-up time (UTC)', 'magicauth' ), self::meta_time( $session->reauth_at ?? 0 ) ],
					[ __( 'Step-up method', 'magicauth' ), self::reauth_method( (string) ( $session->reauth_method ?? '' ) ) ],
				]
			);
		}

		return [
			'data' => $data,
			'done' => true,
		];
	}

	/**
	 * Eraser callback: every credential row of the user ID (snapshot or not),
	 * challenge rows, session state rows and the passkey user meta (on
	 * multisite without the email change time, see the class doc). The
	 * creation stamp in core's session records stays until the sessions end
	 * (rewriting session_tokens would race with live sign-ins, 3.2); that is
	 * reported as retained.
	 *
	 * @param string $email_address Address of the request.
	 * @param int    $page          Unused, one page.
	 * @return array{items_removed:bool,items_retained:bool,messages:array<int,string>,done:bool}|WP_Error
	 */
	public static function erase( string $email_address, int $page = 1 ) {
		unset( $page );
		$user = get_user_by( 'email', $email_address );
		if ( ! $user instanceof WP_User ) {
			return [
				'items_removed'  => false,
				'items_retained' => false,
				'messages'       => [],
				'done'           => true,
			];
		}
		$uid = (int) $user->ID;

		$credentials = 0;
		$challenges  = 0;
		$states      = 0;
		// No passkey tables (schema never created, 5.4): only the meta can exist.
		if ( self::has_tables() ) {
			$credentials = CredentialStore::delete_all_for_user( $uid );
			if ( $credentials instanceof WP_Error ) {
				return self::db_error();
			}
			// Both return 0 on a failed query; the query's error is still on $wpdb.
			$challenges = ChallengeStore::delete_for_user( $uid );
			if ( self::last_query_failed() ) {
				return self::db_error();
			}
			$states = SessionState::delete_for_user( $uid );
			if ( self::last_query_failed() ) {
				return self::db_error();
			}
		}

		// Another site's table may still hold rows created before the email
		// change; only this network-wide time keeps them revoked (7.6).
		$keep_changed = is_multisite() && CredentialStore::email_changed_at( $uid ) > 0;
		$meta         = 0;
		foreach ( self::META as $key ) {
			if ( $keep_changed && self::CHANGED_META === $key ) {
				continue;
			}
			if ( delete_user_meta( $uid, $key ) ) {
				++$meta;
			}
		}

		$stamped  = self::has_stamped_session( $uid );
		$retained = $stamped || $keep_changed;
		$messages = [];
		if ( $stamped ) {
			$messages[] = __( 'The sign-in method and time stay in your active sessions until they end.', 'magicauth' );
		}
		if ( $keep_changed ) {
			$messages[] = __( 'The time of your last email address change is kept, so passkeys created before it stay blocked on the other sites of this network.', 'magicauth' );
		}
		if ( $credentials > 0 ) {
			$messages[] = __( 'Passkeys saved in your browser or password manager are not removed by this site. Delete them there.', 'magicauth' );
		}

		return [
			'items_removed'  => $credentials + $challenges + $states + $meta > 0,
			'items_retained' => $retained,
			'messages'       => $messages,
			'done'           => true,
		];
	}

	/**
	 * Fields of one credential row, without the public key.
	 *
	 * @param object $row Credential row.
	 * @return array<int,array{0:string,1:string}>
	 */
	private static function credential_fields( object $row ): array {
		$be       = ! empty( $row->backup_eligible );
		$bs       = ! empty( $row->backup_state );
		$aaguid   = (string) ( $row->aaguid ?? '' );
		$provider = Aaguids::name( $aaguid );
		if ( $bs ) {
			$sync = __( 'Synced across your devices', 'magicauth' );
		} elseif ( $be ) {
			$sync = __( 'Can be synced, not synced yet', 'magicauth' );
		} else {
			$sync = __( 'This device only', 'magicauth' );
		}

		/* translators: %s: last 4 characters of the passkey's identifier, for example 9F3A. */
		$label = sprintf( __( 'Passkey ending in %s', 'magicauth' ), strtoupper( substr( (string) ( $row->credential_hash ?? '' ), -4 ) ) );

		return [
			[ __( 'Name', 'magicauth' ), (string) ( $row->name ?? '' ) ],
			[ __( 'Label', 'magicauth' ), $label ],
			[ __( 'Provider', 'magicauth' ), null !== $provider ? $provider : $aaguid ],
			[ __( 'Sync state', 'magicauth' ), $sync ],
			[ __( 'Backup eligible', 'magicauth' ), self::yes_no( $be ) ],
			[ __( 'Backup state', 'magicauth' ), self::yes_no( $bs ) ],
			[ __( 'Signature counter', 'magicauth' ), (string) (int) ( $row->sign_count ?? 0 ) ],
			[ __( 'Transports', 'magicauth' ), (string) ( $row->transports ?? '' ) ],
			[ __( 'Added (UTC)', 'magicauth' ), (string) ( $row->created_at ?? '' ) ],
			[ __( 'Last used (UTC)', 'magicauth' ), (string) ( $row->last_used_at ?? '' ) ],
			[ __( 'Possible copy detected (UTC)', 'magicauth' ), (string) ( $row->counter_anomaly_at ?? '' ) ],
			[ __( 'Site address', 'magicauth' ), (string) ( $row->rp_id ?? '' ) ],
			[ __( 'Credential ID', 'magicauth' ), (string) ( $row->credential_id ?? '' ) ],
		];
	}

	/**
	 * One export item of the passkeys group.
	 *
	 * @param string                              $item_id Item ID.
	 * @param array<int,array{0:string,1:string}> $fields  Name and value pairs.
	 * @return array<string,mixed>
	 */
	private static function item( string $item_id, array $fields ): array {
		$data = [];
		foreach ( $fields as $field ) {
			$data[] = [
				'name'  => $field[0],
				'value' => $field[1],
			];
		}
		return [
			'group_id'    => self::GROUP,
			'group_label' => __( 'Passkeys', 'magicauth' ),
			'item_id'     => $item_id,
			'data'        => $data,
		];
	}

	/**
	 * Session state rows of the user whose session has not expired.
	 *
	 * @param int $uid User ID.
	 * @return array<int,object>|null Null on a failed query.
	 */
	private static function live_state_rows( int $uid ): ?array {
		global $wpdb;

		$table = SessionState::table();
		$prev  = $wpdb->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table name from $wpdb->prefix.
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT reauth_at, reauth_method FROM {$table} WHERE user_id = %d AND expires_at > %s ORDER BY expires_at ASC", $uid, gmdate( 'Y-m-d H:i:s', Clock::now() ) ) );
			if ( '' !== $wpdb->last_error ) {
				return null;
			}
		} finally {
			$wpdb->suppress_errors( $prev );
		}
		return array_values( array_filter( (array) $rows, 'is_object' ) );
	}

	/**
	 * Whether any of the settings meta (all but the handle) is stored.
	 *
	 * @param int $uid User ID.
	 */
	private static function has_settings_meta( int $uid ): bool {
		foreach ( self::META as $key ) {
			if ( CredentialStore::HANDLE_META !== $key && [] !== (array) get_user_meta( $uid, $key, false ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether a live core session of the user carries the creation stamp.
	 *
	 * @param int $uid User ID.
	 */
	private static function has_stamped_session( int $uid ): bool {
		if ( ! class_exists( 'WP_Session_Tokens' ) ) {
			return false;
		}
		foreach ( WP_Session_Tokens::get_instance( $uid )->get_all() as $session ) {
			if ( ! is_array( $session ) || (int) ( $session['expiration'] ?? 0 ) < Clock::now() ) {
				continue;
			}
			foreach ( self::STAMP_KEYS as $key ) {
				if ( array_key_exists( $key, $session ) ) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * A stored Unix time as UTC text; '' for none or a malformed value.
	 *
	 * @param mixed $value Meta or column value.
	 */
	private static function meta_time( $value ): string {
		if ( ! is_numeric( $value ) || (int) $value <= 0 ) {
			return '';
		}
		return gmdate( 'Y-m-d H:i:s', (int) $value );
	}

	/**
	 * Step-up method as the person reads it.
	 *
	 * @param string $method email_code | passkey.
	 */
	private static function reauth_method( string $method ): string {
		if ( 'email_code' === $method ) {
			return __( 'Code from your email', 'magicauth' );
		}
		if ( 'passkey' === $method ) {
			return __( 'Passkey', 'magicauth' );
		}
		return '';
	}

	/**
	 * Yes or No.
	 *
	 * @param bool $value Flag.
	 */
	private static function yes_no( bool $value ): string {
		return $value ? __( 'Yes', 'magicauth' ) : __( 'No', 'magicauth' );
	}

	/**
	 * Whether the last $wpdb query failed (wpdb clears last_error when a query starts).
	 *
	 * @phpstan-impure
	 */
	/** Whether the passkey tables were created (a failed schema check never bumps the version, 5.4). */
	private static function has_tables(): bool {
		return (int) get_option( 'magicauth_db_version', 0 ) >= self::PASSKEY_SCHEMA;
	}

	/**
	 * Whether the last query failed ($wpdb->last_error).
	 *
	 * @phpstan-impure
	 */
	private static function last_query_failed(): bool {
		global $wpdb;
		return '' !== $wpdb->last_error;
	}

	/** A failed query: core reports the error and the request can be retried. */
	private static function db_error(): WP_Error {
		return new WP_Error( 'magicauth_db_error', __( 'The passkey data could not be read or removed. Please try again.', 'magicauth' ) );
	}
}
