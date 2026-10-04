<?php
/**
 * T-PRIV (SPEC 12.2, 14.1, build step 15): the passkeys exporter and eraser.
 * Export carries every 12.2 field, the settings item with each meta key, the
 * user handle and the live session state rows, never the public key, and
 * only rows of the user's user_registered snapshot. Erase removes credential
 * rows (snapshot or not), challenge rows, session state rows and the five
 * meta keys, reports a live stamped session as retained, and both answer a
 * failed query with a WP_Error. Both are registered next to the
 * login-activity entries.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Passkeys\ChallengeStore;
use MagicAuth\Passkeys\Clock;
use MagicAuth\Passkeys\CredentialStore;
use MagicAuth\Passkeys\Freshness;
use MagicAuth\Passkeys\Privacy;
use MagicAuth\Passkeys\SessionState;
use MagicAuth\Plugin;
use MagicAuth\Tests\Support\Ceremony;
use MagicAuth\Tests\Support\SoftAuthenticator;
use PHPUnit\Framework\TestCase;
use WP_Error;
use WP_User;

final class PrivacyTest extends TestCase {

	private const CREDENTIAL_FIELDS = [
		'Name',
		'Label',
		'Provider',
		'Sync state',
		'Backup eligible',
		'Backup state',
		'Signature counter',
		'Transports',
		'Added (UTC)',
		'Last used (UTC)',
		'Possible copy detected (UTC)',
		'Site address',
		'Credential ID',
	];

	private const SETTINGS_FIELDS = [
		'Prompt declines',
		'Next prompt (UTC)',
		'Email last verified (UTC)',
		'Email changed (UTC)',
		'Account details changed (UTC)',
	];

	private const META = [
		'magicauth_passkey_user_handle',
		'magicauth_passkey_prompt',
		'magicauth_passkey_details_at',
		'magicauth_passkey_details_sent',
		'magicauth_email_verified_at',
		'magicauth_email_changed_at',
	];

	private const BROWSER_MESSAGE = 'Passkeys saved in your browser or password manager are not removed by this site. Delete them there.';

	private const RETAINED_MESSAGE = 'The sign-in method and time stay in your active sessions until they end.';

	private WP_User $user;

	private WP_User $other;

	protected function setUp(): void {
		Ceremony::site();
		$this->user  = Ceremony::user( 7 );
		$this->other = Ceremony::user( 8 );
	}

	protected function tearDown(): void {
		global $wpdb;
		$_COOKIE = [];
		$wpdb->show_errors( false );
		magicauth_test_reset_state();
	}

	/* ------------------------------------------------------------- helpers */

	private static function enrol( WP_User $user ): int {
		return Ceremony::enrol( new SoftAuthenticator( 'ES256' ), $user );
	}

	private static function count_rows( string $table, int $uid ): int {
		global $wpdb;
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE user_id = %d", $uid ) );
	}

	/** @param array<string,mixed> $fields */
	private static function update_row( int $id, array $fields ): void {
		global $wpdb;
		foreach ( $fields as $column => $value ) {
			$wpdb->query( $wpdb->prepare( 'UPDATE ' . CredentialStore::table() . " SET {$column} = %s WHERE id = %d", (string) $value, $id ) );
		}
	}

	/** A stamped session of $user with a step-up and a state row; returns the session hash. */
	private static function stepped_up_session( WP_User $user, string $method = 'email_code' ): string {
		Ceremony::sign_in( $user, 'link', Ceremony::NOW - 60 );
		self::assertTrue( SessionState::stamp_reauth( $method ) );
		return Freshness::session_hash();
	}

	/**
	 * @param array<string,mixed> $item
	 * @return array<string,string> Field name => value.
	 */
	private static function fields( array $item ): array {
		$out = [];
		foreach ( $item['data'] as $pair ) {
			$out[ $pair['name'] ] = $pair['value'];
		}
		return $out;
	}

	/**
	 * @param array<string,mixed> $export
	 * @return array<string,array<string,mixed>> item_id => item.
	 */
	private static function items( array $export ): array {
		$out = [];
		foreach ( $export['data'] as $item ) {
			$out[ $item['item_id'] ] = $item;
		}
		return $out;
	}

	/** @return array<string,mixed> */
	private function export(): array {
		$export = Privacy::export( 'learner7@example.test' );
		$this->assertIsArray( $export );
		$this->assertTrue( $export['done'] );
		return $export;
	}

	/** @return array<string,mixed> */
	private function erase(): array {
		$result = Privacy::erase( 'learner7@example.test' );
		$this->assertIsArray( $result );
		$this->assertSame( [ 'items_removed', 'items_retained', 'messages', 'done' ], array_keys( $result ) );
		$this->assertTrue( $result['done'] );
		return $result;
	}

	/* -------------------------------------------------------------- export */

	public function test_export_unknown_email(): void {
		$this->assertSame(
			[
				'data' => [],
				'done' => true,
			],
			Privacy::export( 'nobody@example.test' )
		);
	}

	public function test_export_user_without_passkey_data_is_empty(): void {
		self::enrol( $this->other );
		$this->assertSame( [], $this->export()['data'] );
	}

	public function test_export_carries_every_field(): void {
		$first  = self::enrol( $this->user );
		$second = self::enrol( $this->user );
		self::enrol( $this->other );
		self::update_row(
			$second,
			[
				'aaguid'             => 'bada5566-a7aa-401f-bd96-45619a55120d',
				'backup_eligible'    => 0,
				'backup_state'       => 0,
				'sign_count'         => 42,
				'transports'         => 'internal,usb',
				'last_used_at'       => '2026-09-21 10:00:00',
				'counter_anomaly_at' => '2026-09-21 11:00:00',
				'name'               => 'Work laptop',
			]
		);
		self::update_row(
			$first,
			[
				'backup_eligible' => 1,
				'backup_state'    => 0,
			]
		);
		update_user_meta( 7, 'magicauth_passkey_prompt', [ 'declines' => 2, 'next_at' => Ceremony::NOW + 86400 ] );
		update_user_meta( 7, 'magicauth_email_verified_at', Ceremony::NOW - 100 );
		update_user_meta( 7, 'magicauth_email_changed_at', Ceremony::NOW - 200 );
		update_user_meta( 7, 'magicauth_passkey_details_at', Ceremony::NOW - 300 );
		self::stepped_up_session( $this->user, 'email_code' );
		self::stepped_up_session( $this->user, 'passkey' );

		$export = $this->export();
		$items  = self::items( $export );
		$ids    = array_keys( $items );
		$this->assertSame(
			[
				'magicauth-passkey-' . $first,
				'magicauth-passkey-' . $second,
				'magicauth-passkey-user-handle',
				'magicauth-passkey-settings',
				'magicauth-passkey-session-1',
				'magicauth-passkey-session-2',
			],
			$ids
		);
		foreach ( $items as $item ) {
			$this->assertSame( 'magicauth_passkeys', $item['group_id'] );
			$this->assertSame( 'Passkeys', $item['group_label'] );
			foreach ( $item['data'] as $pair ) {
				$this->assertIsString( $pair['name'] );
				$this->assertIsString( $pair['value'] );
			}
		}

		// Credential rows: every 12.2 field, in order.
		$row  = Ceremony::row( $first );
		$one  = self::fields( $items[ 'magicauth-passkey-' . $first ] );
		$this->assertSame( self::CREDENTIAL_FIELDS, array_keys( $one ) );
		$this->assertSame( $row['name'], $one['Name'] );
		$this->assertSame( 'Passkey ending in ' . strtoupper( substr( $row['credential_hash'], -4 ) ), $one['Label'] );
		$this->assertSame( $row['aaguid'], $one['Provider'], 'unknown provider: the AAGUID' );
		$this->assertSame( 'Can be synced, not synced yet', $one['Sync state'] );
		$this->assertSame( 'Yes', $one['Backup eligible'] );
		$this->assertSame( 'No', $one['Backup state'] );
		$this->assertSame( '0', $one['Signature counter'] );
		$this->assertSame( $row['transports'], $one['Transports'] );
		$this->assertSame( $row['created_at'], $one['Added (UTC)'] );
		$this->assertSame( '', $one['Last used (UTC)'] );
		$this->assertSame( '', $one['Possible copy detected (UTC)'] );
		$this->assertSame( Ceremony::RP, $one['Site address'] );
		$this->assertSame( $row['credential_id'], $one['Credential ID'] );

		$two = self::fields( $items[ 'magicauth-passkey-' . $second ] );
		$this->assertSame( 'Work laptop', $two['Name'] );
		$this->assertSame( '1Password', $two['Provider'] );
		$this->assertSame( 'This device only', $two['Sync state'] );
		$this->assertSame( 'No', $two['Backup eligible'] );
		$this->assertSame( '42', $two['Signature counter'] );
		$this->assertSame( 'internal,usb', $two['Transports'] );
		$this->assertSame( '2026-09-21 10:00:00', $two['Last used (UTC)'] );
		$this->assertSame( '2026-09-21 11:00:00', $two['Possible copy detected (UTC)'] );

		// User handle.
		$this->assertSame(
			[ 'Passkey user handle' => CredentialStore::user_handle( 7, false ) ],
			self::fields( $items['magicauth-passkey-user-handle'] )
		);

		// Settings item: each meta key.
		$this->assertSame(
			[
				'Prompt declines'               => '2',
				'Next prompt (UTC)'             => gmdate( 'Y-m-d H:i:s', Ceremony::NOW + 86400 ),
				'Email last verified (UTC)'     => gmdate( 'Y-m-d H:i:s', Ceremony::NOW - 100 ),
				'Email changed (UTC)'           => gmdate( 'Y-m-d H:i:s', Ceremony::NOW - 200 ),
				'Account details changed (UTC)' => gmdate( 'Y-m-d H:i:s', Ceremony::NOW - 300 ),
			],
			self::fields( $items['magicauth-passkey-settings'] )
		);
		$this->assertSame( self::SETTINGS_FIELDS, array_keys( self::fields( $items['magicauth-passkey-settings'] ) ) );

		// One item per live session state row.
		$this->assertSame(
			[
				'Step-up time (UTC)' => gmdate( 'Y-m-d H:i:s', Ceremony::NOW ),
				'Step-up method'     => 'Code from your email',
			],
			self::fields( $items['magicauth-passkey-session-1'] )
		);
		$this->assertSame( 'Passkey', self::fields( $items['magicauth-passkey-session-2'] )['Step-up method'] );
	}

	public function test_export_never_contains_the_public_key_or_another_users_data(): void {
		$id = self::enrol( $this->user );
		self::enrol( $this->other );
		$export = (string) wp_json_encode( $this->export() );
		$row    = Ceremony::row( $id );

		$this->assertStringNotContainsString( 'Public key', $export );
		$key = trim( str_replace( [ '-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----', "\n" ], '', $row['public_key'] ) );
		$this->assertNotSame( '', $key );
		foreach ( str_split( $key, 32 ) as $chunk ) {
			$this->assertStringNotContainsString( $chunk, $export, 'no part of the public key' );
			$this->assertStringNotContainsString( str_replace( '/', '\\/', $chunk ), $export );
		}
		$this->assertStringNotContainsString( (string) CredentialStore::user_handle( 8, false ), $export );
		$this->assertStringNotContainsString( 'learner8', $export );
	}

	public function test_export_skips_a_former_holders_rows(): void {
		// A row left by a former holder of user ID 7 (another user_registered).
		$this->user->user_registered = '2025-01-01 10:00:00';
		$old                         = self::enrol( $this->user );
		$this->user->user_registered = Ceremony::REGISTERED;
		$mine                        = self::enrol( $this->user );

		$ids = array_keys( self::items( $this->export() ) );
		$this->assertContains( 'magicauth-passkey-' . $mine, $ids );
		$this->assertNotContains( 'magicauth-passkey-' . $old, $ids );
	}

	public function test_export_settings_item_only_with_settings_meta(): void {
		self::enrol( $this->user );
		$ids = array_keys( self::items( $this->export() ) );
		$this->assertNotContains( 'magicauth-passkey-settings', $ids, 'the handle alone is its own item' );
		$this->assertContains( 'magicauth-passkey-user-handle', $ids );
		update_user_meta( 7, 'magicauth_passkey_details_sent', str_repeat( 'a', 64 ) );
		$this->assertNotContains( 'magicauth-passkey-settings', array_keys( self::items( $this->export() ) ), 'the details record is erased, not exported' );

		foreach ( [ 'magicauth_passkey_prompt', 'magicauth_passkey_details_at', 'magicauth_email_verified_at', 'magicauth_email_changed_at' ] as $key ) {
			magicauth_test_reset_state();
			Ceremony::site();
			Ceremony::user( 7 );
			update_user_meta( 7, $key, 'magicauth_passkey_prompt' === $key ? [ 'declines' => 1, 'next_at' => 0 ] : Ceremony::NOW );
			$items = self::items( $this->export() );
			$this->assertSame( [ 'magicauth-passkey-settings' ], array_keys( $items ), $key );
			$this->assertSame( self::SETTINGS_FIELDS, array_keys( self::fields( $items['magicauth-passkey-settings'] ) ), $key );
		}
	}

	public function test_export_malformed_meta_reads_as_empty(): void {
		update_user_meta( 7, 'magicauth_passkey_prompt', 'garbage' );
		update_user_meta( 7, 'magicauth_email_verified_at', 'soon' );
		update_user_meta( 7, 'magicauth_email_changed_at', -5 );
		$fields = self::fields( self::items( $this->export() )['magicauth-passkey-settings'] );
		$this->assertSame( '0', $fields['Prompt declines'] );
		$this->assertSame( '', $fields['Next prompt (UTC)'] );
		$this->assertSame( '', $fields['Email last verified (UTC)'] );
		$this->assertSame( '', $fields['Email changed (UTC)'] );
	}

	public function test_export_leaves_out_expired_state_rows(): void {
		global $wpdb;
		$hash = self::stepped_up_session( $this->user );
		$wpdb->query( $wpdb->prepare( 'UPDATE ' . SessionState::table() . ' SET expires_at = %s WHERE session_hash = %s', gmdate( 'Y-m-d H:i:s', Ceremony::NOW - 1 ), $hash ) );
		$this->assertSame( [], preg_grep( '/^magicauth-passkey-session-/', array_keys( self::items( $this->export() ) ) ) );
	}

	public function test_export_state_row_without_step_up(): void {
		Ceremony::sign_in( $this->user, 'link' );
		$this->assertTrue( SessionState::set( 'prompt_done', 1 ) );
		$this->assertSame(
			[
				'Step-up time (UTC)' => '',
				'Step-up method'     => '',
			],
			self::fields( self::items( $this->export() )['magicauth-passkey-session-1'] )
		);
	}

	/** @return array<string,array{string}> */
	public static function export_queries(): array {
		return [
			'credentials'   => [ 'SELECT * FROM wp_magicauth_passkeys ' ],
			'session state' => [ 'SELECT reauth_at, reauth_method FROM wp_magicauth_passkey_sessions' ],
		];
	}

	/** @dataProvider export_queries */
	public function test_export_query_error_is_a_wp_error( string $query ): void {
		global $wpdb;
		self::enrol( $this->user );
		self::stepped_up_session( $this->user );
		$wpdb->fail_next_query( $query );

		ob_start();
		$export = Privacy::export( 'learner7@example.test' );
		$this->assertSame( '', (string) ob_get_clean(), 'nothing printed' );
		$this->assertInstanceOf( WP_Error::class, $export );
		$this->assertSame( 'magicauth_db_error', $export->get_error_code() );
		$this->assertNotSame( '', $export->get_error_message() );

		$this->assertCount( 3, $this->export()['data'], 'the next run is complete' );
	}

	/* --------------------------------------------------------------- erase */

	public function test_erase_unknown_email(): void {
		$this->assertSame(
			[
				'items_removed'  => false,
				'items_retained' => false,
				'messages'       => [],
				'done'           => true,
			],
			Privacy::erase( 'nobody@example.test' )
		);
	}

	public function test_erase_user_without_passkey_data(): void {
		self::enrol( $this->other );
		$this->assertSame(
			[
				'items_removed'  => false,
				'items_retained' => false,
				'messages'       => [],
				'done'           => true,
			],
			$this->erase()
		);
		$this->assertSame( 1, self::count_rows( CredentialStore::table(), 8 ) );
	}

	public function test_erase_removes_rows_state_rows_and_meta(): void {
		self::enrol( $this->user );
		$this->user->user_registered = '2025-01-01 10:00:00';
		self::enrol( $this->user );
		$this->user->user_registered = Ceremony::REGISTERED;
		self::enrol( $this->other );
		ChallengeStore::issue( 'register', 7, Ceremony::SESSION, '', '-7', 420, 'aGFuZGxl' );
		ChallengeStore::issue_code( 7, Ceremony::SESSION );
		ChallengeStore::issue( 'reauth', 8, Ceremony::SESSION, '', '', 420 );
		foreach ( self::META as $key ) {
			if ( 'magicauth_passkey_user_handle' !== $key ) {
				update_user_meta( 7, $key, Ceremony::NOW );
				update_user_meta( 8, $key, Ceremony::NOW );
			}
		}
		self::stepped_up_session( $this->other );
		self::stepped_up_session( $this->user );
		$their_challenges = self::count_rows( ChallengeStore::table(), 8 );
		$this->assertGreaterThan( 0, self::count_rows( ChallengeStore::table(), 7 ) );

		$result = $this->erase();

		$this->assertTrue( $result['items_removed'] );
		$this->assertSame( 0, self::count_rows( CredentialStore::table(), 7 ), 'every row, snapshot or not' );
		$this->assertSame( 0, self::count_rows( ChallengeStore::table(), 7 ) );
		$this->assertSame( 0, self::count_rows( SessionState::table(), 7 ) );
		foreach ( self::META as $key ) {
			$this->assertSame( [], get_user_meta( 7, $key, false ), $key );
			$this->assertNotSame( [], get_user_meta( 8, $key, false ), 'other user keeps ' . $key );
		}
		$this->assertSame( 1, self::count_rows( CredentialStore::table(), 8 ) );
		$this->assertSame( $their_challenges, self::count_rows( ChallengeStore::table(), 8 ) );
		$this->assertSame( 1, self::count_rows( SessionState::table(), 8 ) );

		// The person keeps the account and the stamp in the live session.
		$this->assertTrue( $result['items_retained'] );
		$this->assertSame( [ self::RETAINED_MESSAGE, self::BROWSER_MESSAGE ], $result['messages'] );
		$this->assertNotFalse( get_user_by( 'id', 7 ) );

		// A second run finds nothing to remove but the stamp is still retained.
		$again = $this->erase();
		$this->assertFalse( $again['items_removed'] );
		$this->assertSame( [ self::RETAINED_MESSAGE ], $again['messages'] );
	}

	public function test_erase_never_rewrites_core_session_records(): void {
		global $magicauth_test_state;
		self::enrol( $this->user );
		self::stepped_up_session( $this->user );
		$before = $magicauth_test_state['sessions'][7];
		$this->erase(); // WP_Session_Tokens::update() would throw.
		$this->assertSame( $before, $magicauth_test_state['sessions'][7] );
	}

	public function test_erase_without_live_stamped_sessions_retains_nothing(): void {
		global $magicauth_test_state;
		self::enrol( $this->user );

		// No session.
		$result = $this->erase();
		$this->assertTrue( $result['items_removed'] );
		$this->assertFalse( $result['items_retained'] );
		$this->assertSame( [ self::BROWSER_MESSAGE ], $result['messages'] );

		// An unstamped session (core form, user switching) holds no MagicAuth data.
		self::enrol( $this->user );
		Ceremony::sign_in( $this->user, null );
		$result = $this->erase();
		$this->assertFalse( $result['items_retained'] );
		$this->assertSame( [ self::BROWSER_MESSAGE ], $result['messages'] );

		// A stamped but expired session.
		self::enrol( $this->user );
		Ceremony::sign_in( $this->user, 'code' );
		foreach ( $magicauth_test_state['sessions'][7] as $verifier => $session ) {
			$magicauth_test_state['sessions'][7][ $verifier ]['expiration'] = Ceremony::NOW - 1;
		}
		$result = $this->erase();
		$this->assertFalse( $result['items_retained'] );

		// Another user's stamped session does not count.
		self::enrol( $this->user );
		Ceremony::sign_in( $this->other, 'link' );
		$this->assertFalse( $this->erase()['items_retained'] );
	}

	public function test_erase_password_stamp_is_retained_too(): void {
		Ceremony::sign_in( $this->user, 'password', null, false );
		$result = $this->erase();
		$this->assertFalse( $result['items_removed'] );
		$this->assertTrue( $result['items_retained'] );
		$this->assertSame( [ self::RETAINED_MESSAGE ], $result['messages'] );
	}

	public function test_erase_meta_only_has_no_browser_message(): void {
		update_user_meta( 7, 'magicauth_email_verified_at', Ceremony::NOW );
		$result = $this->erase();
		$this->assertTrue( $result['items_removed'] );
		$this->assertSame( [], $result['messages'] );
		$this->assertSame( '', get_user_meta( 7, 'magicauth_email_verified_at', true ) );
	}

	public function test_erase_challenge_rows_only_count_as_removed(): void {
		ChallengeStore::issue( 'reauth', 7, Ceremony::SESSION, '', '', 420 );
		$result = $this->erase();
		$this->assertTrue( $result['items_removed'] );
		$this->assertSame( [], $result['messages'] );
	}

	/** @return array<string,array{string}> */
	public static function erase_queries(): array {
		return [
			'credentials'   => [ 'DELETE FROM wp_magicauth_passkeys ' ],
			'challenges'    => [ 'DELETE FROM wp_magicauth_passkey_challenges' ],
			'session state' => [ 'DELETE FROM wp_magicauth_passkey_sessions' ],
		];
	}

	/** @dataProvider erase_queries */
	public function test_erase_query_error_is_a_wp_error_and_a_rerun_completes( string $query ): void {
		global $wpdb;
		self::enrol( $this->user );
		ChallengeStore::issue( 'reauth', 7, Ceremony::SESSION, '', '', 420 );
		self::stepped_up_session( $this->user );
		$wpdb->fail_next_query( $query );

		ob_start();
		$result = Privacy::erase( 'learner7@example.test' );
		$this->assertSame( '', (string) ob_get_clean(), 'nothing printed' );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'magicauth_db_error', $result->get_error_code() );
		$this->assertNotSame( [], get_user_meta( 7, 'magicauth_passkey_user_handle', false ), 'meta kept until the rows are gone' );

		$this->erase();
		$this->assertSame( 0, self::count_rows( CredentialStore::table(), 7 ) );
		$this->assertSame( 0, self::count_rows( ChallengeStore::table(), 7 ) );
		$this->assertSame( 0, self::count_rows( SessionState::table(), 7 ) );
		$this->assertSame( [], get_user_meta( 7, 'magicauth_passkey_user_handle', false ) );
	}

	/* -------------------------------------------------------- registration */

	public function test_registered_next_to_the_login_activity_entries(): void {
		$this->assertFalse( \MagicAuth\Passkeys\Module::enabled(), 'registered with the module off' );
		$plugin    = Plugin::instance();
		$exporters = $plugin->register_exporter( [ 'core' => [] ] );
		$erasers   = $plugin->register_eraser( [ 'core' => [] ] );

		$this->assertSame( [ 'core', 'magicauth', 'magicauth-passkeys' ], array_keys( $exporters ) );
		$this->assertSame( [ 'core', 'magicauth', 'magicauth-passkeys' ], array_keys( $erasers ) );
		$this->assertSame( [ Privacy::class, 'export' ], $exporters['magicauth-passkeys']['callback'] );
		$this->assertSame( [ Privacy::class, 'erase' ], $erasers['magicauth-passkeys']['callback'] );
		$this->assertSame( 'MagicAuth passkeys', $exporters['magicauth-passkeys']['exporter_friendly_name'] );
		$this->assertSame( 'MagicAuth passkeys', $erasers['magicauth-passkeys']['eraser_friendly_name'] );
		$this->assertTrue( is_callable( $exporters['magicauth-passkeys']['callback'] ) );
		$this->assertTrue( is_callable( $erasers['magicauth-passkeys']['callback'] ) );
	}

	public function test_clock_pins_the_live_session_boundary(): void {
		global $magicauth_test_state;
		Ceremony::sign_in( $this->user, 'link' );
		foreach ( $magicauth_test_state['sessions'][7] as $verifier => $session ) {
			$magicauth_test_state['sessions'][7][ $verifier ]['expiration'] = Ceremony::NOW;
		}
		$this->assertTrue( $this->erase()['items_retained'], 'expiration equal to now is still live (core: >= time())' );
		Clock::set_for_tests( Ceremony::NOW + 1 );
		$this->assertFalse( $this->erase()['items_retained'] );
	}
}
