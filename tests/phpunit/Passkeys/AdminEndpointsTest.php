<?php
/**
 * T-ADMIN (SPEC 2.4, 6.12, 14.1, build step 13) and T-OFF-2: the admin
 * removal endpoints, magicauth_admin_passkey_delete and _revoke_all, under
 * magicauth_current_user_can_revoke_passkeys(). Role capabilities come from a
 * hand-written fixture of the academy's role shapes (administrator,
 * group_leader with edit_users plus the group_leader and assign_categories
 * caps the administrator role lacks, editor, subscriber), never from the
 * reference DB. Removal only; the endpoints work with the module off.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Passkeys\AdminEndpoints;
use MagicAuth\Passkeys\ChallengeStore;
use MagicAuth\Passkeys\CredentialStore;
use MagicAuth\Passkeys\Module;
use MagicAuth\Passkeys\SessionState;
use MagicAuth\Tests\Support\Ceremony;
use MagicAuth\Tests\Support\SoftAuthenticator;
use PHPUnit\Framework\TestCase;
use WP_User;

final class AdminEndpointsTest extends TestCase {

	private const ADMIN = 1;

	private const LEADER = 2;

	private const EDITOR = 3;

	private const STUDENT = 7;

	private const ADMIN_B = 8;

	/** @var array<string,mixed> */
	private array $server = [];

	protected function setUp(): void {
		$this->server = $_SERVER;
		Ceremony::site();
		self::academy_roles();
		self::person( self::ADMIN, 'administrator' );
		self::person( self::LEADER, 'group_leader' );
		self::person( self::EDITOR, 'editor' );
		self::person( self::STUDENT, 'subscriber' );
		self::person( self::ADMIN_B, 'administrator' );
	}

	protected function tearDown(): void {
		global $wpdb;
		$_SERVER  = $this->server;
		$_POST    = [];
		$_REQUEST = [];
		$_COOKIE  = [];
		$wpdb->show_errors( false );
		magicauth_test_reset_state();
	}

	/* ------------------------------------------------------------- fixture */

	/** The academy's role shapes, hand-written (6.12, T-ADMIN). */
	private static function academy_roles(): void {
		$roles                       = wp_roles();
		$roles->roles['group_leader'] = [
			'name'         => 'Group Leader',
			'capabilities' => [
				'read'              => true,
				'edit_users'        => true,
				'list_users'        => true,
				'group_leader'      => true,
				'assign_categories' => true,
			],
		];
	}

	private static function person( int $id, string $role ): WP_User {
		$user                  = magicauth_test_register_user( $id, "user{$id}@example.test", [ $role ] );
		$user->user_registered = Ceremony::REGISTERED;
		$user->display_name    = "User {$id}";
		$user->user_login      = "user{$id}";
		return $user;
	}

	private static function enrol( int $uid ): int {
		return Ceremony::enrol( new SoftAuthenticator( 'ES256' ), get_userdata( $uid ) );
	}

	/**
	 * @param array<string,mixed> $fields
	 * @return array{status:?int,success:bool,data:array<string,mixed>,body:string}
	 */
	private static function post( string $handler, int $actor, array $fields, string $nonce_action = AdminEndpoints::NONCE ): array {
		global $wpdb;
		magicauth_test_login_as( $actor );
		Ceremony::account_post( $fields, $nonce_action );
		$wpdb->show_errors( true );
		try {
			return Ceremony::call( $handler, AdminEndpoints::class );
		} finally {
			$wpdb->show_errors( false );
		}
	}

	private static function count_for( int $uid ): int {
		global $wpdb;
		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . CredentialStore::table() . ' WHERE user_id = %d', $uid ) );
	}

	/** @return array<int,array<string,mixed>> */
	private static function mails(): array {
		global $magicauth_test_state;
		return $magicauth_test_state['mail'] ?? [];
	}

	/** @param array{status:?int,success:bool,data:array<string,mixed>,body:string} $r */
	private function assert_forbidden( array $r, string $label = '' ): void {
		$this->assertSame( 403, $r['status'], $label . ' ' . $r['body'] );
		$this->assertSame( 'forbidden', $r['data']['code'] ?? null, $label );
	}

	/* ------------------------------------------------------------- the capability gate */

	public function test_administrator_removes_a_group_leaders_passkeys(): void {
		$id = self::enrol( self::LEADER );
		self::enrol( self::LEADER );

		$r = self::post( 'delete', self::ADMIN, [ 'user_id' => (string) self::LEADER, 'id' => (string) $id ] );
		$this->assertSame( 200, $r['status'], $r['body'] );
		$this->assertCount( 1, $r['data']['passkeys'] );
		$this->assertArrayNotHasKey( 'credential_id', $r['data']['passkeys'][0], 'admin responses omit credential IDs' );
		$this->assertNull( Ceremony::row( $id ) );

		$r = self::post( 'revoke_all', self::ADMIN, [ 'user_id' => (string) self::LEADER ] );
		$this->assertSame( 200, $r['status'], $r['body'] );
		$this->assertSame( 1, $r['data']['count'] );
		$this->assertSame( '1 passkey removed.', $r['data']['message'] );
		$this->assertSame( 0, self::count_for( self::LEADER ) );
	}

	public function test_group_leader_cannot_remove_an_administrators_passkeys(): void {
		$id = self::enrol( self::ADMIN );

		$this->assert_forbidden( self::post( 'delete', self::LEADER, [ 'user_id' => (string) self::ADMIN, 'id' => (string) $id ] ) );
		$this->assert_forbidden( self::post( 'revoke_all', self::LEADER, [ 'user_id' => (string) self::ADMIN ] ) );
		$this->assertNotNull( Ceremony::row( $id ) );
	}

	public function test_editor_cannot_remove_a_subscribers_passkeys(): void {
		$id = self::enrol( self::STUDENT );
		$this->assert_forbidden( self::post( 'delete', self::EDITOR, [ 'user_id' => (string) self::STUDENT, 'id' => (string) $id ] ) );
		$this->assert_forbidden( self::post( 'revoke_all', self::EDITOR, [ 'user_id' => (string) self::STUDENT ] ) );
		$this->assertNotNull( Ceremony::row( $id ) );
	}

	public function test_group_leader_with_edit_users_cannot_remove_a_subscribers_passkeys(): void {
		$id = self::enrol( self::STUDENT );
		magicauth_test_login_as( self::LEADER );
		$this->assertTrue( current_user_can( 'edit_user', self::STUDENT ), 'the leader passes edit_user' );

		$this->assert_forbidden( self::post( 'delete', self::LEADER, [ 'user_id' => (string) self::STUDENT, 'id' => (string) $id ] ) );
		$this->assert_forbidden( self::post( 'revoke_all', self::LEADER, [ 'user_id' => (string) self::STUDENT ] ) );
		$this->assertSame( 1, self::count_for( self::STUDENT ) );
	}

	public function test_helper_matrix_does_not_use_the_rank_helper(): void {
		magicauth_test_login_as( self::ADMIN );
		$this->assertFalse( magicauth_current_user_can_control_user( self::STUDENT ), 'B17 (open, as in 1.0.5): the rank helper refuses administrators, the revoke helper does not' );
		$this->assertTrue( magicauth_current_user_can_revoke_passkeys( self::STUDENT ) );
		$this->assertTrue( magicauth_current_user_can_revoke_passkeys( self::LEADER ) );
		$this->assertTrue( magicauth_current_user_can_revoke_passkeys( self::ADMIN_B ), 'peer administrator' );
		$this->assertFalse( magicauth_current_user_can_revoke_passkeys( 0 ) );
		$this->assertFalse( magicauth_current_user_can_revoke_passkeys( -3 ) );

		magicauth_test_login_as( self::LEADER );
		$this->assertFalse( magicauth_current_user_can_revoke_passkeys( self::STUDENT ) );
		$this->assertFalse( magicauth_current_user_can_control_user( self::ADMIN ), 'the rank helper keeps group leaders off administrators' );
		magicauth_test_login_as( self::EDITOR );
		$this->assertFalse( magicauth_current_user_can_revoke_passkeys( self::STUDENT ) );
		magicauth_test_login_as( 0 );
		$this->assertFalse( magicauth_current_user_can_revoke_passkeys( self::STUDENT ) );
	}

	public function test_self_is_allowed_without_the_capability(): void {
		$id = self::enrol( self::STUDENT );
		$other = self::enrol( self::STUDENT );

		$r = self::post( 'delete', self::STUDENT, [ 'user_id' => (string) self::STUDENT, 'id' => (string) $id ] );
		$this->assertSame( 200, $r['status'], $r['body'] );
		$this->assertNull( Ceremony::row( $id ) );
		$this->assertArrayHasKey( 'credential_id', $r['data']['passkeys'][0], 'self gets credential IDs (signals)' );
		$this->assertSame( $other, $r['data']['passkeys'][0]['id'] );

		$r = self::post( 'revoke_all', self::STUDENT, [ 'user_id' => (string) self::STUDENT ] );
		$this->assertSame( 200, $r['status'], $r['body'] );
		$this->assertSame( 0, self::count_for( self::STUDENT ) );
	}

	public function test_admin_capability_filter(): void {
		$sub   = self::enrol( self::STUDENT );
		$admin = self::enrol( self::ADMIN );
		add_filter(
			'magicauth_passkey_admin_capability',
			static function () {
				return 'edit_users';
			}
		);

		$r = self::post( 'delete', self::LEADER, [ 'user_id' => (string) self::STUDENT, 'id' => (string) $sub ] );
		$this->assertSame( 200, $r['status'], 'the filtered capability lets the leader remove a subscriber\'s' );
		$this->assert_forbidden( self::post( 'delete', self::LEADER, [ 'user_id' => (string) self::ADMIN, 'id' => (string) $admin ] ), 'administrators only by peers' );
		$this->assertNotNull( Ceremony::row( $admin ) );
	}

	/**
	 * A role with manage_options but neither edit_users nor delete_users (a
	 * plugin's "site manager"): it fails edit_user on others, and as a target it
	 * is a manage_options holder that is not a super admin, so only peers may
	 * remove its passkeys (each rule of 6.12 alone).
	 */
	public function test_each_rule_of_the_gate_alone(): void {
		$roles                        = wp_roles();
		$roles->roles['site_manager'] = [
			'name'         => 'Site Manager',
			'capabilities' => [
				'read'           => true,
				'manage_options' => true,
			],
		];
		self::person( 20, 'site_manager' );
		self::person( 21, 'site_manager' );
		$student = self::enrol( self::STUDENT );
		$manager = self::enrol( 21 );

		// manage_options without edit_user on the target.
		$this->assert_forbidden( self::post( 'delete', 20, [ 'user_id' => (string) self::STUDENT, 'id' => (string) $student ] ), 'edit_user required' );

		// A non-peer with the filtered capability and edit_user, on a manage_options target that is not a super admin.
		add_filter(
			'magicauth_passkey_admin_capability',
			static function () {
				return 'edit_users';
			}
		);
		magicauth_test_login_as( self::LEADER );
		$this->assertFalse( is_super_admin( 21 ), 'the target is no super admin' );
		$this->assertTrue( current_user_can( 'edit_user', 21 ) );
		$this->assert_forbidden( self::post( 'delete', self::LEADER, [ 'user_id' => '21', 'id' => (string) $manager ] ), 'manage_options targets only for peers' );
		$this->assertNotNull( Ceremony::row( $manager ) );
		$this->assertNotNull( Ceremony::row( $student ) );
	}

	public function test_non_string_capability_filter_denies(): void {
		$id = self::enrol( self::STUDENT );
		add_filter(
			'magicauth_passkey_admin_capability',
			static function () {
				return false;
			}
		);
		$this->assert_forbidden( self::post( 'delete', self::ADMIN, [ 'user_id' => (string) self::STUDENT, 'id' => (string) $id ] ) );
	}

	public function test_can_revoke_filter_both_ways(): void {
		$id = self::enrol( self::STUDENT );
		$deny = static function () {
			return false;
		};
		add_filter( 'magicauth_current_user_can_revoke_passkeys', $deny );
		$this->assert_forbidden( self::post( 'delete', self::ADMIN, [ 'user_id' => (string) self::STUDENT, 'id' => (string) $id ] ) );
		remove_filter( 'magicauth_current_user_can_revoke_passkeys', $deny );

		$seen = null;
		add_filter(
			'magicauth_current_user_can_revoke_passkeys',
			static function ( $can, $target ) use ( &$seen ) {
				$seen = [ $can, $target ];
				return true;
			},
			10,
			2
		);
		$r = self::post( 'delete', self::EDITOR, [ 'user_id' => (string) self::STUDENT, 'id' => (string) $id ] );
		$this->assertSame( 200, $r['status'], $r['body'] );
		$this->assertSame( [ false, self::STUDENT ], $seen );
	}

	public function test_super_admin_targets_only_for_super_admins(): void {
		global $magicauth_test_state;
		$magicauth_test_state['multisite']    = true;
		$magicauth_test_state['super_admins'] = [ 'user8' ];
		$id = self::enrol( self::ADMIN_B );

		$this->assert_forbidden( self::post( 'delete', self::ADMIN, [ 'user_id' => (string) self::ADMIN_B, 'id' => (string) $id ] ), 'administrator on a super admin' );
		$this->assertNotNull( Ceremony::row( $id ) );

		$magicauth_test_state['super_admins'] = [ 'user1', 'user8' ];
		$r = self::post( 'delete', self::ADMIN, [ 'user_id' => (string) self::ADMIN_B, 'id' => (string) $id ] );
		$this->assertSame( 200, $r['status'], $r['body'] );
	}

	/* ------------------------------------------------------------- gates */

	/** @return array<string,array{0:\Closure}> */
	public static function gates(): array {
		return [
			'not logged in'      => [ static function (): void {
				magicauth_test_login_as( 0 );
			} ],
			'no nonce'           => [ static function (): void {
				unset( $_REQUEST['_ajax_nonce'] );
			} ],
			'account nonce'      => [ static function (): void {
				$_REQUEST['_ajax_nonce'] = wp_create_nonce( 'magicauth_passkeys' );
			} ],
			'foreign Origin'     => [ static function (): void {
				$_SERVER['HTTP_ORIGIN'] = 'https://evil.example';
			} ],
			'Origin null'        => [ static function (): void {
				$_SERVER['HTTP_ORIGIN'] = 'null';
			} ],
			'no user_id'         => [ static function (): void {
				unset( $_POST['user_id'] );
			} ],
			'user_id 0'          => [ static function (): void {
				$_POST['user_id'] = '0';
			} ],
			'user_id not a number' => [ static function (): void {
				$_POST['user_id'] = '7 OR 1=1';
			} ],
			'unknown user'       => [ static function (): void {
				$_POST['user_id'] = '999';
			} ],
		];
	}

	/** @dataProvider gates */
	public function test_gates_answer_forbidden_and_remove_nothing( \Closure $breaks ): void {
		$id = self::enrol( self::STUDENT );
		foreach ( [ 'delete', 'revoke_all' ] as $handler ) {
			magicauth_test_login_as( self::ADMIN );
			Ceremony::account_post(
				[
					'user_id' => (string) self::STUDENT,
					'id'      => (string) $id,
				],
				AdminEndpoints::NONCE
			);
			$breaks();
			$this->assert_forbidden( Ceremony::call( $handler, AdminEndpoints::class ), $handler );
		}
		$this->assertNotNull( Ceremony::row( $id ) );
		$this->assertSame( [], self::mails() );
	}

	public function test_get_is_refused_with_405(): void {
		$id = self::enrol( self::STUDENT );
		magicauth_test_login_as( self::ADMIN );
		Ceremony::account_post( [ 'user_id' => (string) self::STUDENT, 'id' => (string) $id ], AdminEndpoints::NONCE );
		$_SERVER['REQUEST_METHOD'] = 'GET';
		$r = Ceremony::call( 'delete', AdminEndpoints::class );
		$this->assertSame( 405, $r['status'] );
		$this->assertNotNull( Ceremony::row( $id ) );
	}

	/* ------------------------------------------------------------- delete */

	public function test_delete_is_scoped_by_user_id(): void {
		$student = self::enrol( self::STUDENT );
		self::enrol( self::LEADER );

		// The student's row id posted with the leader as target: not found, untouched (IDOR).
		$r = self::post( 'delete', self::ADMIN, [ 'user_id' => (string) self::LEADER, 'id' => (string) $student ] );
		$this->assertSame( 404, $r['status'], $r['body'] );
		$this->assertSame( 'not_found', $r['data']['code'] );
		$this->assertNotNull( Ceremony::row( $student ) );
		$this->assertSame( 1, self::count_for( self::LEADER ) );

		foreach ( [ '', '0', '-1', 'abc', '1e3' ] as $bad ) {
			$r = self::post( 'delete', self::ADMIN, [ 'user_id' => (string) self::STUDENT, 'id' => $bad ] );
			$this->assertSame( 404, $r['status'], var_export( $bad, true ) );
		}
		$this->assertNotNull( Ceremony::row( $student ) );
		$this->assertSame( [], self::mails() );
	}

	public function test_delete_signout_destroys_every_session_of_the_target(): void {
		$id = self::enrol( self::STUDENT );
		$id2 = self::enrol( self::STUDENT );
		$tokens = \WP_Session_Tokens::get_instance( self::STUDENT );
		$tokens->create( Ceremony::NOW + DAY_IN_SECONDS );
		$tokens->create( Ceremony::NOW + DAY_IN_SECONDS );

		$r = self::post( 'delete', self::ADMIN, [ 'user_id' => (string) self::STUDENT, 'id' => (string) $id, 'signout' => '0' ] );
		$this->assertFalse( $r['data']['signed_out'] );
		$this->assertCount( 2, $tokens->get_all(), 'signout=0 keeps the sessions' );

		$r = self::post( 'delete', self::ADMIN, [ 'user_id' => (string) self::STUDENT, 'id' => (string) $id2 ] );
		$this->assertTrue( $r['data']['signed_out'], 'signout defaults to 1' );
		$this->assertCount( 0, $tokens->get_all() );
	}

	public function test_self_signout_keeps_the_current_session(): void {
		$id    = self::enrol( self::STUDENT );
		$token = Ceremony::sign_in( get_userdata( self::STUDENT ), 'link' );
		\WP_Session_Tokens::get_instance( self::STUDENT )->create( Ceremony::NOW + DAY_IN_SECONDS );

		$r = self::post( 'delete', self::STUDENT, [ 'user_id' => (string) self::STUDENT, 'id' => (string) $id, 'signout' => '1' ] );
		$this->assertSame( 200, $r['status'], $r['body'] );
		$this->assertTrue( $r['data']['signed_out'] );
		$this->assertCount( 1, \WP_Session_Tokens::get_instance( self::STUDENT )->get_all() );
		$this->assertNotNull( \WP_Session_Tokens::get_instance( self::STUDENT )->get( $token ), 'own session kept' );
	}

	public function test_delete_mails_the_owner_and_fires_the_action(): void {
		global $magicauth_test_state;
		update_option( 'magicauth_settings', [ 'company_name' => 'Example Academy' ] );
		$id    = self::enrol( self::STUDENT );
		$fired = [];
		add_action(
			'magicauth_passkey_removed',
			static function ( ...$args ) use ( &$fired ) {
				$fired[] = $args;
			},
			10,
			3
		);

		$r = self::post( 'delete', self::ADMIN, [ 'user_id' => (string) self::STUDENT, 'id' => (string) $id ] );
		$this->assertSame( 200, $r['status'] );
		$this->assertSame( [ [ self::STUDENT, $id, 'admin' ] ], $fired );
		$mails = self::mails();
		$this->assertCount( 1, $mails, 'removal email queued once' );
		$this->assertSame( 'user7@example.test', $mails[0]['to'] );
		$this->assertSame( '1 passkey was removed from your Example Academy account', $mails[0]['subject'] );
		$this->assertStringContainsString( 'An administrator removed 1 passkey from your account at Example Academy', $mails[0]['alt_body'] );
		$this->assertGreaterThanOrEqual( 1, $magicauth_test_state['after_response_calls'] ?? 0, 'sent after the response' );
	}

	/** r1-frontend-04: a failed list read after the removal is list_error, not an empty list. */
	public function test_a_failed_list_read_after_delete_is_list_error(): void {
		global $wpdb;
		$id = self::enrol( self::STUDENT );
		self::enrol( self::STUDENT );
		$wpdb->before_next_query(
			'DELETE FROM ' . CredentialStore::table(),
			static function () use ( $wpdb ): void {
				$wpdb->fail_next_query( 'SELECT * FROM ' . CredentialStore::table() . ' WHERE user_id' );
			}
		);
		$r = self::post( 'delete', self::ADMIN, [ 'user_id' => (string) self::STUDENT, 'id' => (string) $id ] );
		$this->assertSame( 200, $r['status'], $r['body'] );
		$this->assertNull( $r['data']['passkeys'] );
		$this->assertTrue( $r['data']['list_error'] ?? null );
		$this->assertNull( Ceremony::row( $id ) );
	}

	public function test_delete_database_error_is_retry(): void {
		global $wpdb;
		$id = self::enrol( self::STUDENT );
		$wpdb->fail_next_query( 'DELETE FROM ' . CredentialStore::table() );
		$r = self::post( 'delete', self::ADMIN, [ 'user_id' => (string) self::STUDENT, 'id' => (string) $id ] );
		$this->assertSame( 503, $r['status'], $r['body'] );
		$this->assertSame( 'retry', $r['data']['code'] );
		$this->assertNotNull( Ceremony::row( $id ) );
		$this->assertSame( [], self::mails() );
	}

	/* ------------------------------------------------------------- revoke all */

	public function test_revoke_all_removes_rows_challenges_and_state_and_keeps_the_handle(): void {
		global $wpdb;
		self::enrol( self::STUDENT );
		self::enrol( self::STUDENT );
		self::enrol( self::LEADER );
		$handle = CredentialStore::user_handle( self::STUDENT, false );
		$this->assertNotNull( $handle );
		ChallengeStore::issue( 'reauth', self::STUDENT, Ceremony::SESSION, '', '', 420 );
		Ceremony::sign_in( get_userdata( self::STUDENT ), 'link' );
		$this->assertTrue( SessionState::set( 'prompt_done', 1 ) );

		$fired = [];
		add_action(
			'magicauth_passkeys_revoked',
			static function ( ...$args ) use ( &$fired ) {
				$fired[] = $args;
			},
			10,
			4
		);
		$r = self::post( 'revoke_all', self::ADMIN, [ 'user_id' => (string) self::STUDENT ] );

		$this->assertSame( 200, $r['status'], $r['body'] );
		$this->assertSame( 2, $r['data']['count'] );
		$this->assertSame( '2 passkeys removed.', $r['data']['message'] );
		$this->assertTrue( $r['data']['signed_out'] );
		$this->assertSame( 0, self::count_for( self::STUDENT ) );
		$this->assertSame( 1, self::count_for( self::LEADER ), 'other users untouched' );
		$this->assertSame( 0, (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . ChallengeStore::table() . ' WHERE user_id = %d', self::STUDENT ) ) );
		$this->assertSame( 0, (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . SessionState::table() . ' WHERE user_id = %d', self::STUDENT ) ) );
		$this->assertSame( $handle, CredentialStore::user_handle( self::STUDENT, false ), 'handle kept (checklist 1.3.3)' );
		$this->assertSame( [ [ self::STUDENT, self::ADMIN, 2, 'admin' ] ], $fired );
		$this->assertCount( 0, \WP_Session_Tokens::get_instance( self::STUDENT )->get_all(), 'signed out everywhere' );
		$this->assertCount( 1, self::mails() );
		$this->assertStringContainsString( 'An administrator removed 2 passkeys', self::mails()[0]['alt_body'] );
		$this->assertMatchesRegularExpression( '/^2 passkeys were removed from your .* account$/', self::mails()[0]['subject'] );
	}

	public function test_revoke_all_without_passkeys_sends_no_email(): void {
		$r = self::post( 'revoke_all', self::ADMIN, [ 'user_id' => (string) self::STUDENT, 'signout' => '0' ] );
		$this->assertSame( 200, $r['status'], $r['body'] );
		$this->assertSame( 0, $r['data']['count'] );
		$this->assertSame( '0 passkeys removed.', $r['data']['message'] );
		$this->assertFalse( $r['data']['signed_out'] );
		$this->assertSame( [], self::mails() );
	}

	public function test_revoke_all_database_error_is_retry(): void {
		global $wpdb;
		self::enrol( self::STUDENT );
		$wpdb->fail_next_query( 'DELETE FROM ' . CredentialStore::table() );
		$r = self::post( 'revoke_all', self::ADMIN, [ 'user_id' => (string) self::STUDENT ] );
		$this->assertSame( 503, $r['status'], $r['body'] );
		$this->assertSame( 1, self::count_for( self::STUDENT ) );
		$this->assertCount( 0, self::mails() );
	}

	/* ------------------------------------------------------------- T-OFF-2: module off */

	public function test_registered_inside_admin_whatever_the_toggle(): void {
		global $magicauth_test_state;
		$magicauth_test_state['is_admin'] = true;
		Module::setup();
		do_action( 'init' );
		$this->assertFalse( Module::enabled() );

		$this->assertSame( 10, has_action( 'wp_ajax_magicauth_admin_passkey_delete', [ AdminEndpoints::class, 'delete' ] ) );
		$this->assertSame( 10, has_action( 'wp_ajax_magicauth_admin_passkey_revoke_all', [ AdminEndpoints::class, 'revoke_all' ] ) );
		$this->assertFalse( has_action( 'wp_ajax_nopriv_magicauth_admin_passkey_delete' ) );
		$this->assertFalse( has_action( 'wp_ajax_nopriv_magicauth_admin_passkey_revoke_all' ) );
	}

	public function test_not_registered_outside_admin(): void {
		Module::setup();
		$this->assertFalse( has_action( 'wp_ajax_magicauth_admin_passkey_delete' ) );
		$this->assertFalse( has_action( 'show_user_profile' ) );
	}

	public function test_admin_endpoints_work_with_the_module_off(): void {
		$id = self::enrol( self::STUDENT );
		$this->assertFalse( Module::enabled(), 'module off' );

		$r = self::post( 'delete', self::ADMIN, [ 'user_id' => (string) self::STUDENT, 'id' => (string) $id ] );
		$this->assertSame( 200, $r['status'], $r['body'] );
		self::enrol( self::STUDENT );
		$r = self::post( 'revoke_all', self::ADMIN, [ 'user_id' => (string) self::STUDENT ] );
		$this->assertSame( 200, $r['status'], $r['body'] );
		$this->assertSame( 0, self::count_for( self::STUDENT ) );
	}

	public function test_no_endpoint_creates_a_credential_for_another_user(): void {
		$source = (string) file_get_contents( MAGICAUTH_DIR . 'includes/Passkeys/AdminEndpoints.php' );
		foreach ( [ 'insert(', 'store_registration', 'verify_registration', 'register_options', 'user_handle(' ] as $needle ) {
			$this->assertStringNotContainsString( $needle, $source );
		}
	}
}
