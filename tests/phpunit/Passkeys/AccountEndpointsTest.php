<?php
/**
 * T-MANAGE (SPEC 6.6, 6.8, 6.14, 6.7 reauth_options, 14.1, build steps 13
 * and 14): the owner endpoints rename, delete, signout_others and the prompt
 * choice, and the shared gates of the account endpoints. The prompt choice's
 * cadence and cookie are in PromptTest.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Auth\Throttle;
use MagicAuth\Passkeys\Assets;
use MagicAuth\Passkeys\ChallengeStore;
use MagicAuth\Passkeys\CredentialStore;
use MagicAuth\Passkeys\Module;
use MagicAuth\Passkeys\Signals;
use MagicAuth\Tests\Support\Ceremony;
use MagicAuth\Tests\Support\SoftAuthenticator;
use PHPUnit\Framework\TestCase;
use WP_User;

final class AccountEndpointsTest extends TestCase {

	private WP_User $user;

	private WP_User $other;

	/** @var array<string,mixed> */
	private array $server = [];

	protected function setUp(): void {
		$this->server = $_SERVER;
		Ceremony::site();
		Ceremony::enable_module();
		update_option(
			'magicauth_settings',
			[
				'passkeys_enabled' => true,
				'company_name'     => 'Example Academy',
			]
		);
		Module::reset_for_tests();
		$this->user  = Ceremony::user( 7 );
		$this->other = Ceremony::user( 8 );
		// A fresh link session by default.
		Ceremony::sign_in( $this->user, 'link' );
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

	/* ------------------------------------------------------------- helpers */

	/**
	 * @param array<string,mixed> $fields
	 * @return array{status:?int,success:bool,data:array<string,mixed>,body:string}
	 */
	private static function post( string $handler, array $fields = [] ): array {
		global $wpdb;
		Ceremony::account_post( $fields );
		$wpdb->show_errors( true );
		try {
			return Ceremony::call( $handler );
		} finally {
			$wpdb->show_errors( false );
		}
	}

	private function enrol( WP_User $user, string $name = '' ): int {
		$id = Ceremony::enrol( new SoftAuthenticator( 'ES256' ), $user );
		if ( '' !== $name ) {
			$this->assertTrue( CredentialStore::rename( (int) $user->ID, $id, $name ) );
		}
		return $id;
	}

	/** @param array{status:?int,success:bool,data:array<string,mixed>,body:string} $r */
	private function assert_failed( array $r, string $code, int $status, string $label = '' ): void {
		$this->assertSame( $status, $r['status'], $label . ' ' . $r['body'] );
		$this->assertFalse( $r['success'], $label );
		$this->assertSame( $code, $r['data']['code'] ?? null, $label );
	}

	/** @return array<int,array<string,mixed>> */
	private static function mails(): array {
		global $magicauth_test_state;
		return $magicauth_test_state['mail'] ?? [];
	}

	private static function sessions( int $uid ): int {
		return count( \WP_Session_Tokens::get_instance( $uid )->get_all() );
	}

	/* ------------------------------------------------------------- shared gates */

	/** @return array<string,array{string,array<string,string>}> */
	public static function endpoints(): array {
		return [
			'rename'         => [ 'rename', [ 'id' => '1', 'name' => 'Laptop' ] ],
			'delete'         => [ 'delete', [ 'id' => '1' ] ],
			'signout_others' => [ 'signout_others', [] ],
			'reauth_options' => [ 'reauth_options', [] ],
			'prompt_choice'  => [ 'prompt_choice', [ 'choice' => 'later' ] ],
		];
	}

	/**
	 * @dataProvider endpoints
	 * @param array<string,string> $fields
	 */
	public function test_not_logged_in( string $handler, array $fields ): void {
		magicauth_test_login_as( 0 );
		$this->assert_failed( self::post( $handler, $fields ), 'not_logged_in', 403 );
	}

	/**
	 * @dataProvider endpoints
	 * @param array<string,string> $fields
	 */
	public function test_bad_nonce( string $handler, array $fields ): void {
		Ceremony::account_post( $fields, 'magicauth-passkeys-admin' );
		$this->assert_failed( Ceremony::call( $handler ), 'bad_nonce', 403, 'the admin nonce' );
		Ceremony::account_post( $fields );
		unset( $_REQUEST['_ajax_nonce'] );
		$this->assert_failed( Ceremony::call( $handler ), 'bad_nonce', 403, 'no nonce' );
	}

	/**
	 * @dataProvider endpoints
	 * @param array<string,string> $fields
	 */
	public function test_bad_origin( string $handler, array $fields ): void {
		foreach ( [ 'https://evil.example', 'null', 'https://sub.academy.example.com', 'http://academy.example.com' ] as $origin ) {
			Ceremony::account_post( $fields );
			$_SERVER['HTTP_ORIGIN'] = $origin;
			$this->assert_failed( Ceremony::call( $handler ), 'bad_origin', 403, $origin );
		}
		Ceremony::account_post( $fields );
		unset( $_SERVER['HTTP_ORIGIN'] );
		$this->assert_failed( Ceremony::call( $handler ), 'bad_origin', 403, 'no Origin, no Referer' );
	}

	/**
	 * @dataProvider endpoints
	 * @param array<string,string> $fields
	 */
	public function test_module_off( string $handler, array $fields ): void {
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => false ] );
		Module::reset_for_tests();
		$this->assert_failed( self::post( $handler, $fields ), 'unavailable', 404 );
	}

	/**
	 * @dataProvider endpoints
	 * @param array<string,string> $fields
	 */
	public function test_get_is_refused( string $handler, array $fields ): void {
		Ceremony::account_post( $fields );
		$_SERVER['REQUEST_METHOD'] = 'GET';
		$this->assert_failed( Ceremony::call( $handler ), 'bad_request', 405 );
	}

	public function test_rename_delete_signout_and_prompt_choice_share_passkey_manage_user(): void {
		$id    = $this->enrol( $this->user );
		$calls = [
			[ 'rename', [ 'id' => (string) $id, 'name' => 'Laptop' ] ],
			[ 'delete', [ 'id' => '999' ] ],
			[ 'signout_others', [] ],
			[ 'prompt_choice', [ 'choice' => 'dismiss' ] ],
		];
		for ( $i = 0; $i < 60; $i++ ) {
			[ $handler, $fields ] = $calls[ $i % 4 ];
			$r                    = self::post( $handler, $fields );
			$this->assertNotSame( 429, $r['status'], "call {$i}" );
		}
		foreach ( $calls as [ $handler, $fields ] ) {
			$this->assert_failed( self::post( $handler, $fields ), 'throttled', 429, '61st: ' . $handler );
		}
		$this->assertNotNull( Ceremony::row( $id ), 'the throttled delete never ran' );
		$before = get_user_meta( 7, 'magicauth_passkey_prompt', true );
		$this->assert_failed( self::post( 'prompt_choice', [ 'choice' => 'later' ] ), 'throttled', 429 );
		$this->assertSame( $before, get_user_meta( 7, 'magicauth_passkey_prompt', true ), 'the throttled choice wrote nothing' );

		// Per user: another account is not affected.
		Ceremony::sign_in( $this->other, 'link' );
		$this->assertSame( 200, self::post( 'signout_others' )['status'] );
	}

	/** 6.8: any other choice is 400 bad_request and writes nothing. */
	public function test_prompt_choice_unknown_is_a_bad_request(): void {
		global $magicauth_test_state;
		foreach ( [ 'Later', 'LATER', '', 'devices', 'later ', 'accept', 'create' ] as $choice ) {
			$this->assert_failed( self::post( 'prompt_choice', [ 'choice' => $choice ] ), 'bad_request', 400, var_export( $choice, true ) );
		}
		$this->assert_failed( self::post( 'prompt_choice' ), 'bad_request', 400, 'absent' );
		$this->assert_failed( self::post( 'prompt_choice', [ 'choice' => [ 'later' ] ] ), 'bad_request', 400, 'array' );
		$this->assertSame( '', get_user_meta( 7, 'magicauth_passkey_prompt', true ) );
		$this->assertSame( [], $magicauth_test_state['cookies'] ?? [] );
		$this->assertSame( 200, self::post( 'prompt_choice', [ 'choice' => 'later' ] )['status'] );
	}

	public function test_31st_reauth_options_is_throttled_without_a_challenge_row(): void {
		global $wpdb;
		$this->enrol( $this->user );
		$table  = ChallengeStore::table();
		$before = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE ceremony = 'reauth'" );
		for ( $i = 0; $i < 30; $i++ ) {
			$this->assertSame( 200, self::post( 'reauth_options' )['status'], "call {$i}" );
		}
		$this->assert_failed( self::post( 'reauth_options' ), 'throttled', 429 );
		$this->assertSame( $before + 30, (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE ceremony = 'reauth'" ) );
		$this->assertSame( 0, (int) get_transient( 'magicauth_throttle_' . Throttle::ACTION_PASSKEY_REAUTH_TRY_USER . '_u7' ) );
	}

	public function test_reauth_options_without_a_usable_credential(): void {
		$this->assert_failed( self::post( 'reauth_options' ), 'no_passkey', 409 );
	}

	/* ------------------------------------------------------------- rename */

	public function test_rename_stores_the_sanitised_name_and_answers_the_list(): void {
		$id = $this->enrol( $this->user, 'Old' );
		$this->enrol( $this->user, 'Phone' );

		$r = self::post( 'rename', [ 'id' => (string) $id, 'name' => "  <b>Work</b> \u{202E}laptop " ] );
		$this->assertSame( 200, $r['status'], $r['body'] );
		$this->assertSame( 'Work laptop', Ceremony::row( $id )['name'] );
		$this->assertSame( $id, $r['data']['passkey']['id'] );
		$this->assertSame( 'Work laptop', $r['data']['passkey']['name'] );
		$this->assertArrayHasKey( 'credential_id', $r['data']['passkey'], 'owner response' );
		$this->assertCount( 2, $r['data']['passkeys'] );
		$this->assertCount( 2, $r['data']['signal']['allAccepted'] );
		$this->assertFalse( $r['data']['signal']['details'], 'the list only: details go with a page view (8.7)' );
		$this->assertTrue( Signals::payload( get_userdata( 7 ) )['details'] ?? null, 'still pending for the next page view' );
		$this->assertSame( '', get_user_meta( 7, Signals::SENT_META, true ), 'a response records nothing' );
	}

	public function test_rename_slashed_input_is_unslashed(): void {
		$id = $this->enrol( $this->user );
		$r  = self::post( 'rename', [ 'id' => (string) $id, 'name' => "Nol\\'s key" ] );
		$this->assertSame( 200, $r['status'], $r['body'] );
		$this->assertSame( "Nol's key", Ceremony::row( $id )['name'] );
	}

	public function test_rename_to_the_identical_name_is_200(): void {
		global $wpdb;
		$this->assertTrue( $wpdb->mysql_changed_rows, 'changed-rows semantics' );
		$id = $this->enrol( $this->user, 'Laptop' );
		$r  = self::post( 'rename', [ 'id' => (string) $id, 'name' => 'Laptop' ] );
		$this->assertSame( 200, $r['status'], $r['body'] );
	}

	public function test_rename_of_another_users_id_is_not_found_and_untouched(): void {
		$theirs = $this->enrol( $this->other, 'Theirs' );
		$this->assert_failed( self::post( 'rename', [ 'id' => (string) $theirs, 'name' => 'Mine now' ] ), 'not_found', 404 );
		$this->assertSame( 'Theirs', Ceremony::row( $theirs )['name'] );
		foreach ( [ '', '0', '-1', 'abc', '1 OR 1=1' ] as $bad ) {
			$this->assert_failed( self::post( 'rename', [ 'id' => $bad, 'name' => 'X' ] ), 'not_found', 404, var_export( $bad, true ) );
		}
	}

	/** @return array<string,array{mixed}> */
	public static function invalid_names(): array {
		return [
			'empty'        => [ '' ],
			'spaces'       => [ '   ' ],
			'markup only'  => [ '<script></script>' ],
			'bidi only'    => [ "\u{202E}\u{2066}" ],
			'over 256 B'   => [ str_repeat( 'a', 257 ) ],
			'absent'       => [ null ],
		];
	}

	/** @dataProvider invalid_names */
	public function test_rename_invalid_name( $name ): void {
		$id     = $this->enrol( $this->user, 'Keep' );
		$fields = [ 'id' => (string) $id ];
		if ( null !== $name ) {
			$fields['name'] = $name;
		}
		$r = self::post( 'rename', $fields );
		$this->assert_failed( $r, 'invalid_name', 400 );
		$this->assertSame( 'Enter a name of up to 64 characters.', $r['data']['message'] );
		$this->assertSame( 'Keep', Ceremony::row( $id )['name'] );
	}

	public function test_rename_to_64_characters_cut_from_200(): void {
		$id = $this->enrol( $this->user );
		$r  = self::post( 'rename', [ 'id' => (string) $id, 'name' => str_repeat( 'é', 100 ) ] );
		$this->assertSame( 200, $r['status'], $r['body'] );
		$this->assertSame( str_repeat( 'é', 64 ), Ceremony::row( $id )['name'] );
	}

	public function test_rename_duplicate_name_case_insensitive(): void {
		$this->enrol( $this->user, 'Laptop' );
		$id = $this->enrol( $this->user, 'Phone' );
		$r  = self::post( 'rename', [ 'id' => (string) $id, 'name' => 'LAPTOP' ] );
		$this->assert_failed( $r, 'duplicate_name', 400 );
		$this->assertSame( 'You already have a passkey with this name. Choose another name.', $r['data']['message'] );
		$this->assertSame( 'Phone', Ceremony::row( $id )['name'] );

		// Another user's name does not count.
		$this->enrol( $this->other, 'Tablet' );
		$this->assertSame( 200, self::post( 'rename', [ 'id' => (string) $id, 'name' => 'Tablet' ] )['status'] );
	}

	public function test_rename_database_error_is_retry(): void {
		global $wpdb;
		$id = $this->enrol( $this->user, 'Keep' );
		$wpdb->fail_next_query( 'UPDATE ' . CredentialStore::table() . ' SET name' );
		$r = self::post( 'rename', [ 'id' => (string) $id, 'name' => 'New' ] );
		$this->assert_failed( $r, 'retry', 503 );
		$this->assertStringNotContainsString( 'creating', $r['data']['message'] );
		$this->assertSame( 'Keep', Ceremony::row( $id )['name'] );
	}

	public function test_rename_sends_no_email(): void {
		$id = $this->enrol( $this->user );
		Ceremony::sign_in( $this->user, 'password', Ceremony::NOW - 3600 );
		$this->assertSame( 200, self::post( 'rename', [ 'id' => (string) $id, 'name' => 'New' ] )['status'] );
		$this->assertSame( [], self::mails() );
	}

	/* ------------------------------------------------------------- delete */

	public function test_delete_answers_the_list_and_signal(): void {
		$id   = $this->enrol( $this->user );
		$keep = $this->enrol( $this->user );
		$fired = [];
		add_action(
			'magicauth_passkey_removed',
			static function ( ...$args ) use ( &$fired ) {
				$fired[] = $args;
			},
			10,
			3
		);

		$r = self::post( 'delete', [ 'id' => (string) $id, 'signout_others' => '0' ] );
		$this->assertSame( 200, $r['status'], $r['body'] );
		$this->assertNull( Ceremony::row( $id ) );
		$this->assertSame( [ $keep ], array_column( $r['data']['passkeys'], 'id' ) );
		$this->assertSame( [ Ceremony::row( $keep )['credential_id'] ], $r['data']['signal']['allAccepted'] );
		$this->assertFalse( $r['data']['signal']['details'] );
		$this->assertSame( 0, $r['data']['signed_out'] );
		$this->assertSame( [ [ 7, $id, 'user' ] ], $fired );

		$r = self::post( 'delete', [ 'id' => (string) $keep, 'signout_others' => '0' ] );
		$this->assertSame( [], $r['data']['passkeys'] );
		$this->assertSame( [], $r['data']['signal']['allAccepted'], 'an empty list is sent' );
	}

	/**
	 * r1-frontend-04: the action succeeded but the list read failed: passkeys
	 * null and list_error true, never an empty list the page shows as M3.
	 */
	public function test_a_failed_list_read_after_delete_or_rename_is_list_error(): void {
		global $wpdb;
		$id   = $this->enrol( $this->user );
		$keep = $this->enrol( $this->user );
		$list = 'SELECT * FROM ' . CredentialStore::table() . ' WHERE user_id';

		foreach ( [ 'DELETE FROM ' . CredentialStore::table() => [ 'delete', [ 'id' => (string) $id, 'signout_others' => '0' ] ], 'SET name' => [ 'rename', [ 'id' => (string) $keep, 'name' => 'Work' ] ] ] as $write => [ $action, $fields ] ) {
			$wpdb->before_next_query(
				$write,
				static function () use ( $wpdb, $list ): void {
					$wpdb->fail_next_query( $list );
				}
			);
			$r = self::post( $action, $fields );
			$this->assertSame( 200, $r['status'], $action . ' ' . $r['body'] );
			$this->assertArrayHasKey( 'passkeys', $r['data'], $action );
			$this->assertNull( $r['data']['passkeys'], $action . ': no empty list' );
			$this->assertTrue( $r['data']['list_error'] ?? null, $action );
		}
		$this->assertNull( Ceremony::row( $id ) );
		$this->assertSame( 'Work', Ceremony::row( $keep )['name'] );

		$r = self::post( 'rename', [ 'id' => (string) $keep, 'name' => 'Home' ] );
		$this->assertArrayNotHasKey( 'list_error', $r['data'], 'only on a failed read' );
		$this->assertCount( 1, $r['data']['passkeys'] );
	}

	/** r1-frontend-04: the page config keeps null for an unreadable list, so the script never forgets haslocal. */
	public function test_the_account_config_sends_null_for_an_unreadable_list(): void {
		$this->assertNull( Assets::account_config( $this->user, null )['passkeys'] );
		$this->assertSame( [], Assets::account_config( $this->user, [] )['passkeys'] );
	}

	public function test_delete_of_another_users_id_is_not_found_and_untouched(): void {
		$theirs = $this->enrol( $this->other );
		$this->assert_failed( self::post( 'delete', [ 'id' => (string) $theirs ] ), 'not_found', 404 );
		$this->assertNotNull( Ceremony::row( $theirs ) );
		$this->assertSame( [], self::mails() );
	}

	public function test_delete_signout_others(): void {
		$current = wp_get_session_token();
		$tokens  = \WP_Session_Tokens::get_instance( 7 );
		$tokens->create( Ceremony::NOW + DAY_IN_SECONDS );
		$tokens->create( Ceremony::NOW + DAY_IN_SECONDS );
		$this->assertSame( 3, self::sessions( 7 ) );

		$a = $this->enrol( $this->user );
		$r = self::post( 'delete', [ 'id' => (string) $a, 'signout_others' => '0' ] );
		$this->assertSame( 0, $r['data']['signed_out'] );
		$this->assertSame( 3, self::sessions( 7 ), 'signout_others=0 keeps them' );

		$b = $this->enrol( $this->user );
		$r = self::post( 'delete', [ 'id' => (string) $b ] );
		$this->assertSame( 2, $r['data']['signed_out'], 'default 1' );
		$this->assertSame( 1, self::sessions( 7 ) );
		$this->assertNotNull( $tokens->get( $current ), 'this session stays' );
	}

	public function test_delete_from_a_stale_session_mails_the_owner(): void {
		$id = $this->enrol( $this->user );
		Ceremony::sign_in( $this->user, 'password', Ceremony::NOW - 3600 );

		$r = self::post( 'delete', [ 'id' => (string) $id, 'signout_others' => '0' ] );
		$this->assertSame( 200, $r['status'], $r['body'] );
		$mails = self::mails();
		$this->assertCount( 1, $mails );
		$this->assertSame( 'learner7@example.test', $mails[0]['to'] );
		$this->assertSame( '1 passkey was removed from your Example Academy account', $mails[0]['subject'] );
		$this->assertStringContainsString( 'You removed 1 passkey from your account at Example Academy', $mails[0]['alt_body'] );
	}

	public function test_delete_from_a_fresh_session_sends_nothing(): void {
		$id = $this->enrol( $this->user );
		$r  = self::post( 'delete', [ 'id' => (string) $id, 'signout_others' => '0' ] );
		$this->assertSame( 200, $r['status'], $r['body'] );
		$this->assertSame( [], self::mails() );
	}

	public function test_disabled_user_may_still_remove(): void {
		$id = $this->enrol( $this->user );
		update_user_meta( 7, 'magicauth_disabled', 1 );
		$this->assertSame( 200, self::post( 'delete', [ 'id' => (string) $id ] )['status'] );
		$this->assertNull( Ceremony::row( $id ) );
	}

	public function test_delete_database_error_is_retry(): void {
		global $wpdb;
		$id = $this->enrol( $this->user );
		$wpdb->fail_next_query( 'DELETE FROM ' . CredentialStore::table() );
		$this->assert_failed( self::post( 'delete', [ 'id' => (string) $id ] ), 'retry', 503 );
		$this->assertNotNull( Ceremony::row( $id ) );
	}

	/* ------------------------------------------------------------- sign out on all other devices */

	public function test_signout_others_keeps_this_session_only(): void {
		$current = wp_get_session_token();
		\WP_Session_Tokens::get_instance( 7 )->create( Ceremony::NOW + DAY_IN_SECONDS );
		\WP_Session_Tokens::get_instance( 8 )->create( Ceremony::NOW + DAY_IN_SECONDS );

		$r = self::post( 'signout_others' );
		$this->assertSame( 200, $r['status'], $r['body'] );
		$this->assertTrue( $r['success'] );
		$this->assertSame( [], $r['data'] );
		$this->assertSame( 1, self::sessions( 7 ) );
		$this->assertNotNull( \WP_Session_Tokens::get_instance( 7 )->get( $current ) );
		$this->assertSame( 1, self::sessions( 8 ), 'other users untouched' );
	}

	/* ------------------------------------------------------------- registration */

	public function test_owner_actions_are_wp_ajax_only(): void {
		Module::register();
		foreach ( [ 'rename', 'delete', 'signout_others' ] as $handler ) {
			$this->assertSame( 10, has_action( 'wp_ajax_magicauth_passkey_' . $handler, [ \MagicAuth\Passkeys\AccountEndpoints::class, $handler ] ) );
			$this->assertFalse( has_action( 'wp_ajax_nopriv_magicauth_passkey_' . $handler ) );
		}
	}
}
