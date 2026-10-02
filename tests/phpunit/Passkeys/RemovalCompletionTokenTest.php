<?php
/**
 * Passkey removal and completion tokens (review r1-session-02): a completion token issued before a passkey is
 * removed (with sign-out) must not establish a session afterwards.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Passkeys\AdminEndpoints;
use MagicAuth\Passkeys\ChallengeStore;
use MagicAuth\Passkeys\CredentialStore;
use MagicAuth\Passkeys\Freshness;
use MagicAuth\Passkeys\SignInEndpoints;
use MagicAuth\Tests\Stubs\JsonResponseSent;
use MagicAuth\Tests\Stubs\RedirectSent;
use MagicAuth\Tests\Support\Ceremony;
use MagicAuth\Tests\Support\SoftAuthenticator;
use PHPUnit\Framework\TestCase;
use WP_User;

final class RemovalCompletionTokenTest extends TestCase {

	private const RETURN_TO = 'https://academy.example.com/login/?ref=1';

	private WP_User $user;

	/** @var array<string,mixed> */
	private array $server = [];

	protected function setUp(): void {
		global $magicauth_test_state;
		$this->server = $_SERVER;
		Ceremony::site();
		Ceremony::enable_module();
		$magicauth_test_state['redirect_throws'] = true;
		$this->user                              = Ceremony::user( 7 );
		$this->user->user_login                  = 'learner7';
		$_COOKIE                                 = [];
		$_SERVER['REMOTE_ADDR']                  = '203.0.113.10';
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

	/** @param array<string,mixed> $fields */
	private static function attacker_request( array $fields ): void {
		global $magicauth_test_state;
		magicauth_test_login_as( 0 );
		unset( $magicauth_test_state['session_token'] );
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$_SERVER['HTTP_ORIGIN']    = Ceremony::ORIGIN;
		unset( $_SERVER['HTTP_REFERER'], $_SERVER['CONTENT_LENGTH'], $_SERVER['HTTP_SEC_FETCH_SITE'], $_SERVER['HTTP_SEC_FETCH_MODE'] );
		$_POST    = $fields;
		$_REQUEST = $fields;
		$_COOKIE  = [ SignInEndpoints::BIND_COOKIE => Ceremony::COOKIE ];
		$magicauth_test_state['cookies'] = [];
		$magicauth_test_state['headers'] = [];
	}

	/** Attacker's browser: options, verify; returns the held completion token. */
	private function held_token( SoftAuthenticator $auth ): string {
		self::attacker_request( [] );
		$options = $this->json( 'options' );
		$this->assertSame( 200, $options['status'] );
		$credential = Ceremony::encode( $auth->assert( $options['data']['publicKey'], Ceremony::ORIGIN, [] ) );
		self::attacker_request( [ 'credential' => $credential ] );
		$verify = $this->json( 'verify' );
		$this->assertSame( 200, $verify['status'], (string) json_encode( $verify['data'] ) );
		return (string) $verify['data']['complete'];
	}

	/** @return array{status:?int,data:array<string,mixed>} */
	private function json( string $handler ): array {
		ob_start();
		try {
			call_user_func( [ SignInEndpoints::class, $handler ] );
		} catch ( JsonResponseSent $sent ) {
			ob_end_clean();
			$payload = is_array( $sent->payload ) ? $sent->payload : [];
			return [
				'status' => $sent->status,
				'data'   => is_array( $payload['data'] ?? null ) ? $payload['data'] : [],
			];
		}
		ob_end_clean();
		throw new \RuntimeException( $handler . ' sent no response' );
	}

	/** @return array{location:string,query:array<string,string>} */
	private function complete( string $token ): array {
		self::attacker_request(
			[
				'action'      => 'magicauth_passkey_complete',
				'token'       => $token,
				'redirect_to' => '',
				'return_to'   => self::RETURN_TO,
			]
		);
		ob_start();
		try {
			SignInEndpoints::complete();
		} catch ( RedirectSent $sent ) {
			ob_end_clean();
			parse_str( (string) wp_parse_url( $sent->location, PHP_URL_QUERY ), $query );
			return [
				'location' => $sent->location,
				'query'    => $query,
			];
		}
		ob_end_clean();
		throw new \RuntimeException( 'complete sent no redirect' );
	}

	private function assert_refused( array $nav ): void {
		global $magicauth_test_state;
		$this->assertArrayHasKey( 'magicauth_passkey_error', $nav['query'], 'held token after removal must be refused; got ' . $nav['location'] . ' signed in as ' . get_current_user_id() . ', auth cookies ' . count( $magicauth_test_state['auth_cookies'] ?? [] ) );
		$this->assertSame( 0, get_current_user_id(), 'nobody signed in' );
		$this->assertArrayNotHasKey( 'auth_cookies', $magicauth_test_state, 'no auth cookie' );
		$fresh = array_filter(
			$magicauth_test_state['cookies'] ?? [],
			static function ( array $c ): bool {
				return Freshness::COOKIE === $c['name'] && '' !== $c['value'];
			}
		);
		$this->assertSame( [], array_values( $fresh ), 'no fresh cookie' );
	}

	public function test_owner_removal_with_signout_invalidates_a_held_completion_token(): void {
		$auth = new SoftAuthenticator( 'ES256', [ 'be' => true, 'bs' => true ] );
		$id   = Ceremony::enrol( $auth, $this->user );

		$token = $this->held_token( $auth );

		// The owner, on their own device, removes that passkey with sign-out of others.
		Ceremony::sign_in( $this->user, 'link' );
		Ceremony::account_post( [ 'id' => (string) $id, 'signout_others' => '1' ] );
		$r = Ceremony::call( 'delete' );
		$this->assertSame( 200, $r['status'], $r['body'] );
		$this->assertNull( Ceremony::row( $id ), 'passkey removed' );

		// Within the 120 s token TTL the attacker posts the held token.
		$this->assert_refused( $this->complete( $token ) );
	}

	public function test_admin_removal_with_signout_invalidates_a_held_completion_token(): void {
		$admin                  = magicauth_test_register_user( 1, 'admin@example.test', [ 'administrator' ] );
		$admin->user_registered = Ceremony::REGISTERED;
		$admin->user_login      = 'admin1';

		$auth = new SoftAuthenticator( 'ES256', [ 'be' => true, 'bs' => true ] );
		$id   = Ceremony::enrol( $auth, $this->user );

		$token = $this->held_token( $auth );

		magicauth_test_login_as( 1 );
		Ceremony::account_post( [ 'user_id' => '7', 'id' => (string) $id, 'signout' => '1' ], AdminEndpoints::NONCE );
		$r = Ceremony::call( 'delete', AdminEndpoints::class );
		$this->assertSame( 200, $r['status'], $r['body'] );
		$this->assertNull( Ceremony::row( $id ), 'passkey removed' );

		$this->assert_refused( $this->complete( $token ) );
	}
	public function test_removal_without_signout_also_kills_the_held_token(): void {
		$auth = new SoftAuthenticator( 'ES256', [ 'be' => true, 'bs' => true ] );
		$id   = Ceremony::enrol( $auth, $this->user );

		$token = $this->held_token( $auth );

		Ceremony::sign_in( $this->user, 'link' );
		Ceremony::account_post( [ 'id' => (string) $id, 'signout_others' => '0' ] );
		$r = Ceremony::call( 'delete' );
		$this->assertSame( 200, $r['status'], $r['body'] );

		$this->assert_refused( $this->complete( $token ) );
	}

	public function test_removal_between_the_account_check_and_the_token_burns_it(): void {
		global $wpdb;
		$auth = new SoftAuthenticator( 'ES256', [ 'be' => true, 'bs' => true ] );
		$id   = Ceremony::enrol( $auth, $this->user );

		self::attacker_request( [] );
		$options = $this->json( 'options' );
		$this->assertSame( 200, $options['status'] );
		$credential = Ceremony::encode( $auth->assert( $options['data']['publicKey'], Ceremony::ORIGIN, [] ) );

		// The owner's removal lands after A-9 read the row and before the
		// completion row exists, so its purge finds nothing to delete.
		$wpdb->before_next_query(
			'INSERT INTO wp_magicauth_passkey_challenges',
			static function () use ( $id ): void {
				CredentialStore::delete( 7, $id );
				ChallengeStore::delete_completions_for_user( 7 );
			}
		);
		self::attacker_request( [ 'credential' => $credential ] );
		$verify = $this->json( 'verify' );
		$this->assertSame( 400, $verify['status'], (string) json_encode( $verify['data'] ) );
		$this->assertSame( 'passkey_failed', $verify['data']['code'] ?? null );
		$this->assertArrayNotHasKey( 'complete', $verify['data'] );
		$this->assertSame( 0, (int) $wpdb->get_var( "SELECT COUNT(*) FROM wp_magicauth_passkey_challenges WHERE ceremony = 'complete' AND consumed_at IS NULL" ), 'no live completion token' );
	}

	public function test_other_users_tokens_survive_a_removal(): void {
		$other     = Ceremony::user( 8 );
		$auth      = new SoftAuthenticator( 'ES256', [ 'be' => true, 'bs' => true ] );
		$auth8     = new SoftAuthenticator( 'ES256', [ 'be' => true, 'bs' => true ] );
		$id        = Ceremony::enrol( $auth, $this->user );
		$other->user_login = 'learner8';
		Ceremony::enrol( $auth8, $other );

		$token8 = $this->held_token( $auth8 );

		Ceremony::sign_in( $this->user, 'link' );
		Ceremony::account_post( [ 'id' => (string) $id, 'signout_others' => '1' ] );
		$this->assertSame( 200, Ceremony::call( 'delete' )['status'] );

		$nav = $this->complete( $token8 );
		$this->assertArrayNotHasKey( 'magicauth_passkey_error', $nav['query'], $nav['location'] );
		$this->assertSame( 8, get_current_user_id() );
	}
}
