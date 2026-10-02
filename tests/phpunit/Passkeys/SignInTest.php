<?php
/**
 * T-AUTH at the endpoint level (SPEC 6.2, 6.3, 6.13, 7.4, 14.1, build step
 * 12): magicauth_passkey_signin_options, magicauth_passkey_signin and
 * magicauth_passkey_complete through SignInEndpoints with SoftAuthenticator
 * credentials, real challenge rows bound to the magicauth_pk_bind cookie, real
 * sessions through Login::establish() and MySQL changed-rows semantics.
 *
 * The verifier's per-check negatives (6 to 16d, 20, 21) are covered one by one
 * in SignInVerifierTest; here the gates, the binding cookie and its sliding
 * expiry, the failure throttle (counted only after A-3, never for a database
 * error), the response bodies (unknown_credential present only when flagged),
 * the status per code, the completion token and the completion navigation,
 * jitter, redirects and the signin_failed action. The endpoint counter cases
 * of T-AUTH 15 also run in the real-database suite (group realdb).
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Auth\Throttle;
use MagicAuth\Passkeys\Base64Url;
use MagicAuth\Passkeys\ChallengeStore;
use MagicAuth\Passkeys\Clock;
use MagicAuth\Passkeys\CredentialStore;
use MagicAuth\Passkeys\Freshness;
use MagicAuth\Passkeys\Module;
use MagicAuth\Passkeys\SignInEndpoints;
use MagicAuth\Tests\Stubs\JsonResponseSent;
use MagicAuth\Tests\Stubs\RedirectSent;
use MagicAuth\Tests\Support\Ceremony;
use MagicAuth\Tests\Support\SoftAuthenticator;
use PHPUnit\Framework\TestCase;
use WP_User;

final class SignInTest extends TestCase {

	private const IP = '203.0.113.10';

	private const RETURN_TO = 'https://academy.example.com/login/?ref=1';

	/** The other browser's binding cookie (login CSRF: the attacker's own). */
	private const OTHER_COOKIE = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210';

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
		$_SERVER['REMOTE_ADDR']                  = self::IP;
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
	 * A POST as the login script sends it: fields in $_POST, the Origin
	 * header (null: absent), the binding cookie (null: absent).
	 *
	 * @param array<string,mixed> $fields
	 * @param array<string,string> $headers Extra $_SERVER entries.
	 */
	private static function request( array $fields = [], ?string $origin = Ceremony::ORIGIN, ?string $cookie = Ceremony::COOKIE, array $headers = [] ): void {
		global $magicauth_test_state;
		$_SERVER['REQUEST_METHOD'] = 'POST';
		unset( $_SERVER['HTTP_ORIGIN'], $_SERVER['HTTP_REFERER'], $_SERVER['CONTENT_LENGTH'], $_SERVER['HTTP_SEC_FETCH_SITE'], $_SERVER['HTTP_SEC_FETCH_MODE'] );
		if ( null !== $origin ) {
			$_SERVER['HTTP_ORIGIN'] = $origin;
		}
		foreach ( $headers as $key => $value ) {
			$_SERVER[ $key ] = $value;
		}
		$_POST    = $fields;
		$_REQUEST = $fields;
		unset( $_COOKIE[ SignInEndpoints::BIND_COOKIE ] );
		if ( null !== $cookie ) {
			$_COOKIE[ SignInEndpoints::BIND_COOKIE ] = $cookie;
		}
		$magicauth_test_state['cookies'] = [];
		$magicauth_test_state['headers'] = [];
	}

	/**
	 * Calls a JSON handler; nothing else may be printed.
	 *
	 * @return array{status:?int,success:bool,data:array<string,mixed>,body:string}
	 */
	private static function json( string $handler ): array {
		global $wpdb;
		$wpdb->show_errors( true );
		ob_start();
		try {
			call_user_func( [ SignInEndpoints::class, $handler ] );
		} catch ( JsonResponseSent $sent ) {
			$out = (string) ob_get_clean();
			if ( '' !== $out ) {
				throw new \RuntimeException( 'printed before the JSON: ' . $out );
			}
			$payload = is_array( $sent->payload ) ? $sent->payload : [];
			return [
				'status'  => $sent->status,
				'success' => true === ( $payload['success'] ?? null ),
				'data'    => is_array( $payload['data'] ?? null ) ? $payload['data'] : [],
				'body'    => $sent->body,
			];
		} finally {
			$wpdb->show_errors( false );
		}
		ob_end_clean();
		throw new \RuntimeException( $handler . ' sent no response' );
	}

	/**
	 * Calls complete(); it must redirect (303) and print nothing.
	 *
	 * @return array{location:string,status:int,query:array<string,string>}
	 */
	private static function navigate(): array {
		global $wpdb;
		$wpdb->show_errors( true );
		ob_start();
		try {
			SignInEndpoints::complete();
		} catch ( RedirectSent $sent ) {
			$out = (string) ob_get_clean();
			if ( '' !== $out ) {
				throw new \RuntimeException( 'printed before the redirect: ' . $out );
			}
			parse_str( (string) wp_parse_url( $sent->location, PHP_URL_QUERY ), $query );
			return [
				'location' => $sent->location,
				'status'   => $sent->status,
				'query'    => $query,
			];
		} finally {
			$wpdb->show_errors( false );
		}
		ob_end_clean();
		throw new \RuntimeException( 'complete sent no redirect' );
	}

	/** @return array{status:?int,success:bool,data:array<string,mixed>,body:string} */
	private static function options( ?string $cookie = Ceremony::COOKIE ): array {
		self::request( [], Ceremony::ORIGIN, $cookie );
		return self::json( 'options' );
	}

	/** @return array<string,mixed> publicKey of a 200 signin_options. */
	private function public_key( ?string $cookie = Ceremony::COOKIE ): array {
		$response = self::options( $cookie );
		$this->assertSame( 200, $response['status'], $response['body'] );
		return $response['data']['publicKey'];
	}

	/** @param array<string,mixed> $o SoftAuthenticator overrides. */
	private function credential( SoftAuthenticator $auth, array $o = [], ?string $cookie = Ceremony::COOKIE ): string {
		return Ceremony::encode( $auth->assert( $this->public_key( $cookie ), Ceremony::ORIGIN, $o ) );
	}

	/**
	 * @param array<string,mixed> $extra More POST fields.
	 * @return array{status:?int,success:bool,data:array<string,mixed>,body:string}
	 */
	private static function verify( string $credential, ?string $cookie = Ceremony::COOKIE, ?string $origin = Ceremony::ORIGIN, array $extra = [] ): array {
		self::request( [ 'credential' => $credential ] + $extra, $origin, $cookie );
		return self::json( 'verify' );
	}

	/**
	 * @param array<string,string> $headers
	 * @return array{location:string,status:int,query:array<string,string>}
	 */
	private static function complete( string $token, ?string $cookie = Ceremony::COOKIE, ?string $origin = Ceremony::ORIGIN, string $redirect_to = '', array $headers = [] ): array {
		self::request(
			[
				'action'      => 'magicauth_passkey_complete',
				'token'       => $token,
				'redirect_to' => $redirect_to,
				'return_to'   => self::RETURN_TO,
			],
			$origin,
			$cookie,
			$headers
		);
		return self::navigate();
	}

	/** Device-bound authenticator enrolled for $user. */
	private static function enrolled( WP_User $user, string $alg = 'ES256', array $opts = [] ): SoftAuthenticator {
		$auth = new SoftAuthenticator(
			$alg,
			$opts + [
				'be' => false,
				'bs' => false,
			]
		);
		Ceremony::enrol( $auth, $user );
		return $auth;
	}

	/** A verified token for $auth (full options and verify through the endpoints). */
	private function token( SoftAuthenticator $auth, string $redirect_to = '' ): string {
		$response = self::verify( $this->credential( $auth ), Ceremony::COOKIE, Ceremony::ORIGIN, [ 'redirect_to' => $redirect_to ] );
		$this->assertSame( 200, $response['status'], $response['body'] );
		return (string) $response['data']['complete'];
	}

	/** @param array{status:?int,success:bool,data:array<string,mixed>,body:string} $response */
	private function assert_failed( array $response, string $code, int $status, bool $flag = false, string $label = '' ): void {
		$this->assertSame( $status, $response['status'], $label . ' ' . $response['body'] );
		$this->assertFalse( $response['success'], $label );
		$this->assertSame( $code, $response['data']['code'] ?? null, $label );
		$this->assertSame( self::message( $code ), $response['data']['message'] ?? null, $label . ': message' );
		if ( $flag ) {
			$this->assertTrue( $response['data']['unknown_credential'] ?? null, $label . ': flagged' );
		} else {
			$this->assertArrayNotHasKey( 'unknown_credential', $response['data'], $label . ': no flag key' );
		}
		$this->assertIsArray( json_decode( $response['body'], true ), 'valid JSON body' );
	}

	private static function message( string $code ): string {
		$strings = SignInEndpoints::strings();
		$map     = [
			'passkey_failed'    => 'L3',
			'throttled'         => 'L4',
			'other_account'     => 'L5',
			'retry'             => 'L6',
			'unavailable'       => 'L7',
			'reverify_required' => 'L8',
		];
		return $strings[ $map[ $code ] ];
	}

	/** @param array{location:string,status:int,query:array<string,string>} $nav */
	private function assert_returned( array $nav, string $code, string $label = '' ): void {
		$this->assertSame( 303, $nav['status'], $label );
		$this->assertStringStartsWith( 'https://academy.example.com/login/', $nav['location'], $label );
		$this->assertSame( $code, $nav['query']['magicauth_passkey_error'] ?? null, $label );
		$this->assertSame( '1', $nav['query']['ref'] ?? null, $label . ': return_to kept' );
		$this->assertSame( 0, get_current_user_id(), $label . ': nobody signed in' );
		$this->assertArrayNotHasKey( 'auth_cookies', $GLOBALS['magicauth_test_state'], $label . ': no auth cookie' );
	}

	private static function fail_count(): int {
		return (int) get_transient( 'magicauth_throttle_' . Throttle::ACTION_PASSKEY_FAIL_IP . '_' . magicauth_hash_ip( self::IP ) );
	}

	private static function rows( string $ceremony ): int {
		global $wpdb;
		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . ChallengeStore::table() . ' WHERE ceremony = %s', $ceremony ) );
	}

	/** @return array<int,array<string,mixed>> Cookies of the last request named $name. */
	private static function cookies( string $name ): array {
		return array_values(
			array_filter(
				$GLOBALS['magicauth_test_state']['cookies'] ?? [],
				static function ( array $c ) use ( $name ): bool {
					return $name === $c['name'];
				}
			)
		);
	}

	/** @param array<string,mixed> $cookie */
	private function assert_bind_cookie( array $cookie, string $value, int $max_age ): void {
		$this->assertSame( $value, $cookie['value'] );
		$this->assertSame( $max_age, $cookie['max_age'] );
		$this->assertSame( '/wp-admin/admin-ajax.php', $cookie['path'] );
		$this->assertSame( '', $cookie['domain'], 'host-only' );
		$this->assertTrue( $cookie['httponly'] );
		$this->assertTrue( $cookie['secure'] );
		$this->assertSame( 'Strict', $cookie['samesite'] );
	}

	/** @return array<int,string> Recorded magicauth_passkey_signin_failed calls as "reason:user". */
	private static function track_failures(): \ArrayObject {
		$seen = new \ArrayObject();
		add_action(
			'magicauth_passkey_signin_failed',
			static function ( $reason, $user_id ) use ( $seen ) {
				$seen[] = $reason . ':' . $user_id;
			},
			10,
			2
		);
		return $seen;
	}

	/* --------------------------------------------------- hooks and module off */

	public function test_signin_hooks_are_registered_for_logged_out_and_logged_in_browsers(): void {
		Module::register();
		foreach ( [ 'signin_options' => 'options', 'signin' => 'verify', 'complete' => 'complete' ] as $action => $method ) {
			foreach ( [ 'wp_ajax_nopriv_', 'wp_ajax_' ] as $prefix ) {
				$this->assertSame( 10, has_action( $prefix . 'magicauth_passkey_' . $action, [ SignInEndpoints::class, $method ] ), $prefix . $action );
			}
		}
	}

	public function test_1_module_off(): void {
		$auth       = self::enrolled( $this->user );
		$credential = $this->credential( $auth );
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => false ] );
		Module::reset_for_tests();

		$this->assert_failed( self::options(), 'unavailable', 404 );
		$this->assertSame( [], self::cookies( SignInEndpoints::BIND_COOKIE ), 'no cookie' );
		$this->assert_failed( self::verify( $credential ), 'unavailable', 404 );
		$this->assert_returned( self::complete( 'x' ), 'passkey_failed' );
	}

	public function test_1_unavailable_site(): void {
		update_option( 'magicauth_db_version', 1 );
		Module::reset_for_tests();
		$this->assert_failed( self::options(), 'unavailable', 404 );
	}

	/** @return array<string,array{string}> */
	public static function json_handlers(): array {
		return [
			'options' => [ 'options' ],
			'verify'  => [ 'verify' ],
		];
	}

	/** @dataProvider json_handlers */
	public function test_get_is_405( string $handler ): void {
		self::request();
		$_SERVER['REQUEST_METHOD'] = 'GET';
		$response                  = self::json( $handler );
		$this->assertSame( 405, $response['status'] );
		$this->assertSame( 'bad_request', $response['data']['code'] );
		$this->assertContains( 'Allow: POST', $GLOBALS['magicauth_test_state']['headers'] );
	}

	public function test_complete_get_is_405_json(): void {
		self::request();
		$_SERVER['REQUEST_METHOD'] = 'GET';
		$response                  = self::json( 'complete' );
		$this->assertSame( 405, $response['status'] );
	}

	/* ------------------------------------------------------------- options */

	public function test_options_shape_cookie_and_challenge_row(): void {
		$response = self::options( null );

		$this->assertSame( 200, $response['status'] );
		$this->assertTrue( $response['success'] );
		$this->assertSame( [ 'publicKey', 'refresh_after', 'ttl' ], array_keys( $response['data'] ) );
		$this->assertSame( 540, $response['data']['refresh_after'] );
		$this->assertSame( 600, $response['data']['ttl'] );
		$public_key = $response['data']['publicKey'];
		$this->assertSame( [ 'challenge', 'rpId', 'allowCredentials', 'userVerification', 'timeout' ], array_keys( $public_key ) );
		$this->assertSame( Ceremony::RP, $public_key['rpId'] );
		$this->assertSame( [], $public_key['allowCredentials'], 'usernameless, no enumeration' );
		$this->assertSame( 'required', $public_key['userVerification'] );
		$this->assertSame( 300000, $public_key['timeout'] );

		$cookies = self::cookies( SignInEndpoints::BIND_COOKIE );
		$this->assertCount( 1, $cookies );
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{64}$/', $cookies[0]['value'] );
		$this->assert_bind_cookie( $cookies[0], $cookies[0]['value'], 720 );

		// The row is bound to the new cookie and single-use.
		$raw = (string) Base64Url::decode( $public_key['challenge'], 32, 32 );
		$row = ChallengeStore::consume( 'signin', $raw );
		$this->assertNotNull( $row );
		$this->assertSame( ChallengeStore::binding_hash( $cookies[0]['value'] ), $row->binding_hash );
		$this->assertSame( '0', (string) $row->user_id );
		$this->assertSame( gmdate( 'Y-m-d H:i:s', Ceremony::NOW + 600 ), $row->expires_at );

		foreach ( [ 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private', 'Pragma: no-cache', 'X-Content-Type-Options: nosniff' ] as $line ) {
			$this->assertContains( $line, $GLOBALS['magicauth_test_state']['headers'] );
		}
	}

	public function test_options_reuses_a_valid_cookie_with_a_new_max_age(): void {
		self::options();
		$cookies = self::cookies( SignInEndpoints::BIND_COOKIE );
		$this->assertCount( 1, $cookies );
		$this->assert_bind_cookie( $cookies[0], Ceremony::COOKIE, 720 );
	}

	/** @return array<string,array{string}> */
	public static function malformed_cookies(): array {
		return [
			'upper case' => [ strtoupper( Ceremony::COOKIE ) ],
			'short'      => [ substr( Ceremony::COOKIE, 1 ) ],
			'long'       => [ Ceremony::COOKIE . '0' ],
			'non-hex'    => [ str_repeat( 'g', 64 ) ],
			'empty'      => [ '' ],
		];
	}

	/** @dataProvider malformed_cookies */
	public function test_options_replaces_a_malformed_cookie( string $cookie ): void {
		self::options( $cookie );
		$cookies = self::cookies( SignInEndpoints::BIND_COOKIE );
		$this->assertCount( 1, $cookies );
		$this->assertNotSame( $cookie, $cookies[0]['value'] );
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{64}$/', $cookies[0]['value'] );
	}

	public function test_options_works_for_a_logged_in_browser(): void {
		magicauth_test_login_as( 7 );
		$this->assertSame( 200, self::options()['status'] );
	}

	/** @return array<string,array{?string,array<string,string>}> */
	public static function bad_origins(): array {
		return [
			'missing'            => [ null, [] ],
			'foreign'            => [ 'https://evil.example', [] ],
			'null'               => [ 'null', [] ],
			'null with metadata' => [
				'null',
				[
					'HTTP_SEC_FETCH_SITE' => 'same-origin',
					'HTTP_SEC_FETCH_MODE' => 'navigate',
				],
			],
			'subdomain'          => [ 'https://www.academy.example.com', [] ],
			'http'               => [ 'http://academy.example.com', [] ],
		];
	}

	/**
	 * @dataProvider bad_origins
	 * @param array<string,string> $headers
	 */
	public function test_options_origin_gate( ?string $origin, array $headers ): void {
		self::request( [], $origin, Ceremony::COOKIE, $headers );
		$this->assert_failed( self::json( 'options' ), 'passkey_failed', 403 );
		$this->assertSame( 0, self::rows( 'signin' ) );
		$this->assertSame( [], self::cookies( SignInEndpoints::BIND_COOKIE ) );
		$this->assertFalse( get_transient( 'magicauth_throttle_' . Throttle::ACTION_PASSKEY_OPTS_GLOBAL . '_all' ), 'not counted' );
	}

	public function test_options_global_ceiling_is_429_without_an_insert(): void {
		global $wpdb;
		set_transient( 'magicauth_throttle_' . Throttle::ACTION_PASSKEY_OPTS_GLOBAL . '_all', 5000, 600 );
		$wpdb->query_log = [];

		$this->assert_failed( self::options(), 'throttled', 429 );
		$this->assertSame( 0, self::rows( 'signin' ) );
		$this->assertSame( [], self::cookies( SignInEndpoints::BIND_COOKIE ) );
		foreach ( $wpdb->query_log as $sql ) {
			$this->assertStringNotContainsString( 'INSERT INTO ' . strtoupper( ChallengeStore::table() ), strtoupper( (string) $sql ) );
		}
		// The network check runs first (r1-endpoints-01) and passed.
		$this->assertSame( 1, (int) get_transient( 'magicauth_throttle_' . Throttle::ACTION_PASSKEY_OPTS_IP . '_' . magicauth_hash_ip( self::IP ) ), 'per-network bucket counted once' );
	}

	public function test_options_per_network_limit(): void {
		set_transient( 'magicauth_throttle_' . Throttle::ACTION_PASSKEY_OPTS_IP . '_' . magicauth_hash_ip( self::IP ), 300, 600 );
		$this->assert_failed( self::options(), 'throttled', 429 );
		$this->assertSame( 0, self::rows( 'signin' ) );
		$this->assertFalse( get_transient( 'magicauth_throttle_' . Throttle::ACTION_PASSKEY_OPTS_GLOBAL . '_all' ), 'a refused network never counts toward the global ceiling' );

		// Another /64 is another bucket.
		$_SERVER['REMOTE_ADDR'] = '2001:db8:1:2::5';
		$this->assertSame( 200, self::options()['status'] );
	}

	public function test_options_purges_up_to_20_expired_rows_first(): void {
		for ( $i = 0; $i < 25; $i++ ) {
			ChallengeStore::issue( 'signin', 0, '', Ceremony::COOKIE, '', 60 );
		}
		Clock::set_for_tests( Ceremony::NOW + 61 );
		self::options();
		$this->assertSame( 6, self::rows( 'signin' ), '25 expired, 20 purged, 1 new' );
	}

	public function test_options_insert_error_is_retry(): void {
		global $wpdb;
		$wpdb->fail_next_query( 'INSERT INTO ' . ChallengeStore::table() );
		$this->assert_failed( self::options(), 'retry', 503 );
		$this->assertSame( [], self::cookies( SignInEndpoints::BIND_COOKIE ) );
	}

	public function test_options_has_no_jitter(): void {
		self::options();
		$this->assertSame( 0, $GLOBALS['magicauth_test_state']['jitter_calls'] ?? 0 );
	}

	/* -------------------------------------------------------------- verify */

	/** @return array<string,array{string}> */
	public static function algs(): array {
		return [
			'ES256' => [ 'ES256' ],
			'RS256' => [ 'RS256' ],
			'EdDSA' => [ 'EdDSA' ],
		];
	}

	/** @dataProvider algs */
	public function test_22_verify_returns_a_bound_completion_token_and_sets_no_auth_cookie( string $alg ): void {
		$auth = self::enrolled( $this->user, $alg );
		$used = [];
		add_action(
			'magicauth_passkey_used',
			static function ( $uid, $id ) use ( &$used ) {
				$used[] = [ $uid, $id ];
			},
			10,
			2
		);
		$credential = $this->credential( $auth );
		Clock::set_for_tests( Ceremony::NOW + 30 );

		$response = self::verify( $credential, Ceremony::COOKIE, Ceremony::ORIGIN, [ 'redirect_to' => 'https://academy.example.com/courses/root-acces-nl/lessen/3/' ] );

		$this->assertSame( 200, $response['status'], $response['body'] );
		$this->assertSame( [ 'complete', 'redirect' ], array_keys( $response['data'] ) );
		$this->assertSame( 'https://academy.example.com/courses/root-acces-nl/lessen/3/', $response['data']['redirect'] );
		$token = Base64Url::decode( (string) $response['data']['complete'], 32, 32 );
		$this->assertNotNull( $token );

		// No session yet: only the completion navigation establishes it.
		$this->assertSame( 0, get_current_user_id() );
		$this->assertArrayNotHasKey( 'auth_cookies', $GLOBALS['magicauth_test_state'] );
		$this->assertSame( [], self::cookies( Freshness::COOKIE ) );

		// The bind cookie is re-sent: same value, new Max-Age (5.3).
		$cookies = self::cookies( SignInEndpoints::BIND_COOKIE );
		$this->assertCount( 1, $cookies );
		$this->assert_bind_cookie( $cookies[0], Ceremony::COOKIE, 720 );

		$row = ChallengeStore::consume( 'complete', $token );
		$this->assertNotNull( $row );
		$this->assertSame( '7', (string) $row->user_id );
		$this->assertSame( ChallengeStore::binding_hash( Ceremony::COOKIE ), $row->binding_hash );
		$this->assertSame( gmdate( 'Y-m-d H:i:s', Ceremony::NOW + 30 + 120 ), $row->expires_at );

		$this->assertCount( 1, $used );
		$this->assertSame( 7, $used[0][0] );
		$stored = Ceremony::row( (int) $used[0][1] );
		$this->assertNotNull( $stored );
		$this->assertSame( gmdate( 'Y-m-d H:i:s', Ceremony::NOW + 30 ), $stored['last_used_at'], 'usage recorded' );
		$this->assertSame( 0, self::fail_count(), 'a success is never counted' );
	}

	/** @dataProvider bad_origins */
	public function test_2_origin_gate( ?string $origin, array $headers ): void {
		$auth       = self::enrolled( $this->user );
		$credential = $this->credential( $auth );
		self::request( [ 'credential' => $credential ], $origin, Ceremony::COOKIE, $headers );
		$this->assert_failed( self::json( 'verify' ), 'passkey_failed', 400 );
		$this->assertSame( 0, self::fail_count(), 'not counted' );

		// Origin alone decided: the challenge was not consumed, the same assertion still works.
		$this->assertSame( 200, self::verify( $credential )['status'] );
	}

	/** @return array<string,array{?string}> */
	public static function bad_bind_cookies(): array {
		return [
			'missing'       => [ null ],
			'malformed'     => [ 'not-a-cookie' ],
			'upper case'    => [ strtoupper( Ceremony::COOKIE ) ],
			'other browser' => [ self::OTHER_COOKIE ],
		];
	}

	/** @dataProvider bad_bind_cookies */
	public function test_3_binding_cookie( ?string $cookie ): void {
		$auth       = self::enrolled( $this->user );
		$credential = $this->credential( $auth );
		$seen       = self::track_failures();

		$this->assert_failed( self::verify( $credential, $cookie ), 'passkey_failed', 400 );
		$this->assertSame( 0, self::fail_count(), 'unbound: not counted' );
		$this->assertSame( [ 'binding:0' ], $seen->getArrayCopy() );
		$this->assertSame( [], self::cookies( SignInEndpoints::BIND_COOKIE ), 'a failed verify re-sends nothing' );

		// Burnt whatever the outcome.
		$this->assert_failed( self::verify( $credential ), 'passkey_failed', 400, false, 'replay with the right cookie' );
	}

	/** 3c: valid Origin, the attacker's own binding cookie: rejected at A-3 by the binding alone. */
	public function test_3c_binding_alone_rejects_login_csrf(): void {
		$auth       = self::enrolled( $this->user );
		$credential = $this->credential( $auth, [], self::OTHER_COOKIE );
		$this->assert_failed( self::verify( $credential, Ceremony::COOKIE ), 'passkey_failed', 400 );
		$this->assertSame( 0, self::rows( 'complete' ) );
	}

	/** 3d: matching binding cookie, foreign Origin: rejected by the Origin alone. */
	public function test_3d_origin_alone_rejects_login_csrf(): void {
		$auth       = self::enrolled( $this->user );
		$credential = $this->credential( $auth );
		$this->assert_failed( self::verify( $credential, Ceremony::COOKIE, 'https://evil.example' ), 'passkey_failed', 400 );
		$this->assertSame( 0, self::rows( 'complete' ) );
	}

	/** 3b: options at 0, again at 540 with the cookie, verify at 700 against the second challenge. */
	public function test_3b_sliding_cookie_across_a_refresh(): void {
		$auth = self::enrolled( $this->user );
		self::options();
		$this->assert_bind_cookie( self::cookies( SignInEndpoints::BIND_COOKIE )[0], Ceremony::COOKIE, 720 );

		Clock::set_for_tests( Ceremony::NOW + 540 );
		$public_key = $this->public_key();
		$cookie     = self::cookies( SignInEndpoints::BIND_COOKIE )[0];
		$this->assert_bind_cookie( $cookie, Ceremony::COOKIE, 720 );
		$this->assertSame( Ceremony::NOW + 540 + 720, $cookie['expires'] );

		Clock::set_for_tests( Ceremony::NOW + 700 );
		$credential = Ceremony::encode( $auth->assert( $public_key, Ceremony::ORIGIN ) );
		$this->assertSame( 200, self::verify( $credential )['status'] );
	}

	/** 3b: options at 0, verify at 595 re-sends the cookie, complete at 700 succeeds. */
	public function test_3b_verify_re_sends_the_cookie_for_the_completion(): void {
		$auth       = self::enrolled( $this->user );
		$credential = $this->credential( $auth );

		Clock::set_for_tests( Ceremony::NOW + 595 );
		$response = self::verify( $credential );
		$this->assertSame( 200, $response['status'], $response['body'] );
		$cookie = self::cookies( SignInEndpoints::BIND_COOKIE )[0];
		$this->assert_bind_cookie( $cookie, Ceremony::COOKIE, 720 );
		$this->assertSame( Ceremony::NOW + 595 + 720, $cookie['expires'], 'outlives the completion row (595 + 120)' );

		Clock::set_for_tests( Ceremony::NOW + 700 );
		$nav = self::complete( (string) $response['data']['complete'] );
		$this->assertSame( 303, $nav['status'] );
		$this->assertArrayNotHasKey( 'magicauth_passkey_error', $nav['query'] );
		$this->assertSame( 7, get_current_user_id() );
	}

	/** @return array<string,array{string}> */
	public static function challenge_cases(): array {
		return [
			'unknown'  => [ 'unknown' ],
			'expired'  => [ 'expired' ],
			'replayed' => [ 'replayed' ],
			'register' => [ 'register' ],
		];
	}

	/** @dataProvider challenge_cases */
	public function test_4_challenge( string $case ): void {
		$auth = self::enrolled( $this->user );
		switch ( $case ) {
			case 'unknown':
				$credential = Ceremony::encode( $auth->assert( [ 'challenge' => Base64Url::encode( random_bytes( 32 ) ) ] + $this->public_key(), Ceremony::ORIGIN ) );
				break;
			case 'expired':
				$credential = $this->credential( $auth );
				Clock::set_for_tests( Ceremony::NOW + 600 );
				break;
			case 'replayed':
				$credential = $this->credential( $auth );
				$this->assertSame( 200, self::verify( $credential )['status'] );
				break;
			default:
				$issued     = Ceremony::register_options( $this->user );
				$credential = Ceremony::encode( $auth->assert( [ 'challenge' => Base64Url::encode( $issued['challenge'] ) ] + $this->public_key(), Ceremony::ORIGIN ) );
		}
		$this->assert_failed( self::verify( $credential ), 'passkey_failed', 400 );
		$this->assertSame( 0, self::fail_count(), 'no consumed bound challenge: not counted' );
	}

	public function test_5_junk_posts_without_a_challenge_never_move_the_failure_counter(): void {
		$auth = self::enrolled( $this->user );
		for ( $i = 0; $i < 100; $i++ ) {
			$junk = Ceremony::encode( $auth->assert( [ 'challenge' => Base64Url::encode( random_bytes( 32 ) ) ] + \MagicAuth\Passkeys\Options::request( random_bytes( 32 ) ), Ceremony::ORIGIN ) );
			self::verify( 0 === $i % 2 ? $junk : 'junk' );
		}
		$this->assertSame( 0, self::fail_count() );
		$this->assertSame( 200, self::verify( $this->credential( $auth ) )['status'] );
	}

	public function test_5_the_31st_bound_consumed_failure_blocks(): void {
		$auth = self::enrolled( $this->user );
		for ( $i = 1; $i <= 30; $i++ ) {
			$this->assert_failed( self::verify( $this->credential( $auth, [ 'signature' => random_bytes( 70 ) ] ) ), 'passkey_failed', 400, false, "failure {$i}" );
		}
		$this->assertSame( 30, self::fail_count() );

		$credential = $this->credential( $auth );
		$seen       = self::track_failures();
		$this->assert_failed( self::verify( $credential ), 'throttled', 429 );
		$this->assertSame( [ 'throttled:0' ], $seen->getArrayCopy() );
		$this->assertSame( 30, self::fail_count(), 'a peek, not an increment' );

		// Other networks are unaffected.
		$_SERVER['REMOTE_ADDR'] = '198.51.100.7';
		$this->assertSame( 200, self::verify( $credential )['status'], 'the throttled request did not burn the challenge' );
	}

	public function test_5_database_errors_are_not_counted(): void {
		global $wpdb;
		$auth       = self::enrolled( $this->user );
		$credential = $this->credential( $auth );
		$wpdb->fail_next_query( 'SELECT * FROM ' . CredentialStore::table() );
		$this->assert_failed( self::verify( $credential ), 'retry', 503 );
		$this->assertSame( 0, self::fail_count() );
	}

	public function test_6_body_and_field_caps(): void {
		$auth       = self::enrolled( $this->user );
		$credential = $this->credential( $auth );

		self::request( [ 'credential' => $credential ] );
		$_SERVER['CONTENT_LENGTH'] = '65537';
		$this->assert_failed( self::json( 'verify' ), 'passkey_failed', 400 );

		$this->assert_failed( self::verify( str_pad( $credential, 24577 ) ), 'passkey_failed', 400 );
		$this->assertSame( 0, self::fail_count() );
		$this->assertSame( 200, self::verify( $credential )['status'], 'caps run before the challenge is consumed' );
	}

	public function test_6_credential_absent_or_an_array(): void {
		self::request( [] );
		$this->assert_failed( self::json( 'verify' ), 'passkey_failed', 400 );
		self::request( [ 'credential' => [ 'a' ] ] );
		$this->assert_failed( self::json( 'verify' ), 'passkey_failed', 400 );
	}

	/** @return array<string,array{\Closure}> */
	public static function malformed(): array {
		return [
			'not JSON'           => [ static fn( array $c ) => 'nope' ],
			'missing userHandle' => [
				static function ( array $c ) {
					unset( $c['response']['userHandle'] );
					return $c;
				},
			],
			'userHandle 65'      => [
				static function ( array $c ) {
					$c['response']['userHandle'] = Base64Url::encode( str_repeat( 'h', 65 ) );
					return $c;
				},
			],
		];
	}

	/** @dataProvider malformed */
	public function test_7_malformed_is_generic( \Closure $mutate ): void {
		$auth       = self::enrolled( $this->user );
		$credential = $mutate( Ceremony::decode( $this->credential( $auth ) ) );
		$this->assert_failed( self::verify( is_string( $credential ) ? $credential : Ceremony::encode( $credential ) ), 'passkey_failed', 400 );
		$this->assertSame( 0, self::fail_count() );
	}

	public function test_8_unknown_credential_with_an_issued_handle_is_flagged_and_counted(): void {
		$stray = new SoftAuthenticator( 'ES256', [ 'user_handle' => (string) Base64Url::decode( (string) CredentialStore::user_handle( 7, true ), 1, 64 ) ] );
		$seen  = self::track_failures();
		$this->assert_failed( self::verify( $this->credential( $stray ) ), 'passkey_failed', 400, true );
		$this->assertSame( 1, self::fail_count() );
		$this->assertSame( [ 'unknown_credential:0' ], $seen->getArrayCopy() );
	}

	public function test_8_unknown_credential_with_a_bad_client_origin_is_not_flagged(): void {
		$stray = new SoftAuthenticator( 'ES256', [ 'user_handle' => (string) Base64Url::decode( (string) CredentialStore::user_handle( 7, true ), 1, 64 ) ] );
		$this->assert_failed( self::verify( $this->credential( $stray, [ 'origin' => 'https://evil.example' ] ) ), 'passkey_failed', 400 );
	}

	public function test_8c_unknown_credential_with_a_foreign_handle_is_not_flagged(): void {
		$stray = new SoftAuthenticator( 'ES256', [ 'user_handle' => random_bytes( 64 ) ] );
		$this->assert_failed( self::verify( $this->credential( $stray ) ), 'passkey_failed', 400 );
	}

	public function test_8c_handle_lookup_error_is_retry(): void {
		global $wpdb;
		$stray      = new SoftAuthenticator( 'ES256', [ 'user_handle' => (string) Base64Url::decode( (string) CredentialStore::user_handle( 7, true ), 1, 64 ) ] );
		$credential = $this->credential( $stray );
		$wpdb->fail_next_query( 'SELECT user_id FROM wp_usermeta' );
		$this->assert_failed( self::verify( $credential ), 'retry', 503 );
		$this->assertSame( 0, self::fail_count() );
	}

	public function test_8b_lookup_error_is_retry_without_flag(): void {
		global $wpdb;
		$stray      = new SoftAuthenticator( 'ES256', [ 'user_handle' => (string) Base64Url::decode( (string) CredentialStore::user_handle( 7, true ), 1, 64 ) ] );
		$credential = $this->credential( $stray );
		$wpdb->fail_next_query( 'SELECT * FROM ' . CredentialStore::table() . ' WHERE credential_hash' );
		$this->assert_failed( self::verify( $credential ), 'retry', 503 );
	}

	public function test_11_bad_signature_is_generic_and_counted_with_the_user(): void {
		$auth = self::enrolled( $this->user );
		$seen = self::track_failures();
		$this->assert_failed( self::verify( $this->credential( $auth, [ 'signature' => random_bytes( 70 ) ] ) ), 'passkey_failed', 400 );
		$this->assertSame( 1, self::fail_count() );
		$this->assertSame( [ 'signature:7' ], $seen->getArrayCopy() );
	}

	/**
	 * T-AUTH 15 through the endpoint: a device-bound counter regression blocks
	 * the credential, a blocked credential stays rejected with a higher counter.
	 *
	 * @group realdb
	 */
	public function test_15_counter_regression_blocks_through_the_endpoint(): void {
		$auth = self::enrolled( $this->user, 'ES256', [ 'sign_count' => 10 ] );
		$this->assertSame( 200, self::verify( $this->credential( $auth ) )['status'] );
		$this->assert_failed( self::verify( $this->credential( $auth, [ 'sign_count' => 5 ] ) ), 'passkey_failed', 400 );
		$this->assert_failed( self::verify( $this->credential( $auth, [ 'sign_count' => 50 ] ) ), 'passkey_failed', 400, false, 'blocked stays blocked' );
		$this->assertSame( 2, self::fail_count() );

		// The blocked email (10.5) went once, from the request that blocked it (build step 13).
		global $magicauth_test_state;
		$blocked = array_values(
			array_filter(
				$magicauth_test_state['mail'] ?? [],
				static fn( array $m ): bool => false !== strpos( (string) $m['subject'], 'was blocked' )
			)
		);
		$this->assertCount( 1, $blocked );
		$this->assertSame( 'learner7@example.test', $blocked[0]['to'] );
		$this->assertStringContainsString( 'because it may have been copied', $blocked[0]['alt_body'] );
	}

	/** @group realdb */
	public function test_15_counter_write_error_is_retry(): void {
		global $wpdb;
		$auth       = self::enrolled( $this->user, 'ES256', [ 'sign_count' => 3 ] );
		$credential = $this->credential( $auth );
		$wpdb->fail_next_query( 'SET sign_count' );
		$this->assert_failed( self::verify( $credential ), 'retry', 503 );
		$this->assertSame( 0, self::fail_count() );
		$this->assertSame( 0, self::rows( 'complete' ) );
	}

	/** @return array<string,array{string}> */
	public static function denied_accounts(): array {
		return [
			'disabled' => [ 'disabled' ],
			'deleted'  => [ 'deleted' ],
			'filter'   => [ 'filter' ],
		];
	}

	/** @dataProvider denied_accounts */
	public function test_16_account_state_is_generic( string $case ): void {
		global $magicauth_test_state;
		$auth       = self::enrolled( $this->user );
		$credential = $this->credential( $auth );
		if ( 'disabled' === $case ) {
			update_user_meta( 7, 'magicauth_disabled', 1 );
		} elseif ( 'deleted' === $case ) {
			unset( $magicauth_test_state['users'][7] );
		} else {
			add_filter( 'magicauth_allow_login', static fn() => false );
		}
		$this->assert_failed( self::verify( $credential ), 'passkey_failed', 400 );
		$this->assertSame( 0, self::rows( 'complete' ) );
	}

	public function test_17_same_user_signed_in_completes_without_a_new_session(): void {
		$auth  = self::enrolled( $this->user );
		$token = Ceremony::sign_in( $this->user, 'link', Ceremony::NOW, true, false );
		unset( $GLOBALS['magicauth_test_state']['auth_cookies'] );
		$sessions = $GLOBALS['magicauth_test_state']['sessions'][7] ?? [];

		$complete = $this->token( $auth );
		$nav      = self::complete( $complete );

		$this->assertSame( 303, $nav['status'] );
		$this->assertArrayNotHasKey( 'magicauth_passkey_error', $nav['query'] );
		$this->assertArrayNotHasKey( 'auth_cookies', $GLOBALS['magicauth_test_state'], 'ALREADY: no cookie' );
		$this->assertSame( $sessions, $GLOBALS['magicauth_test_state']['sessions'][7] ?? [], 'no new session' );
		$this->assertSame( $token, wp_get_session_token() );
		$deleted = self::cookies( SignInEndpoints::BIND_COOKIE );
		$this->assertCount( 1, $deleted );
		$this->assert_bind_cookie( $deleted[0], '', 0 );
	}

	public function test_17_other_user_signed_in_is_409_without_state_change(): void {
		$auth = self::enrolled( $this->user, 'ES256', [ 'sign_count' => 4 ] );
		Ceremony::user( 8 );
		magicauth_test_login_as( 8 );
		$id         = (int) CredentialStore::find_by_raw_id( $auth->credentialId() )->id;
		$credential = $this->credential( $auth );

		$this->assert_failed( self::verify( $credential ), 'other_account', 409 );
		$row = Ceremony::row( $id );
		$this->assertNotNull( $row );
		$this->assertSame( '4', (string) $row['sign_count'] );
		$this->assertNull( $row['last_used_at'] );
		$this->assertSame( 0, self::rows( 'complete' ) );
		$this->assertSame( 8, get_current_user_id(), 'no session swap' );
	}

	/**
	 * r1-endpoints-05: other_account and reverify_required follow a valid
	 * signature by the key holder; they never count toward passkey_fail_ip,
	 * so a NAT full of lapsed rule E users does not block everyone on it.
	 */
	public function test_valid_assertions_refused_by_preflight_are_not_counted(): void {
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => true, 'passkeys_email_reverify_days' => 30, 'throttle' => [ 'per_ip_passkey_max' => 2 ] ] );
		$auth = self::enrolled( $this->user );
		for ( $i = 0; $i < 3; $i++ ) {
			$this->assert_failed( self::verify( $this->credential( $auth ) ), 'reverify_required', 403 );
		}
		$this->assertSame( 0, self::fail_count(), 'rule E not counted' );

		update_user_meta( 7, 'magicauth_email_verified_at', Ceremony::NOW );
		Ceremony::user( 8 );
		magicauth_test_login_as( 8 );
		for ( $i = 0; $i < 3; $i++ ) {
			$this->assert_failed( self::verify( $this->credential( $auth ) ), 'other_account', 409 );
		}
		$this->assertSame( 0, self::fail_count(), 'other_account not counted' );
		$this->assertFalse( Throttle::passkey_signin_blocked( magicauth_hash_ip( self::IP ) ) );
	}

	public function test_18_rule_e(): void {
		$auth = self::enrolled( $this->user );
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => true, 'passkeys_email_reverify_days' => 30 ] );

		$this->assert_failed( self::verify( $this->credential( $auth ) ), 'reverify_required', 403, false, 'missing counts as 0' );

		update_user_meta( 7, 'magicauth_email_verified_at', Ceremony::NOW - 30 * DAY_IN_SECONDS - 1 );
		$this->assert_failed( self::verify( $this->credential( $auth ) ), 'reverify_required', 403, false, 'one second over' );

		update_user_meta( 7, 'magicauth_email_verified_at', Ceremony::NOW - 30 * DAY_IN_SECONDS );
		$this->assertSame( 200, self::verify( $this->credential( $auth ) )['status'], 'at the boundary' );
	}

	public function test_18_duplicate_email_account_gets_passkey_failed_not_l8(): void {
		$auth = self::enrolled( $this->user );
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => true, 'passkeys_email_reverify_days' => 30 ] );
		// Another account holds the same address and is found first by email (T22).
		global $magicauth_test_state;
		$magicauth_test_state['users'] = [ 3 => new WP_User( 3, 'learner7@example.test', [ 'subscriber' ] ) ] + $magicauth_test_state['users'];
		$this->assert_failed( self::verify( $this->credential( $auth ) ), 'passkey_failed', 400 );
	}

	/** @return array<string,array{string}> */
	public static function bad_redirects(): array {
		return [
			'foreign host' => [ 'https://evil.example/' ],
			'wp-login'     => [ 'https://academy.example.com/wp-login.php?action=magicauth' ],
			'javascript'   => [ 'javascript:alert(1)' ],
		];
	}

	/** @dataProvider bad_redirects */
	public function test_19_redirect_to_falls_back_to_home( string $redirect_to ): void {
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => true, 'redirect_to_default' => 'home' ] );
		$auth     = self::enrolled( $this->user );
		$response = self::verify( $this->credential( $auth ), Ceremony::COOKIE, Ceremony::ORIGIN, [ 'redirect_to' => $redirect_to ] );
		$this->assertSame( 'https://academy.example.com/', $response['data']['redirect'] );
	}

	public function test_19_filter_gets_passkey_and_a_foreign_result_falls_back(): void {
		$methods = [];
		add_filter(
			'magicauth_redirect_to',
			static function ( $target, $user, $context, $method ) use ( &$methods ) {
				$methods[] = $method;
				return 'https://evil.example/';
			},
			10,
			4
		);
		$auth  = self::enrolled( $this->user );
		$token = $this->token( $auth );
		$nav   = self::complete( $token, Ceremony::COOKIE, Ceremony::ORIGIN, 'https://academy.example.com/x/' );

		$this->assertSame( [ 'passkey', 'passkey' ], $methods, 'verify and complete' );
		$this->assertSame( 'https://academy.example.com/', $nav['location'] );
	}

	public function test_23_jitter_once_per_response(): void {
		global $magicauth_test_state;
		$auth = self::enrolled( $this->user );

		$credential                           = $this->credential( $auth );
		$magicauth_test_state['jitter_calls'] = 0;
		$response                             = self::verify( $credential );
		$this->assertSame( 1, $magicauth_test_state['jitter_calls'], 'verify success' );

		$magicauth_test_state['jitter_calls'] = 0;
		self::verify( 'junk' );
		$this->assertSame( 1, $magicauth_test_state['jitter_calls'], 'verify failure' );

		$magicauth_test_state['jitter_calls'] = 0;
		self::verify( 'junk', Ceremony::COOKIE, 'https://evil.example' );
		$this->assertSame( 1, $magicauth_test_state['jitter_calls'], 'verify gate failure' );

		$magicauth_test_state['jitter_calls'] = 0;
		self::complete( (string) $response['data']['complete'] );
		$this->assertSame( 1, $magicauth_test_state['jitter_calls'], 'complete success' );

		$magicauth_test_state['jitter_calls'] = 0;
		self::complete( 'junk' );
		$this->assertSame( 1, $magicauth_test_state['jitter_calls'], 'complete failure' );
	}

	/* ------------------------------------------------------------ complete */

	public function test_24_complete_establishes_the_session_and_redirects_303(): void {
		global $magicauth_test_state;
		$auth   = self::enrolled( $this->user );
		$token  = $this->token( $auth );
		$logins = [];
		add_action(
			'wp_login',
			static function ( $login ) use ( &$logins ) {
				$logins[] = $login;
			}
		);

		$nav = self::complete( $token, Ceremony::COOKIE, Ceremony::ORIGIN, 'https://academy.example.com/courses/root-acces-nl/lessen/3/#notes' );

		$this->assertSame( 303, $nav['status'] );
		$this->assertSame( 'https://academy.example.com/courses/root-acces-nl/lessen/3/#notes', $nav['location'] );
		$this->assertSame( 7, get_current_user_id() );
		$this->assertSame( [ 'learner7' ], $logins );
		$this->assertCount( 1, $magicauth_test_state['auth_cookies'] );

		$sessions = array_values( $magicauth_test_state['sessions'][7] );
		$this->assertCount( 1, $sessions );
		$this->assertSame( 'passkey', $sessions[0]['magicauth_method'] );

		// Bind cookie deleted with the same attributes; a fresh cookie for the passkey session.
		$deleted = self::cookies( SignInEndpoints::BIND_COOKIE );
		$this->assertCount( 1, $deleted );
		$this->assert_bind_cookie( $deleted[0], '', 0 );
		$this->assertCount( 1, self::cookies( Freshness::COOKIE ) );

		foreach ( [ 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private', 'Pragma: no-cache' ] as $line ) {
			$this->assertContains( $line, $magicauth_test_state['headers'] );
		}
	}

	public function test_24_navigation_origin_null_with_same_origin_fetch_metadata(): void {
		$auth  = self::enrolled( $this->user );
		$token = $this->token( $auth );
		$nav   = self::complete(
			$token,
			Ceremony::COOKIE,
			'null',
			'',
			[
				'HTTP_SEC_FETCH_SITE' => 'same-origin',
				'HTTP_SEC_FETCH_MODE' => 'navigate',
			]
		);
		$this->assertArrayNotHasKey( 'magicauth_passkey_error', $nav['query'] );
		$this->assertSame( 7, get_current_user_id() );
	}

	public function test_24_navigation_referer_only(): void {
		$auth  = self::enrolled( $this->user );
		$token = $this->token( $auth );
		self::complete( $token, Ceremony::COOKIE, null, '', [ 'HTTP_REFERER' => self::RETURN_TO ] );
		$this->assertSame( 7, get_current_user_id() );
	}

	/** @return array<string,array{?string,array<string,string>}> */
	public static function bad_navigation_origins(): array {
		return [
			'foreign'                => [ 'https://evil.example', [] ],
			'missing'                => [ null, [] ],
			'null cross-site'        => [
				'null',
				[
					'HTTP_SEC_FETCH_SITE' => 'cross-site',
					'HTTP_SEC_FETCH_MODE' => 'navigate',
				],
			],
			'null same-site'         => [
				'null',
				[
					'HTTP_SEC_FETCH_SITE' => 'same-site',
					'HTTP_SEC_FETCH_MODE' => 'navigate',
				],
			],
			'null without metadata'  => [ 'null', [] ],
			'null same-origin, cors' => [
				'null',
				[
					'HTTP_SEC_FETCH_SITE' => 'same-origin',
					'HTTP_SEC_FETCH_MODE' => 'cors',
				],
			],
		];
	}

	/**
	 * @dataProvider bad_navigation_origins
	 * @param array<string,string> $headers
	 */
	public function test_24_navigation_origin_gate( ?string $origin, array $headers ): void {
		$auth  = self::enrolled( $this->user );
		$token = $this->token( $auth );
		$this->assert_returned( self::complete( $token, Ceremony::COOKIE, $origin, '', $headers ), 'passkey_failed' );

		// The Origin decided alone: the token was not consumed.
		$nav = self::complete( $token );
		$this->assertArrayNotHasKey( 'magicauth_passkey_error', $nav['query'] );
	}

	/** @return array<string,array{string}> */
	public static function bad_tokens(): array {
		return [
			'replay'         => [ 'replay' ],
			'foreign cookie' => [ 'foreign cookie' ],
			'no cookie'      => [ 'no cookie' ],
			'expired'        => [ 'expired' ],
			'malformed'      => [ 'malformed' ],
			'unknown'        => [ 'unknown' ],
			'signin token'   => [ 'signin token' ],
		];
	}

	/** @dataProvider bad_tokens */
	public function test_24_bad_token_returns_with_retry( string $case ): void {
		$auth   = self::enrolled( $this->user );
		$token  = $this->token( $auth );
		$cookie = Ceremony::COOKIE;
		switch ( $case ) {
			case 'replay':
				self::complete( $token );
				wp_set_current_user( 0 );
				unset( $GLOBALS['magicauth_test_state']['auth_cookies'] );
				break;
			case 'foreign cookie':
				$cookie = self::OTHER_COOKIE;
				break;
			case 'no cookie':
				$cookie = null;
				break;
			case 'expired':
				Clock::set_for_tests( Ceremony::NOW + 120 );
				break;
			case 'malformed':
				$token = $token . 'A';
				break;
			case 'unknown':
				$token = Base64Url::encode( random_bytes( 32 ) );
				break;
			default:
				$token = (string) $this->public_key()['challenge'];
		}
		$this->assert_returned( self::complete( $token, $cookie ), 'retry', $case );
	}

	public function test_24_disabled_between_verify_and_complete(): void {
		$auth  = self::enrolled( $this->user );
		$token = $this->token( $auth );
		update_user_meta( 7, 'magicauth_disabled', 1 );
		$this->assert_returned( self::complete( $token ), 'passkey_failed' );
	}

	public function test_24_deleted_between_verify_and_complete(): void {
		$auth  = self::enrolled( $this->user );
		$token = $this->token( $auth );
		unset( $GLOBALS['magicauth_test_state']['users'][7] );
		$this->assert_returned( self::complete( $token ), 'passkey_failed' );
	}

	public function test_24_rule_e_turned_on_between_verify_and_complete(): void {
		$auth  = self::enrolled( $this->user );
		$token = $this->token( $auth );
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => true, 'passkeys_email_reverify_days' => 30 ] );
		$this->assert_returned( self::complete( $token ), 'reverify_required' );
	}

	public function test_24_other_account_signed_in_between_verify_and_complete(): void {
		$auth  = self::enrolled( $this->user );
		$token = $this->token( $auth );
		Ceremony::user( 8 );
		magicauth_test_login_as( 8 );
		$nav = self::complete( $token );
		$this->assertSame( 'other_account', $nav['query']['magicauth_passkey_error'] ?? null );
		$this->assertSame( 8, get_current_user_id(), 'no session swap' );
	}

	public function test_24_cookie_failure_is_retry(): void {
		global $magicauth_test_state;
		$auth                                       = self::enrolled( $this->user );
		$token                                      = $this->token( $auth );
		$magicauth_test_state['auth_cookie_throws'] = new \RuntimeException( 'headers' );
		$nav                                        = self::complete( $token );
		$this->assertSame( 'retry', $nav['query']['magicauth_passkey_error'] ?? null );
	}

	public function test_24_database_error_on_the_token_is_retry(): void {
		global $wpdb;
		$auth  = self::enrolled( $this->user );
		$token = $this->token( $auth );
		$wpdb->fail_next_query( 'SELECT * FROM ' . ChallengeStore::table() );
		$this->assert_returned( self::complete( $token ), 'retry' );
	}

	public function test_24_body_cap(): void {
		$auth  = self::enrolled( $this->user );
		$token = $this->token( $auth );
		self::request( [ 'token' => $token, 'return_to' => self::RETURN_TO ] );
		$_SERVER['CONTENT_LENGTH'] = '65537';
		$this->assert_returned( self::navigate(), 'passkey_failed' );
	}

	/** @return array<string,array{string}> */
	public static function bad_return_to(): array {
		return [
			'foreign'    => [ 'https://evil.example/login/' ],
			'empty'      => [ '' ],
			'javascript' => [ 'javascript:alert(1)' ],
		];
	}

	/** @dataProvider bad_return_to */
	public function test_24_failure_return_to_stays_on_the_site( string $return_to ): void {
		self::request(
			[
				'token'     => 'junk',
				'return_to' => $return_to,
			]
		);
		$nav = self::navigate();
		$this->assertSame( 303, $nav['status'] );
		$this->assertSame( 'https://academy.example.com/?magicauth_passkey_error=retry', $nav['location'] );
	}

	public function test_24_return_to_with_an_old_error_gets_the_new_one(): void {
		self::request(
			[
				'token'     => 'junk',
				'return_to' => 'https://academy.example.com/login/?magicauth_passkey_error=other_account',
			]
		);
		$this->assertSame( 'https://academy.example.com/login/?magicauth_passkey_error=retry', self::navigate()['location'] );
	}
}
