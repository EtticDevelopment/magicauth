<?php
/**
 * Passkeys\Http (SPEC 6.1, 14.1, build step 10): POST only (405), the Origin
 * gate, body and field caps with unslashing, the no-store JSON envelope, the
 * signed-in session gate in its fixed order, the suppress-errors wrapper and
 * the cookie seam.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Passkeys\Clock;
use MagicAuth\Passkeys\Http;
use MagicAuth\Tests\Stubs\JsonResponseSent;
use MagicAuth\Tests\Support\Ceremony;
use PHPUnit\Framework\TestCase;

final class HttpTest extends TestCase {

	private const NO_STORE = [
		'Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private',
		'Pragma: no-cache',
		'X-Content-Type-Options: nosniff',
	];

	/** @var array<string,mixed> */
	private array $server = [];

	/** @var array{0:string,1:string}|null */
	private ?array $log_capture = null;

	protected function setUp(): void {
		Ceremony::site();
		$this->server = $_SERVER;
		$_POST        = [];
		$_REQUEST     = [];
	}

	protected function tearDown(): void {
		global $wpdb;
		$_SERVER  = $this->server;
		$_POST    = [];
		$_REQUEST = [];
		$wpdb->show_errors( false );
		if ( null !== $this->log_capture ) {
			ini_set( 'error_log', $this->log_capture[1] ); // phpcs:ignore WordPress.PHP.IniSet.Risky
			if ( is_file( $this->log_capture[0] ) ) {
				unlink( $this->log_capture[0] );
			}
		}
		magicauth_test_reset_state();
	}

	/**
	 * Runs $fn and returns the JSON response it sent.
	 *
	 * @return array{payload:mixed,status:?int}
	 */
	private static function response( callable $fn ): array {
		try {
			$fn();
		} catch ( JsonResponseSent $sent ) {
			return [
				'payload' => $sent->payload,
				'status'  => $sent->status,
			];
		}
		self::fail( 'no response sent' );
	}

	/** @return array<int,string> */
	private static function headers(): array {
		global $magicauth_test_state;
		return $magicauth_test_state['headers'] ?? [];
	}

	/* ----------------------------------------------------- require_post() */

	public function test_post_passes(): void {
		$_SERVER['REQUEST_METHOD'] = 'POST';
		Http::require_post();
		$this->assertSame( [], self::headers() );
	}

	/** @return array<string,array{0:mixed}> */
	public static function non_post_methods(): array {
		return [
			'GET'       => [ 'GET' ],
			'HEAD'      => [ 'HEAD' ],
			'PUT'       => [ 'PUT' ],
			'lowercase' => [ 'post' ],
			'padded'    => [ ' POST' ],
			'empty'     => [ '' ],
			'missing'   => [ null ],
			'array'     => [ [ 'POST' ] ],
		];
	}

	/**
	 * @dataProvider non_post_methods
	 * @param mixed $method
	 */
	public function test_every_other_method_gets_405( $method ): void {
		if ( null === $method ) {
			unset( $_SERVER['REQUEST_METHOD'] );
		} else {
			$_SERVER['REQUEST_METHOD'] = $method;
		}

		$response = self::response( [ Http::class, 'require_post' ] );

		$this->assertSame( 405, $response['status'] );
		$this->assertSame( false, $response['payload']['success'] );
		$this->assertSame( 'bad_request', $response['payload']['data']['code'] );
		$this->assertSame( array_merge( [ 'Allow: POST' ], self::NO_STORE ), self::headers() );
	}

	/* ------------------------------------------------------- origin_ok() */

	public function test_origin_gate_uses_this_request(): void {
		$_SERVER['HTTP_ORIGIN'] = Ceremony::ORIGIN;
		$this->assertTrue( Http::origin_ok() );

		$_SERVER['HTTP_ORIGIN'] = 'https://evil.example';
		$this->assertFalse( Http::origin_ok() );

		$_SERVER['HTTP_ORIGIN'] = 'null';
		$this->assertFalse( Http::origin_ok() );
		$_SERVER['HTTP_SEC_FETCH_SITE'] = 'same-origin';
		$_SERVER['HTTP_SEC_FETCH_MODE'] = 'navigate';
		$this->assertFalse( Http::origin_ok(), 'fetch mode never accepts Origin: null' );
		$this->assertTrue( Http::origin_ok( true ), 'navigation mode with same-origin fetch metadata' );

		unset( $_SERVER['HTTP_ORIGIN'], $_SERVER['HTTP_SEC_FETCH_SITE'], $_SERVER['HTTP_SEC_FETCH_MODE'] );
		$_SERVER['HTTP_REFERER'] = Ceremony::ORIGIN . '/login/';
		$this->assertTrue( Http::origin_ok(), 'Referer only when Origin is absent' );
		unset( $_SERVER['HTTP_REFERER'] );
		$this->assertFalse( Http::origin_ok(), 'neither header' );
	}

	/* -------------------------------------------------- body_too_large() */

	/** @return array<string,array{0:mixed,1:bool}> */
	public static function content_lengths(): array {
		return [
			'absent'      => [ null, false ],
			'zero'        => [ '0', false ],
			'at cap'      => [ '65536', false ],
			'over cap'    => [ '65537', true ],
			'huge'        => [ '999999999999999999', true ],
			'int'         => [ 70000, true ],
			'int at cap'  => [ 65536, false ],
			'negative'    => [ '-1', true ],
			'text'        => [ 'abc', true ],
			'padded'      => [ ' 10', true ],
			'hex'         => [ '0x10', true ],
			'too long'    => [ '0000000000000000001', true ],
			'array'       => [ [ '10' ], true ],
		];
	}

	/**
	 * @dataProvider content_lengths
	 * @param mixed $length
	 */
	public function test_body_cap( $length, bool $too_large ): void {
		if ( null === $length ) {
			unset( $_SERVER['CONTENT_LENGTH'] );
		} else {
			$_SERVER['CONTENT_LENGTH'] = $length;
		}
		$this->assertSame( $too_large, Http::body_too_large() );
	}

	/* ------------------------------------------------------------ field() */

	public function test_field_is_unslashed_and_capped(): void {
		$_POST['credential'] = addslashes( '{"id":"a\\"b"}' );
		$this->assertSame( '{"id":"a\\"b"}', Http::field( 'credential', 100 ) );

		$_POST['name'] = str_repeat( 'x', 10 );
		$this->assertSame( str_repeat( 'x', 10 ), Http::field( 'name', 10 ), 'at the cap' );
		$this->assertNull( Http::field( 'name', 9 ), 'over the cap' );

		$_POST['multi'] = "\u{00e9}\u{00e9}";
		$this->assertNull( Http::field( 'multi', 3 ), 'the cap counts bytes' );
	}

	public function test_field_absent_or_not_a_string_is_null(): void {
		$_POST['list'] = [ 'a' ];
		$this->assertNull( Http::field( 'missing', 10 ) );
		$this->assertNull( Http::field( 'list', 10 ) );
		$_POST['empty'] = '';
		$this->assertSame( '', Http::field( 'empty', 10 ) );
	}

	/* ------------------------------------------------------- ok(), fail() */

	public function test_ok_sends_the_success_envelope_with_no_store(): void {
		$response = self::response( static fn() => Http::ok( [ 'complete' => 'abc' ] ) );

		$this->assertSame( 200, $response['status'] );
		$this->assertSame(
			[
				'success' => true,
				'data'    => [ 'complete' => 'abc' ],
			],
			$response['payload']
		);
		$this->assertSame( self::NO_STORE, self::headers() );
	}

	public function test_ok_with_another_status(): void {
		$response = self::response( static fn() => Http::ok( [], 201 ) );
		$this->assertSame( 201, $response['status'] );
	}

	public function test_fail_sends_code_message_and_extra(): void {
		$response = self::response( static fn() => Http::fail( 'passkey_failed', 'Nope.', 400, [ 'unknown_credential' => true ] ) );

		$this->assertSame( 400, $response['status'] );
		$this->assertSame(
			[
				'success' => false,
				'data'    => [
					'code'               => 'passkey_failed',
					'message'            => 'Nope.',
					'unknown_credential' => true,
				],
			],
			$response['payload']
		);
		$this->assertSame( self::NO_STORE, self::headers() );
	}

	public function test_fail_extra_never_replaces_code_or_message(): void {
		$response = self::response(
			static fn() => Http::fail(
				'retry',
				'Again.',
				503,
				[
					'code'    => 'x',
					'message' => 'y',
				]
			)
		);
		$this->assertSame( 'retry', $response['payload']['data']['code'] );
		$this->assertSame( 'Again.', $response['payload']['data']['message'] );
	}

	/* -------------------------------------------------- require_session() */

	private function signed_in_request( bool $nonce = true, bool $origin = true ): void {
		magicauth_test_login_as( (int) Ceremony::user( 40 )->ID );
		if ( $nonce ) {
			$_REQUEST['_ajax_nonce'] = wp_create_nonce( 'magicauth_passkeys' );
		}
		$_SERVER['HTTP_ORIGIN'] = $origin ? Ceremony::ORIGIN : 'https://evil.example';
	}

	public function test_session_gate_returns_the_user(): void {
		$this->signed_in_request();
		$this->assertSame( 40, (int) Http::require_session( 'magicauth_passkeys' )->ID );
		$this->assertSame( [], self::headers() );
	}

	public function test_session_gate_not_logged_in_comes_first(): void {
		$_SERVER['HTTP_ORIGIN'] = 'https://evil.example';
		$response               = self::response( static fn() => Http::require_session( 'magicauth_passkeys' ) );
		$this->assertSame( 403, $response['status'] );
		$this->assertSame( 'not_logged_in', $response['payload']['data']['code'] );
	}

	public function test_session_gate_bad_nonce_before_origin(): void {
		$this->signed_in_request( false, false );
		$response = self::response( static fn() => Http::require_session( 'magicauth_passkeys' ) );
		$this->assertSame( 403, $response['status'] );
		$this->assertSame( 'bad_nonce', $response['payload']['data']['code'] );
		$this->assertSame( self::NO_STORE, self::headers(), 'a JSON body, not wp_die( -1 )' );
	}

	public function test_session_gate_nonce_of_another_action_is_bad(): void {
		$this->signed_in_request( false );
		$_REQUEST['_ajax_nonce'] = wp_create_nonce( 'magicauth-passkeys-admin' );
		$response                = self::response( static fn() => Http::require_session( 'magicauth_passkeys' ) );
		$this->assertSame( 'bad_nonce', $response['payload']['data']['code'] );
	}

	public function test_session_gate_bad_origin(): void {
		$this->signed_in_request( true, false );
		$response = self::response( static fn() => Http::require_session( 'magicauth_passkeys' ) );
		$this->assertSame( 403, $response['status'] );
		$this->assertSame( 'bad_origin', $response['payload']['data']['code'] );
	}

	/* ---------------------------------------------------------- quietly() */

	public function test_quietly_prints_nothing_logs_and_restores_suppress_errors(): void {
		global $wpdb;
		$file              = (string) tempnam( sys_get_temp_dir(), 'magicauth-log' );
		$this->log_capture = [ $file, (string) ini_get( 'error_log' ) ];
		ini_set( 'error_log', $file ); // phpcs:ignore WordPress.PHP.IniSet.Risky
		add_filter( 'magicauth_debug_log', static fn() => true );

		foreach ( [ false, true ] as $previous ) {
			$wpdb->show_errors( true );
			$wpdb->suppress_errors( $previous );
			$inside = null;

			ob_start();
			$result = Http::quietly(
				static function () use ( $wpdb, &$inside ) {
					$inside = $wpdb->suppress_errors;
					return $wpdb->query( 'INSERT INTO no_such_table (a) VALUES (1)' );
				},
				'register: credential insert'
			);
			$out = (string) ob_get_clean();

			$this->assertFalse( $result );
			$this->assertTrue( $inside, 'suppressed while the query runs' );
			$this->assertSame( '', $out, 'nothing printed with show_errors on' );
			$this->assertSame( $previous, $wpdb->suppress_errors, 'restored' );
		}
		$log = (string) file_get_contents( $file );
		$this->assertStringContainsString( '[magicauth] register: credential insert: query failed', $log );
		$this->assertStringNotContainsString( 'no_such_table', $log, 'no SQL error text in the log' );
	}

	public function test_quietly_returns_the_result_and_logs_nothing_on_success(): void {
		global $wpdb;
		add_filter( 'magicauth_debug_log', static fn() => true );
		$file              = (string) tempnam( sys_get_temp_dir(), 'magicauth-log' );
		$this->log_capture = [ $file, (string) ini_get( 'error_log' ) ];
		ini_set( 'error_log', $file ); // phpcs:ignore WordPress.PHP.IniSet.Risky

		$this->assertSame( '1', Http::quietly( static fn() => (string) $wpdb->get_var( 'SELECT 1' ), 'ctx' ) );
		$this->assertSame( '', (string) file_get_contents( $file ) );
	}

	public function test_quietly_restores_suppress_errors_when_the_callback_throws(): void {
		global $wpdb;
		$wpdb->suppress_errors( false );
		try {
			Http::quietly(
				static function () {
					throw new \RuntimeException( 'boom' );
				},
				'ctx'
			);
			$this->fail( 'exception expected' );
		} catch ( \RuntimeException $e ) {
			$this->assertSame( 'boom', $e->getMessage() );
		}
		$this->assertFalse( $wpdb->suppress_errors );
	}

	/* -------------------------------------------------------- set_cookie() */

	public function test_cookie_seam_records_every_attribute(): void {
		global $magicauth_test_state;
		Clock::set_for_tests( 1000 );

		Http::set_cookie(
			'magicauth_pk_bind',
			str_repeat( 'a', 64 ),
			[
				'expires'  => 1720,
				'path'     => '/wp-admin/admin-ajax.php',
				'domain'   => '',
				'secure'   => true,
				'httponly' => true,
				'samesite' => 'Strict',
			]
		);

		$this->assertSame(
			[
				[
					'name'     => 'magicauth_pk_bind',
					'value'    => str_repeat( 'a', 64 ),
					'max_age'  => 720,
					'expires'  => 1720,
					'path'     => '/wp-admin/admin-ajax.php',
					'domain'   => '',
					'secure'   => true,
					'httponly' => true,
					'samesite' => 'Strict',
				],
			],
			$magicauth_test_state['cookies']
		);
	}

	public function test_max_body_constant(): void {
		$this->assertSame( 65536, Http::MAX_BODY );
	}
}
