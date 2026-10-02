<?php
/**
 * T-FRESH, creation part (SPEC 15 step 3, 3.2 to 3.4, 14.1): the one-shot
 * creation stamp, the fresh cookie, the window and its clamp, the method
 * list, the cookie binding and the email-change boundary (3.4 step 6).
 *
 * Step-up part (build step 11): the state row (5.6) as candidate B, made
 * fresh only with the cookie issued by the step-up, the destroyed record, the
 * email-change boundary for step-up stamps, and the newest candidate deciding.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Passkeys\Clock;
use MagicAuth\Passkeys\Freshness;
use MagicAuth\Passkeys\SessionState;
use PHPUnit\Framework\TestCase;

final class FreshnessTest extends TestCase {

	private const NOW = 1790000000;

	private const USER_ID = 910;

	private const OTHER_ID = 911;

	protected function setUp(): void {
		magicauth_test_reset_state();
		magicauth_test_register_user( self::USER_ID, 'fresh@example.test' );
		magicauth_test_register_user( self::OTHER_ID, 'other@example.test' );
		magicauth_test_login_as( self::USER_ID );
		Clock::set_for_tests( self::NOW );
		$_COOKIE = [];
	}

	protected function tearDown(): void {
		$_COOKIE = [];
		magicauth_test_reset_state();
	}

	/* ------------------------------------------------------------- helpers */

	private static function hmac( string $cookie ): string {
		return hash_hmac( 'sha256', 'magicauth-passkey-fresh|' . $cookie, wp_salt( 'auth' ) );
	}

	/**
	 * Creates a core session for the user through WP_Session_Tokens::create()
	 * with $stamp applied as attach_session_information would, makes it the
	 * request's session, and returns the token.
	 *
	 * @param array<string,mixed> $stamp
	 */
	private static function session_with( array $stamp, int $user_id = self::USER_ID ): string {
		$cb = static function ( $session ) use ( $stamp ) {
			return array_merge( (array) $session, $stamp );
		};
		add_filter( 'attach_session_information', $cb, 10, 2 );
		$token = \WP_Session_Tokens::get_instance( $user_id )->create( self::NOW + DAY_IN_SECONDS );
		remove_filter( 'attach_session_information', $cb, 10 );

		global $magicauth_test_state;
		$magicauth_test_state['session_token'] = $token;
		return $token;
	}

	/**
	 * A complete fresh-capable stamp; the matching cookie goes into $_COOKIE.
	 *
	 * @return array<string,mixed>
	 */
	private static function stamp( string $method, int $auth_at, string $cookie = '' ): array {
		$cookie = '' !== $cookie ? $cookie : str_repeat( 'a1', 32 );
		$_COOKIE[ Freshness::COOKIE ] = $cookie;
		return [
			'magicauth_method'     => $method,
			'magicauth_auth_at'    => $auth_at,
			'magicauth_fresh_hash' => self::hmac( $cookie ),
		];
	}

	/* -------------------------------------------------------------- window */

	public function test_link_session_599_seconds_old_is_fresh(): void {
		self::session_with( self::stamp( 'link', self::NOW - 599 ) );
		$this->assertTrue( Freshness::is_fresh() );
	}

	public function test_window_boundary_600_seconds_is_fresh(): void {
		self::session_with( self::stamp( 'link', self::NOW - 600 ) );
		$this->assertTrue( Freshness::is_fresh() );
	}

	public function test_link_session_601_seconds_old_is_stale(): void {
		self::session_with( self::stamp( 'link', self::NOW - 601 ) );
		$this->assertFalse( Freshness::is_fresh() );
	}

	/** @return array<string,array{0:string}> */
	public static function fresh_methods(): array {
		return [
			'link'    => [ 'link' ],
			'code'    => [ 'code' ],
			'reset'   => [ 'reset' ],
			'passkey' => [ 'passkey' ],
		];
	}

	/** @dataProvider fresh_methods */
	public function test_every_fresh_method_counts( string $method ): void {
		self::session_with( self::stamp( $method, self::NOW - 1 ) );
		$this->assertTrue( Freshness::is_fresh() );
	}

	public function test_window_default_is_600(): void {
		$this->assertSame( 600, Freshness::window() );
		$this->assertSame( 600, Freshness::FRESH_WINDOW );
	}

	/** @return array<string,array{0:mixed,1:int}> */
	public static function window_filter_values(): array {
		return [
			'59 clamps to 60'      => [ 59, 60 ],
			'60 kept'              => [ 60, 60 ],
			'4000 clamps to 3600'  => [ 4000, 3600 ],
			'3600 kept'            => [ 3600, 3600 ],
			'negative clamps'      => [ -5, 60 ],
			'non-numeric clamps'   => [ 'forever', 60 ],
			'numeric string'       => [ '900', 900 ],
		];
	}

	/**
	 * @dataProvider window_filter_values
	 * @param mixed $filtered
	 */
	public function test_window_filter_is_clamped( $filtered, int $expected ): void {
		add_filter(
			'magicauth_passkey_fresh_window',
			static function () use ( $filtered ) {
				return $filtered;
			}
		);
		$this->assertSame( $expected, Freshness::window() );
	}

	public function test_filtered_window_applies_to_is_fresh(): void {
		add_filter(
			'magicauth_passkey_fresh_window',
			static function (): int {
				return 59; // Clamped to 60.
			}
		);
		self::session_with( self::stamp( 'link', self::NOW - 60 ) );
		$this->assertTrue( Freshness::is_fresh() );

		self::session_with( self::stamp( 'link', self::NOW - 61 ) );
		$this->assertFalse( Freshness::is_fresh() );
	}

	/* --------------------------------------------------------------- stamp */

	public function test_missing_stamp_is_stale(): void {
		$_COOKIE[ Freshness::COOKIE ] = str_repeat( 'a1', 32 );
		self::session_with( [] );
		$this->assertFalse( Freshness::is_fresh() );
	}

	/** @return array<string,array{0:mixed}> */
	public static function non_integer_stamps(): array {
		return [
			'numeric string' => [ (string) ( self::NOW - 10 ) ],
			'float'          => [ (float) ( self::NOW - 10 ) ],
			'null'           => [ null ],
			'bool'           => [ true ],
		];
	}

	/**
	 * @dataProvider non_integer_stamps
	 * @param mixed $auth_at
	 */
	public function test_non_integer_auth_at_is_stale( $auth_at ): void {
		$stamp                      = self::stamp( 'link', self::NOW - 10 );
		$stamp['magicauth_auth_at'] = $auth_at;
		self::session_with( $stamp );
		$this->assertFalse( Freshness::is_fresh() );
	}

	/** @return array<string,array{0:mixed}> */
	public static function bad_fresh_hashes(): array {
		return [
			'missing'   => [ null ],
			'short'     => [ str_repeat( 'a', 63 ) ],
			'uppercase' => [ str_repeat( 'A', 64 ) ],
			'not hex'   => [ str_repeat( 'z', 64 ) ],
			'int'       => [ 12 ],
		];
	}

	/**
	 * @dataProvider bad_fresh_hashes
	 * @param mixed $hash
	 */
	public function test_creation_stamp_without_a_valid_fresh_hash_is_stale( $hash ): void {
		$stamp = self::stamp( 'link', self::NOW - 10 );
		if ( null === $hash ) {
			unset( $stamp['magicauth_fresh_hash'] );
		} else {
			$stamp['magicauth_fresh_hash'] = $hash;
		}
		self::session_with( $stamp );
		$this->assertFalse( Freshness::is_fresh() );
	}

	public function test_password_session_one_second_old_is_stale(): void {
		self::session_with( self::stamp( 'password', self::NOW - 1 ) );
		$this->assertFalse( Freshness::is_fresh() );
	}

	public function test_admin_link_session_one_second_old_is_stale(): void {
		self::session_with( self::stamp( 'admin_link', self::NOW - 1 ) );
		$this->assertFalse( Freshness::is_fresh() );
	}

	public function test_unknown_method_is_stale(): void {
		self::session_with( self::stamp( 'sso', self::NOW - 1 ) );
		$this->assertFalse( Freshness::is_fresh() );
	}

	public function test_methods_filter_can_only_remove(): void {
		add_filter(
			'magicauth_passkey_fresh_methods',
			static function (): array {
				return [ 'code', 'password', 'admin_link' ];
			}
		);

		self::session_with( self::stamp( 'link', self::NOW - 1 ) );
		$this->assertFalse( Freshness::is_fresh(), 'link removed by the filter' );

		self::session_with( self::stamp( 'password', self::NOW - 1 ) );
		$this->assertFalse( Freshness::is_fresh(), 'password cannot be added' );

		self::session_with( self::stamp( 'admin_link', self::NOW - 1 ) );
		$this->assertFalse( Freshness::is_fresh(), 'admin_link cannot be added' );

		self::session_with( self::stamp( 'code', self::NOW - 1 ) );
		$this->assertTrue( Freshness::is_fresh(), 'code kept' );
	}

	public function test_methods_filter_returning_garbage_means_none(): void {
		add_filter(
			'magicauth_passkey_fresh_methods',
			static function (): string {
				return 'link';
			}
		);
		self::session_with( self::stamp( 'link', self::NOW - 1 ) );
		$this->assertFalse( Freshness::is_fresh() );
	}

	/* -------------------------------------------------------------- cookie */

	public function test_link_session_without_fresh_cookie_is_stale(): void {
		self::session_with( self::stamp( 'link', self::NOW - 1 ) );
		unset( $_COOKIE[ Freshness::COOKIE ] );
		$this->assertFalse( Freshness::is_fresh(), 'copied session cookies without magicauth_pk_fresh' );
	}

	public function test_link_session_with_wrong_fresh_cookie_is_stale(): void {
		self::session_with( self::stamp( 'link', self::NOW - 1 ) );
		$_COOKIE[ Freshness::COOKIE ] = str_repeat( 'b2', 32 );
		$this->assertFalse( Freshness::is_fresh(), 'cookie from an earlier authentication' );
	}

	/** @return array<string,array{0:mixed}> */
	public static function malformed_cookies(): array {
		$good = str_repeat( 'a1', 32 );
		return [
			'uppercase' => [ strtoupper( $good ) ],
			'too long'  => [ $good . 'a' ],
			'too short' => [ substr( $good, 1 ) ],
			'array'     => [ [ $good ] ],
			'empty'     => [ '' ],
			'padded'    => [ ' ' . $good ],
		];
	}

	/**
	 * The stamp holds the HMAC of the malformed value itself, so only the
	 * format check can reject it.
	 *
	 * @dataProvider malformed_cookies
	 * @param mixed $cookie
	 */
	public function test_malformed_fresh_cookie_is_stale( $cookie ): void {
		$stamp                         = self::stamp( 'link', self::NOW - 1 );
		$stamp['magicauth_fresh_hash'] = self::hmac( is_string( $cookie ) ? $cookie : 'x' );
		self::session_with( $stamp );
		$_COOKIE[ Freshness::COOKIE ] = $cookie;
		$this->assertFalse( Freshness::is_fresh() );
	}

	/* ------------------------------------------------------------- session */

	public function test_no_session_token_is_stale(): void {
		self::session_with( self::stamp( 'link', self::NOW - 1 ) );
		global $magicauth_test_state;
		$magicauth_test_state['session_token'] = '';
		$this->assertFalse( Freshness::is_fresh() );
		$this->assertSame( '', Freshness::session_hash() );
		$this->assertNull( Freshness::session() );
	}

	public function test_destroyed_core_record_is_stale(): void {
		$token = self::session_with( self::stamp( 'link', self::NOW - 1 ) );
		$this->assertTrue( Freshness::is_fresh() );

		\WP_Session_Tokens::get_instance( self::USER_ID )->destroy( $token );
		$this->assertFalse( Freshness::is_fresh(), 'Log Out Everywhere or a password change ends freshness' );
		$this->assertNull( Freshness::session() );
	}

	public function test_record_of_another_user_does_not_count(): void {
		self::session_with( self::stamp( 'link', self::NOW - 1 ), self::OTHER_ID );
		$this->assertFalse( Freshness::is_fresh(), 'the token is looked up for the current user only' );
	}

	public function test_logged_out_request_is_stale(): void {
		self::session_with( self::stamp( 'link', self::NOW - 1 ) );
		magicauth_test_login_as( 0 );
		$this->assertFalse( Freshness::is_fresh() );
		$this->assertNull( Freshness::session() );
	}

	public function test_session_hash_is_a_domain_separated_hmac_of_the_token(): void {
		$token = self::session_with( [] );
		$hash  = Freshness::session_hash();
		$this->assertSame( hash_hmac( 'sha256', 'magicauth-passkey-session|' . $token, wp_salt( 'auth' ) ), $hash );
		$this->assertNotSame( hash( 'sha256', $token ), $hash, 'not the key core uses in session_tokens' );
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{64}$/', $hash );
	}

	public function test_session_returns_the_core_record(): void {
		self::session_with( self::stamp( 'code', self::NOW - 5 ) );
		$session = Freshness::session();
		$this->assertIsArray( $session );
		$this->assertSame( 'code', $session['magicauth_method'] );
		$this->assertSame( self::NOW - 5, $session['magicauth_auth_at'] );
	}

	/* ------------------------------------------------- email change, step 6 */

	public function test_email_changed_after_sign_in_makes_session_stale(): void {
		// auth_at = 0, email changed at 30, checked at 60 with a valid cookie.
		self::session_with( self::stamp( 'link', self::NOW ) );
		update_user_meta( self::USER_ID, 'magicauth_email_changed_at', self::NOW + 30 );
		Clock::set_for_tests( self::NOW + 60 );
		$this->assertFalse( Freshness::is_fresh() );
	}

	public function test_email_changed_at_equal_to_auth_at_is_stale(): void {
		self::session_with( self::stamp( 'link', self::NOW ) );
		update_user_meta( self::USER_ID, 'magicauth_email_changed_at', self::NOW );
		$this->assertFalse( Freshness::is_fresh() );
	}

	public function test_session_created_after_the_email_change_is_fresh(): void {
		self::session_with( self::stamp( 'link', self::NOW + 31 ) );
		update_user_meta( self::USER_ID, 'magicauth_email_changed_at', self::NOW + 30 );
		Clock::set_for_tests( self::NOW + 60 );
		$this->assertTrue( Freshness::is_fresh() );
	}

	public function test_email_change_of_another_user_is_ignored(): void {
		self::session_with( self::stamp( 'link', self::NOW ) );
		update_user_meta( self::OTHER_ID, 'magicauth_email_changed_at', self::NOW + 30 );
		Clock::set_for_tests( self::NOW + 60 );
		$this->assertTrue( Freshness::is_fresh() );
	}

	/* ------------------------------------------------------ stamp_callback */

	public function test_stamp_callback_stamps_only_the_first_session_of_the_user(): void {
		$stamp = Freshness::stamp_callback( self::USER_ID, 'code', str_repeat( 'c', 64 ) );

		$this->assertSame( [ 'x' => 1 ], $stamp( [ 'x' => 1 ], self::OTHER_ID ), 'another user is not stamped and does not use up the stamp' );

		$first = $stamp( [ 'x' => 1 ], self::USER_ID );
		$this->assertSame(
			[
				'x'                    => 1,
				'magicauth_method'     => 'code',
				'magicauth_auth_at'    => self::NOW,
				'magicauth_fresh_hash' => str_repeat( 'c', 64 ),
			],
			$first
		);

		$this->assertSame( [ 'y' => 2 ], $stamp( [ 'y' => 2 ], self::USER_ID ), 'one-shot' );
	}

	public function test_stamp_callback_without_fresh_hash_writes_no_hash_key(): void {
		$stamp   = Freshness::stamp_callback( self::USER_ID, 'link', null );
		$session = $stamp( [], self::USER_ID );
		$this->assertSame( [ 'magicauth_method' => 'link', 'magicauth_auth_at' => self::NOW ], $session );
	}

	public function test_stamped_session_without_hash_is_never_fresh(): void {
		$stamp = Freshness::stamp_callback( self::USER_ID, 'link', null );
		add_filter( 'attach_session_information', $stamp, 10, 2 );
		$token = \WP_Session_Tokens::get_instance( self::USER_ID )->create( self::NOW + DAY_IN_SECONDS );
		global $magicauth_test_state;
		$magicauth_test_state['session_token'] = $token;
		$_COOKIE[ Freshness::COOKIE ]          = str_repeat( 'a1', 32 );

		$this->assertFalse( Freshness::is_fresh(), 'a module-off session steps up' );
	}

	/* -------------------------------------------------- issue_fresh_cookie */

	public function test_issue_fresh_cookie_records_host_only_strict_cookie_scoped_to_admin_ajax(): void {
		global $magicauth_test_state;
		$hash = Freshness::issue_fresh_cookie();

		$cookies = $magicauth_test_state['cookies'] ?? [];
		$this->assertCount( 1, $cookies );
		$cookie = $cookies[0];
		$this->assertSame( 'magicauth_pk_fresh', $cookie['name'] );
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{64}$/', $cookie['value'] );
		$this->assertSame( self::hmac( $cookie['value'] ), $hash, 'returns the HMAC, never the value' );
		$this->assertSame( '/wp-admin/admin-ajax.php', $cookie['path'] );
		$this->assertSame( '', $cookie['domain'] );
		$this->assertTrue( $cookie['httponly'] );
		$this->assertSame( 'Strict', $cookie['samesite'] );
		$this->assertFalse( $cookie['secure'] );
		$this->assertSame( 600, $cookie['max_age'] );
		$this->assertSame( self::NOW + 600, $cookie['expires'] );
	}

	public function test_issue_fresh_cookie_follows_ssl_window_and_admin_path(): void {
		global $magicauth_test_state;
		$magicauth_test_state['is_ssl']  = true;
		$magicauth_test_state['siteurl'] = 'https://example.test/wp';
		add_filter(
			'magicauth_passkey_fresh_window',
			static function (): int {
				return 120;
			}
		);

		Freshness::issue_fresh_cookie();
		Freshness::issue_fresh_cookie();

		$cookies = $magicauth_test_state['cookies'];
		$this->assertTrue( $cookies[0]['secure'] );
		$this->assertSame( '/wp/wp-admin/admin-ajax.php', $cookies[0]['path'] );
		$this->assertSame( 120, $cookies[0]['max_age'] );
		$this->assertNotSame( $cookies[0]['value'], $cookies[1]['value'], 'a new random value each time' );
	}

	/** Value and HMAC first, cookie later: new_fresh_value() sends nothing, send_fresh_cookie() sends that value. */
	public function test_new_fresh_value_sends_nothing_until_send_fresh_cookie(): void {
		global $magicauth_test_state;
		$fresh = Freshness::new_fresh_value();
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{64}$/', $fresh['value'] );
		$this->assertSame( self::hmac( $fresh['value'] ), $fresh['hash'] );
		$this->assertNotSame( $fresh['value'], Freshness::new_fresh_value()['value'] );
		$this->assertSame( [], $magicauth_test_state['cookies'] ?? [] );

		Freshness::send_fresh_cookie( $fresh['value'] );
		$cookies = $magicauth_test_state['cookies'] ?? [];
		$this->assertCount( 1, $cookies );
		$this->assertSame( 'magicauth_pk_fresh', $cookies[0]['name'] );
		$this->assertSame( $fresh['value'], $cookies[0]['value'] );
		$this->assertSame( '/wp-admin/admin-ajax.php', $cookies[0]['path'] );
		$this->assertTrue( $cookies[0]['httponly'] );
		$this->assertSame( 'Strict', $cookies[0]['samesite'] );
		$this->assertSame( 600, $cookies[0]['max_age'] );
	}

	public function test_issued_cookie_and_stamp_make_the_session_fresh(): void {
		global $magicauth_test_state;
		$hash  = Freshness::issue_fresh_cookie();
		$value = $magicauth_test_state['cookies'][0]['value'];

		$stamp = Freshness::stamp_callback( self::USER_ID, 'passkey', $hash );
		add_filter( 'attach_session_information', $stamp, 10, 2 );
		$token = \WP_Session_Tokens::get_instance( self::USER_ID )->create( self::NOW + DAY_IN_SECONDS );
		remove_filter( 'attach_session_information', $stamp, 10 );
		$magicauth_test_state['session_token'] = $token;

		$_COOKIE[ Freshness::COOKIE ] = $value;
		$this->assertTrue( Freshness::is_fresh() );

		Clock::set_for_tests( self::NOW + 601 );
		$this->assertFalse( Freshness::is_fresh() );
	}

	public function test_is_fresh_never_rewrites_core_session_records(): void {
		// WP_Session_Tokens::update() throws in the harness (invariant 11).
		$token = self::session_with( self::stamp( 'link', self::NOW - 1 ) );
		global $magicauth_test_state;
		$before = $magicauth_test_state['sessions'];
		$this->assertTrue( Freshness::is_fresh() );
		Freshness::session();
		Freshness::session_hash();
		$this->assertSame( $before, $magicauth_test_state['sessions'] );
		$this->assertNotSame( '', $token );
	}

	/* ------------------------------------------------- step-up (candidate B) */

	/** Stamps a step-up for the current session and returns the cookie it sent. */
	private function step_up( string $method = 'email_code' ): string {
		global $magicauth_test_state;
		$this->assertTrue( SessionState::stamp_reauth( $method ) );
		$cookies = $magicauth_test_state['cookies'] ?? [];
		return (string) end( $cookies )['value'];
	}

	public function test_step_up_makes_a_stale_password_session_fresh_with_its_new_cookie_only(): void {
		self::session_with( self::stamp( 'password', self::NOW - 1 ) );
		$old = (string) $_COOKIE[ Freshness::COOKIE ];
		$this->assertFalse( Freshness::is_fresh(), 'password session' );

		$new = $this->step_up();

		$this->assertFalse( Freshness::is_fresh(), 'old cookie (a copy taken before the step-up)' );
		$_COOKIE[ Freshness::COOKIE ] = $new;
		$this->assertTrue( Freshness::is_fresh() );
		$_COOKIE[ Freshness::COOKIE ] = $old;
		$this->assertFalse( Freshness::is_fresh() );
	}

	public function test_step_up_makes_an_unstamped_session_fresh(): void {
		self::session_with( [] );
		$_COOKIE[ Freshness::COOKIE ] = $this->step_up( 'passkey' );
		$this->assertTrue( Freshness::is_fresh() );
	}

	public function test_step_up_window(): void {
		self::session_with( self::stamp( 'password', self::NOW - 1 ) );
		$_COOKIE[ Freshness::COOKIE ] = $this->step_up();
		Clock::set_for_tests( self::NOW + 600 );
		$this->assertTrue( Freshness::is_fresh() );
		Clock::set_for_tests( self::NOW + 601 );
		$this->assertFalse( Freshness::is_fresh() );
	}

	/** A step-up in the second of the sign-in replaced the cookie: the step-up decides the tie. */
	public function test_step_up_in_the_same_second_as_the_sign_in(): void {
		self::session_with( self::stamp( 'link', self::NOW ) );
		$first = (string) $_COOKIE[ Freshness::COOKIE ];
		$_COOKIE[ Freshness::COOKIE ] = $this->step_up();
		$this->assertTrue( Freshness::is_fresh() );
		$_COOKIE[ Freshness::COOKIE ] = $first;
		$this->assertFalse( Freshness::is_fresh(), 'the newest candidate decides' );
	}

	public function test_newest_candidate_decides(): void {
		self::session_with( self::stamp( 'link', self::NOW - 500 ) );
		$creation_cookie = (string) $_COOKIE[ Freshness::COOKIE ];
		Clock::set_for_tests( self::NOW - 100 );
		$step_up_cookie = $this->step_up();
		Clock::set_for_tests( self::NOW );

		$_COOKIE[ Freshness::COOKIE ] = $creation_cookie;
		$this->assertFalse( Freshness::is_fresh(), 'creation cookie after a newer step-up' );
		$_COOKIE[ Freshness::COOKIE ] = $step_up_cookie;
		$this->assertTrue( Freshness::is_fresh() );
	}

	public function test_step_up_row_of_a_destroyed_session_does_not_count(): void {
		$token = self::session_with( self::stamp( 'password', self::NOW - 1 ) );
		$_COOKIE[ Freshness::COOKIE ] = $this->step_up();
		$this->assertTrue( Freshness::is_fresh() );

		\WP_Session_Tokens::get_instance( self::USER_ID )->destroy( $token );

		$this->assertNull( SessionState::get() );
		$this->assertFalse( Freshness::is_fresh() );
	}

	public function test_cleared_step_up_does_not_count(): void {
		self::session_with( self::stamp( 'password', self::NOW - 1 ) );
		$_COOKIE[ Freshness::COOKIE ] = $this->step_up();
		SessionState::clear_reauth_for_user( self::USER_ID );
		$this->assertFalse( Freshness::is_fresh() );
	}

	public function test_step_up_row_of_another_session_does_not_count(): void {
		self::session_with( self::stamp( 'password', self::NOW - 1 ) );
		$cookie = $this->step_up();
		self::session_with( self::stamp( 'password', self::NOW - 1 ) );
		$_COOKIE[ Freshness::COOKIE ] = $cookie;
		$this->assertFalse( Freshness::is_fresh() );
	}

	/** 3.4 step 6 for candidate B: link at 0, email changed at 30, passkey step-up at 40 is fresh. */
	public function test_step_up_after_an_email_change_is_fresh(): void {
		$t0 = self::NOW - 60;
		self::session_with( self::stamp( 'link', $t0 ) );
		update_user_meta( self::USER_ID, 'magicauth_email_changed_at', $t0 + 30 );

		Clock::set_for_tests( $t0 + 40 );
		$cookie = $this->step_up( 'passkey' );
		Clock::set_for_tests( $t0 + 60 );
		$_COOKIE[ Freshness::COOKIE ] = $cookie;

		$this->assertTrue( Freshness::is_fresh() );
	}

	public function test_step_up_at_the_email_change_is_stale(): void {
		$t0 = self::NOW - 60;
		self::session_with( self::stamp( 'link', $t0 ) );
		update_user_meta( self::USER_ID, 'magicauth_email_changed_at', $t0 + 30 );

		Clock::set_for_tests( $t0 + 30 );
		$cookie = $this->step_up( 'passkey' );
		Clock::set_for_tests( $t0 + 60 );
		$_COOKIE[ Freshness::COOKIE ] = $cookie;

		$this->assertFalse( Freshness::is_fresh() );
	}

	public function test_step_up_never_rewrites_core_session_records(): void {
		global $magicauth_test_state;
		self::session_with( self::stamp( 'password', self::NOW - 1 ) );
		$before = $magicauth_test_state['sessions'];
		$_COOKIE[ Freshness::COOKIE ] = $this->step_up();
		$this->assertTrue( Freshness::is_fresh() );
		$this->assertSame( $before, $magicauth_test_state['sessions'] );
	}
}
