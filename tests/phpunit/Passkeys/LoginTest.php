<?php
/**
 * T-LOGIN (SPEC 15 step 3, 4.3, 7.6, 7.7, 14.1): Auth\Login preflight and
 * establish for all six methods, B2 (no session swap), B3 (disable checked
 * at consume), multisite spam, magicauth_allow_login, the one-shot creation
 * stamp, hook $method arguments, cookie failure, email-verified stamp and the
 * validated redirect target.
 *
 * The default state has the module off (setting off, site not available), so
 * no case outside the "module enabled" section may see magicauth_pk_fresh.
 * Since build step 10 Login::fresh_cookie_enabled() is Module::enabled():
 * that section covers the cookie for fresh methods while the module is on.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Auth\Login;
use MagicAuth\Passkeys\Clock;
use PHPUnit\Framework\TestCase;
use WP_Error;
use WP_User;

final class LoginTest extends TestCase {

	private const NOW = 1790000000;

	private const USER_ID = 920;

	private const OTHER_ID = 921;

	private WP_User $user;

	protected function setUp(): void {
		magicauth_test_reset_state();
		$this->user             = magicauth_test_register_user( self::USER_ID, 'learner@example.test' );
		$this->user->user_login = 'learner';
		magicauth_test_register_user( self::OTHER_ID, 'other@example.test' );
		Clock::set_for_tests( self::NOW );
		$_COOKIE = [];
	}

	protected function tearDown(): void {
		$_COOKIE = [];
		magicauth_test_reset_state();
	}

	/* ------------------------------------------------------------- helpers */

	/** @return array<string,array{0:string}> */
	public static function all_methods(): array {
		$out = [];
		foreach ( Login::METHODS as $method ) {
			$out[ $method ] = [ $method ];
		}
		return $out;
	}

	/** @return array<int,array<string,mixed>> */
	private static function sessions( int $user_id = self::USER_ID ): array {
		global $magicauth_test_state;
		return array_values( $magicauth_test_state['sessions'][ $user_id ] ?? [] );
	}

	private static function auth_cookie_count(): int {
		global $magicauth_test_state;
		return count( $magicauth_test_state['auth_cookies'] ?? [] );
	}

	private static function fresh_cookie_sent(): bool {
		global $magicauth_test_state;
		foreach ( $magicauth_test_state['cookies'] ?? [] as $cookie ) {
			if ( 'magicauth_pk_fresh' === ( $cookie['name'] ?? '' ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Records every call of an action or filter; filters pass the value through.
	 *
	 * @return \ArrayObject<int,array<int,mixed>>
	 */
	private static function record( string $hook, int $accepted_args = 5 ): \ArrayObject {
		$calls = new \ArrayObject();
		add_filter(
			$hook,
			static function ( ...$args ) use ( $calls ) {
				$calls[] = $args;
				return $args[0] ?? null;
			},
			10,
			$accepted_args
		);
		return $calls;
	}

	/* ----------------------------------------------------- happy, per method */

	/** @dataProvider all_methods */
	public function test_establish_signs_in_and_stamps_the_session( string $method ): void {
		$wp_login  = self::record( 'wp_login', 2 );
		$completed = self::record( 'magicauth_login_completed', 2 );

		$this->assertTrue( Login::preflight( $this->user, $method ) );
		$this->assertSame( Login::SIGNED_IN, Login::establish( $this->user, $method ) );

		global $magicauth_test_state;
		$this->assertSame( self::USER_ID, $magicauth_test_state['auth_cookie_set_for'] );
		$this->assertSame( 1, self::auth_cookie_count() );
		$this->assertSame( self::USER_ID, get_current_user_id() );
		$this->assertSame( [ [ 'learner', $this->user ] ], $wp_login->getArrayCopy() );
		$this->assertSame( [ [ self::USER_ID, $method ] ], $completed->getArrayCopy() );

		$sessions = self::sessions();
		$this->assertCount( 1, $sessions );
		$this->assertSame( $method, $sessions[0]['magicauth_method'] );
		$this->assertSame( self::NOW, $sessions[0]['magicauth_auth_at'] );
		$this->assertArrayNotHasKey( 'magicauth_fresh_hash', $sessions[0], 'no fresh hash with the module off' );
		$this->assertFalse( self::fresh_cookie_sent(), 'no magicauth_pk_fresh with the module off' );
		$this->assertFalse( has_filter( 'attach_session_information' ), 'stamp filter removed' );
	}

	/* -------------------------------- module enabled: magicauth_pk_fresh (step 10) */

	/** An available site (https home, DB v2) with the setting on. */
	private static function enable_module(): void {
		global $magicauth_test_state;
		$magicauth_test_state['home']   = 'https://academy.example.com';
		$magicauth_test_state['is_ssl'] = true;
		update_option( 'magicauth_db_version', 2 );
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => true ] );
	}

	/** @return array<int,array<string,mixed>> */
	private static function fresh_cookies(): array {
		global $magicauth_test_state;
		return array_values(
			array_filter(
				$magicauth_test_state['cookies'] ?? [],
				static fn( array $c ): bool => 'magicauth_pk_fresh' === ( $c['name'] ?? '' )
			)
		);
	}

	/** @dataProvider all_methods */
	public function test_fresh_cookie_only_for_fresh_methods_while_enabled( string $method ): void {
		self::enable_module();
		$this->assertTrue( \MagicAuth\Passkeys\Module::enabled() );

		$this->assertSame( Login::SIGNED_IN, Login::establish( $this->user, $method ) );

		$sessions = self::sessions();
		$this->assertCount( 1, $sessions );
		if ( in_array( $method, [ 'link', 'code', 'reset', 'passkey' ], true ) ) {
			$cookies = self::fresh_cookies();
			$this->assertCount( 1, $cookies, $method );
			$this->assertMatchesRegularExpression( '/^[0-9a-f]{64}$/', $cookies[0]['value'] );
			$this->assertSame( '/wp-admin/admin-ajax.php', $cookies[0]['path'] );
			$this->assertSame( '', $cookies[0]['domain'] );
			$this->assertTrue( $cookies[0]['secure'] );
			$this->assertTrue( $cookies[0]['httponly'] );
			$this->assertSame( 'Strict', $cookies[0]['samesite'] );
			$this->assertSame( 600, $cookies[0]['max_age'] );
			$this->assertSame(
				hash_hmac( 'sha256', 'magicauth-passkey-fresh|' . $cookies[0]['value'], wp_salt( 'auth' ) ),
				$sessions[0]['magicauth_fresh_hash'],
				'the session stores the HMAC of the cookie it was issued with'
			);
		} else {
			$this->assertSame( [], self::fresh_cookies(), $method . ' never proves the mailbox' );
			$this->assertArrayNotHasKey( 'magicauth_fresh_hash', $sessions[0] );
		}
		$this->assertSame( $method, $sessions[0]['magicauth_method'] );
	}

	/** @dataProvider all_methods */
	public function test_setting_on_but_site_unavailable_sends_no_fresh_cookie( string $method ): void {
		self::enable_module();
		update_option( 'magicauth_db_version', 1 );

		$this->assertSame( Login::SIGNED_IN, Login::establish( $this->user, $method ) );

		$this->assertSame( [], self::fresh_cookies() );
		$this->assertArrayNotHasKey( 'magicauth_fresh_hash', self::sessions()[0] );
	}

	/** @dataProvider all_methods */
	public function test_available_site_with_setting_off_sends_no_fresh_cookie( string $method ): void {
		self::enable_module();
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => false ] );

		$this->assertSame( Login::SIGNED_IN, Login::establish( $this->user, $method ) );

		$this->assertSame( [], self::fresh_cookies() );
		$this->assertArrayNotHasKey( 'magicauth_fresh_hash', self::sessions()[0] );
	}

	public function test_enabled_refusals_and_already_send_no_fresh_cookie(): void {
		self::enable_module();
		magicauth_test_login_as( self::USER_ID );
		$this->assertSame( Login::ALREADY, Login::establish( $this->user, 'link' ) );
		$this->assertSame( [], self::fresh_cookies(), 'already signed in' );

		magicauth_test_login_as( 0 );
		update_user_meta( self::USER_ID, 'magicauth_disabled', '1' );
		$this->assertInstanceOf( WP_Error::class, Login::establish( $this->user, 'code' ) );
		$this->assertSame( [], self::fresh_cookies(), 'refused by preflight' );
	}

	/** A sign-in with the module on is fresh in that browser and stale without its cookie. */
	public function test_enabled_link_sign_in_is_fresh_only_with_its_cookie(): void {
		global $magicauth_test_state;
		self::enable_module();
		$this->assertSame( Login::SIGNED_IN, Login::establish( $this->user, 'link' ) );
		$magicauth_test_state['session_token'] = (string) $magicauth_test_state['auth_cookies'][0]['token'];

		$this->assertFalse( \MagicAuth\Passkeys\Freshness::is_fresh(), 'copied session cookie without magicauth_pk_fresh' );
		$_COOKIE['magicauth_pk_fresh'] = self::fresh_cookies()[0]['value'];
		$this->assertTrue( \MagicAuth\Passkeys\Freshness::is_fresh() );
	}

	public function test_constants_match_the_spec(): void {
		$this->assertSame( [ 'link', 'code', 'admin_link', 'password', 'reset', 'passkey' ], Login::METHODS );
		$this->assertSame( [ 'link', 'code', 'admin_link', 'passkey' ], Login::DISABLE_BLOCKS );
		$this->assertSame( 'signed_in', Login::SIGNED_IN );
		$this->assertSame( 'already', Login::ALREADY );
	}

	public function test_unknown_method_is_denied_without_side_effects(): void {
		$result = Login::establish( $this->user, 'shortcode' );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'magicauth_login_denied', $result->get_error_code() );
		$this->assertSame( 0, self::auth_cookie_count() );
		$this->assertFalse( is_user_logged_in() );
	}

	/* -------------------------------------------------- already signed in */

	/** @dataProvider all_methods */
	public function test_same_user_already_signed_in_returns_already_without_cookie( string $method ): void {
		magicauth_test_login_as( self::USER_ID );
		$wp_login  = self::record( 'wp_login', 2 );
		$completed = self::record( 'magicauth_login_completed', 2 );
		$pre       = self::record( 'magicauth_pre_set_auth_cookie', 3 );

		$this->assertSame( Login::ALREADY, Login::establish( $this->user, $method ) );
		$this->assertSame( 0, self::auth_cookie_count() );
		$this->assertSame( [], self::sessions() );
		$this->assertCount( 0, $wp_login );
		$this->assertCount( 0, $completed );
		$this->assertCount( 0, $pre );
		$this->assertSame( '', get_user_meta( self::USER_ID, 'magicauth_email_verified_at', true ) );
	}

	/** @dataProvider all_methods */
	public function test_other_account_signed_in_is_refused_b2( string $method ): void {
		magicauth_test_login_as( self::OTHER_ID );
		$wp_login = self::record( 'wp_login', 2 );

		$pre = Login::preflight( $this->user, $method );
		$this->assertInstanceOf( WP_Error::class, $pre );
		$this->assertSame( 'magicauth_other_account', $pre->get_error_code() );

		$result = Login::establish( $this->user, $method );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'magicauth_other_account', $result->get_error_code() );
		$this->assertSame( 0, self::auth_cookie_count() );
		$this->assertSame( self::OTHER_ID, get_current_user_id(), 'session not swapped' );
		$this->assertCount( 0, $wp_login );
	}

	public function test_other_account_is_checked_before_the_disable_flag(): void {
		magicauth_test_login_as( self::OTHER_ID );
		update_user_meta( self::USER_ID, 'magicauth_disabled', '1' );
		$this->assertSame( 'magicauth_other_account', Login::establish( $this->user, 'link' )->get_error_code() );
	}

	/* --------------------------------------------------------- disable, B3 */

	/** @dataProvider all_methods */
	public function test_disable_flag_blocks_only_disable_block_methods( string $method ): void {
		update_user_meta( self::USER_ID, 'magicauth_disabled', '1' );
		$result = Login::establish( $this->user, $method );

		if ( in_array( $method, [ 'link', 'code', 'admin_link', 'passkey' ], true ) ) {
			$this->assertInstanceOf( WP_Error::class, $result );
			$this->assertSame( 'magicauth_user_disabled', $result->get_error_code() );
			$this->assertSame( 0, self::auth_cookie_count() );
			$this->assertFalse( is_user_logged_in() );
		} else {
			$this->assertSame( Login::SIGNED_IN, $result, $method . ' is not blocked by the per-user disable' );
		}
	}

	/* ------------------------------------------------------ multisite spam */

	/** @dataProvider all_methods */
	public function test_multisite_spammy_user_is_denied_for_every_method( string $method ): void {
		global $magicauth_test_state;
		$magicauth_test_state['multisite']    = true;
		$magicauth_test_state['spammy_users'] = [ self::USER_ID ];

		$result = Login::establish( $this->user, $method );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'magicauth_login_denied', $result->get_error_code() );
		$this->assertSame( 0, self::auth_cookie_count() );
	}

	public function test_spam_flag_is_ignored_on_single_site(): void {
		global $magicauth_test_state;
		$magicauth_test_state['spammy_users'] = [ self::USER_ID ];
		$this->assertSame( Login::SIGNED_IN, Login::establish( $this->user, 'link' ) );
	}

	public function test_multisite_user_who_is_not_spammy_signs_in(): void {
		global $magicauth_test_state;
		$magicauth_test_state['multisite']    = true;
		$magicauth_test_state['spammy_users'] = [ self::OTHER_ID ];
		$this->assertSame( Login::SIGNED_IN, Login::establish( $this->user, 'code' ) );
	}

	/* --------------------------------------------------- magicauth_allow_login */

	/** @return array<string,array{0:mixed}> */
	public static function non_true_filter_values(): array {
		return [
			'false'      => [ false ],
			'int 1'      => [ 1 ],
			'string yes' => [ 'yes' ],
			'null'       => [ null ],
		];
	}

	/**
	 * @dataProvider non_true_filter_values
	 * @param mixed $value
	 */
	public function test_allow_login_filter_anything_but_true_denies( $value ): void {
		add_filter(
			'magicauth_allow_login',
			static function () use ( $value ) {
				return $value;
			}
		);
		$result = Login::establish( $this->user, 'link' );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'magicauth_login_denied', $result->get_error_code() );
		$this->assertSame( 0, self::auth_cookie_count() );
	}

	public function test_allow_login_filter_wp_error_is_passed_as_data_never_as_message(): void {
		$reason = new WP_Error( 'vdm_expired', 'Your access expired on 1 May.' );
		add_filter(
			'magicauth_allow_login',
			static function () use ( $reason ) {
				return $reason;
			}
		);
		$result = Login::preflight( $this->user, 'code' );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'magicauth_login_denied', $result->get_error_code() );
		$this->assertSame( $reason, $result->error_data['magicauth_login_denied'] ?? null );
		$this->assertSame( '', $result->get_error_message() );
	}

	public function test_allow_login_filter_receives_user_and_method(): void {
		$calls = self::record( 'magicauth_allow_login', 3 );
		Login::establish( $this->user, 'reset' );
		$this->assertSame( [ [ true, $this->user, 'reset' ] ], $calls->getArrayCopy() );
	}

	public function test_preflight_has_no_side_effects(): void {
		$wp_login = self::record( 'wp_login', 2 );
		$this->assertTrue( Login::preflight( $this->user, 'link' ) );
		$this->assertSame( 0, self::auth_cookie_count() );
		$this->assertFalse( is_user_logged_in() );
		$this->assertCount( 0, $wp_login );
		$this->assertSame( '', get_user_meta( self::USER_ID, 'magicauth_email_verified_at', true ) );
	}

	/* ------------------------------------------------------ creation stamp */

	public function test_wp_login_callback_issuing_another_cookie_gets_an_unstamped_session(): void {
		// Two-factor plugins and session rotation create a second session on wp_login.
		add_action(
			'wp_login',
			static function ( $login, $user ): void {
				unset( $login );
				wp_set_auth_cookie( (int) $user->ID, true );
			},
			10,
			2
		);

		$this->assertSame( Login::SIGNED_IN, Login::establish( $this->user, 'code' ) );

		$sessions = self::sessions();
		$this->assertCount( 2, $sessions );
		$this->assertSame( 'code', $sessions[0]['magicauth_method'] );
		$this->assertArrayNotHasKey( 'magicauth_method', $sessions[1] );
		$this->assertArrayNotHasKey( 'magicauth_auth_at', $sessions[1] );
	}

	public function test_stamp_filter_is_removed_before_wp_login(): void {
		$seen = null;
		add_action(
			'wp_login',
			static function () use ( &$seen ): void {
				$seen = has_filter( 'attach_session_information' );
			}
		);
		Login::establish( $this->user, 'link' );
		$this->assertFalse( $seen );
	}

	public function test_session_of_another_user_created_during_establish_is_not_stamped(): void {
		add_action(
			'magicauth_pre_set_auth_cookie',
			static function (): void {
				\WP_Session_Tokens::get_instance( self::OTHER_ID )->create( self::NOW + 60 );
			}
		);
		Login::establish( $this->user, 'link' );

		$other = self::sessions( self::OTHER_ID );
		$this->assertCount( 1, $other );
		$this->assertArrayNotHasKey( 'magicauth_method', $other[0] );
		$this->assertSame( 'link', self::sessions()[0]['magicauth_method'] );
	}

	public function test_existing_stamp_keys_from_other_filters_are_overwritten_by_ours(): void {
		add_filter(
			'attach_session_information',
			static function ( $session ) {
				$session['magicauth_method'] = 'passkey';
				return $session;
			},
			5
		);
		Login::establish( $this->user, 'password' );
		$this->assertSame( 'password', self::sessions()[0]['magicauth_method'] );
	}

	/* ------------------------------------------------------- cookie failure */

	public function test_cookie_throw_gives_cookie_failed_and_removes_the_filter(): void {
		global $magicauth_test_state;
		$magicauth_test_state['auth_cookie_throws'] = new \RuntimeException( 'headers sent' );
		$wp_login  = self::record( 'wp_login', 2 );
		$completed = self::record( 'magicauth_login_completed', 2 );

		$result = Login::establish( $this->user, 'link' );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'magicauth_cookie_failed', $result->get_error_code() );
		$this->assertFalse( has_filter( 'attach_session_information' ), 'removed after a throw' );
		$this->assertFalse( is_user_logged_in() );
		$this->assertCount( 0, $wp_login );
		$this->assertCount( 0, $completed );
		$this->assertSame( '', get_user_meta( self::USER_ID, 'magicauth_email_verified_at', true ) );

		// The next session for this user is not stamped by a leftover closure.
		unset( $magicauth_test_state['auth_cookie_throws'] );
		\WP_Session_Tokens::get_instance( self::USER_ID )->create( self::NOW + 60 );
		$this->assertArrayNotHasKey( 'magicauth_method', self::sessions()[0] );
	}

	public function test_error_thrown_type_is_caught_too(): void {
		global $magicauth_test_state;
		$magicauth_test_state['auth_cookie_throws'] = new \TypeError( 'bad' );
		$this->assertSame( 'magicauth_cookie_failed', Login::establish( $this->user, 'code' )->get_error_code() );
	}

	/* -------------------------------------------------------- hook arguments */

	/** @dataProvider all_methods */
	public function test_pre_set_auth_cookie_and_remember_default_receive_method( string $method ): void {
		$pre      = self::record( 'magicauth_pre_set_auth_cookie', 3 );
		$remember = self::record( 'magicauth_remember_default', 2 );

		Login::establish( $this->user, $method );

		$this->assertSame( [ [ self::USER_ID, 'shortcode', $method ] ], $pre->getArrayCopy() );
		$this->assertSame( [ [ true, $method ] ], $remember->getArrayCopy() );
	}

	public function test_old_two_argument_callbacks_still_work(): void {
		$pre = self::record( 'magicauth_pre_set_auth_cookie', 2 );
		Login::establish( $this->user, 'code' );
		$this->assertSame( [ [ self::USER_ID, 'shortcode' ] ], $pre->getArrayCopy() );
	}

	public function test_remember_default_filter_value_is_used(): void {
		add_filter(
			'magicauth_remember_default',
			static function ( $remember, $method ) {
				return 'password' === $method ? false : $remember;
			},
			10,
			2
		);
		Login::establish( $this->user, 'password' );

		global $magicauth_test_state;
		$this->assertFalse( $magicauth_test_state['auth_cookies'][0]['remember'] );
	}

	/** @dataProvider all_methods */
	public function test_redirect_filter_receives_method( string $method ): void {
		$calls  = self::record( 'magicauth_redirect_to', 4 );
		$target = Login::redirect_target( $this->user, 'https://example.test/course/', $method );

		$this->assertSame( 'https://example.test/course/', $target );
		$this->assertSame( [ [ 'https://example.test/course/', $this->user, 'shortcode', $method ] ], $calls->getArrayCopy() );
	}

	/* ------------------------------------------------- email verified stamp */

	/** @dataProvider all_methods */
	public function test_email_verified_at_is_stamped_for_link_and_code_only( string $method ): void {
		Login::establish( $this->user, $method );

		$stamped = get_user_meta( self::USER_ID, 'magicauth_email_verified_at', true );
		if ( 'link' === $method || 'code' === $method ) {
			$this->assertSame( self::NOW, $stamped );
		} else {
			$this->assertSame( '', $stamped, $method . ' never proves the mailbox' );
		}
	}

	/* ------------------------------------------------------- A->B session */

	public function test_establish_ends_the_a_to_b_session(): void {
		set_transient( 'magicauth_session_abc123', [ 'email' => 'learner@example.test' ], 1800 );
		$_COOKIE['magicauth_session'] = 'abc123';

		Login::establish( $this->user, 'code' );

		$this->assertFalse( get_transient( 'magicauth_session_abc123' ) );
	}

	public function test_refused_sign_in_keeps_the_a_to_b_session(): void {
		set_transient( 'magicauth_session_abc123', [ 'email' => 'learner@example.test' ], 1800 );
		$_COOKIE['magicauth_session'] = 'abc123';
		update_user_meta( self::USER_ID, 'magicauth_disabled', '1' );

		Login::establish( $this->user, 'code' );

		$this->assertIsArray( get_transient( 'magicauth_session_abc123' ) );
	}

	/* -------------------------------------------------------- rule E (7.6) */

	private static function reverify_days( int $days ): void {
		update_option( 'magicauth_settings', [ 'passkeys_email_reverify_days' => $days ] );
	}

	public function test_rule_e_off_by_default(): void {
		$this->assertTrue( Login::preflight( $this->user, 'passkey' ), 'missing email_verified_at is fine while N = 0' );
	}

	public function test_rule_e_requires_reverification_after_n_days(): void {
		self::reverify_days( 30 );
		update_user_meta( self::USER_ID, 'magicauth_email_verified_at', self::NOW - 30 * DAY_IN_SECONDS );
		$this->assertTrue( Login::preflight( $this->user, 'passkey' ), 'boundary: exactly N days is still fine' );

		update_user_meta( self::USER_ID, 'magicauth_email_verified_at', self::NOW - 30 * DAY_IN_SECONDS - 1 );
		$result = Login::preflight( $this->user, 'passkey' );
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'magicauth_reverify_required', $result->get_error_code() );
	}

	public function test_rule_e_missing_verified_at_counts_as_zero(): void {
		self::reverify_days( 1 );
		$this->assertSame( 'magicauth_reverify_required', Login::preflight( $this->user, 'passkey' )->get_error_code() );
	}

	public function test_rule_e_applies_to_passkey_only(): void {
		self::reverify_days( 1 );
		foreach ( [ 'link', 'code', 'admin_link', 'password', 'reset' ] as $method ) {
			$this->assertTrue( Login::preflight( $this->user, $method ), $method );
		}
	}

	public function test_rule_e_duplicate_email_account_fails_generic_not_reverify(): void {
		self::reverify_days( 1 );
		// Another account holds the same address and is found first by email.
		global $magicauth_test_state;
		$dupe  = new WP_User( 5, 'learner@example.test', [ 'subscriber' ] );
		$users = $magicauth_test_state['users'];
		$magicauth_test_state['users'] = [ 5 => $dupe ] + $users;

		$this->assertSame( 'magicauth_login_denied', Login::preflight( $this->user, 'passkey' )->get_error_code() );
	}

	public function test_rule_e_setting_is_clamped_to_730_days(): void {
		self::reverify_days( 100000 );
		update_user_meta( self::USER_ID, 'magicauth_email_verified_at', self::NOW - 731 * DAY_IN_SECONDS );
		$this->assertSame( 'magicauth_reverify_required', Login::preflight( $this->user, 'passkey' )->get_error_code() );
	}

	/* ------------------------------------------------------ redirect_target */

	private static function deny_redirect_filter( string $value ): void {
		add_filter(
			'magicauth_redirect_to',
			static function () use ( $value ): string {
				return $value;
			}
		);
	}

	public function test_redirect_filter_returning_a_foreign_host_falls_back_home(): void {
		self::deny_redirect_filter( 'https://evil.example/' );
		$this->assertSame( 'https://example.test/', Login::redirect_target( $this->user, '', 'link' ) );
	}

	public function test_redirect_filter_returning_javascript_falls_back_home(): void {
		self::deny_redirect_filter( 'javascript:alert(1)' );
		$this->assertSame( 'https://example.test/', Login::redirect_target( $this->user, '', 'code' ) );
	}

	public function test_redirect_filter_returning_wp_login_falls_back_home(): void {
		self::deny_redirect_filter( 'https://example.test/wp-login.php?action=logout' );
		$this->assertSame( 'https://example.test/', Login::redirect_target( $this->user, '', 'passkey' ) );
	}

	public function test_redirect_filter_returning_empty_falls_back_home(): void {
		self::deny_redirect_filter( '' );
		$this->assertSame( 'https://example.test/', Login::redirect_target( $this->user, '', 'passkey' ) );
	}

	public function test_wp_login_redirect_to_is_dropped_for_the_default(): void {
		update_option( 'magicauth_settings', [ 'redirect_to_default' => 'home' ] );
		$this->assertSame( 'https://example.test/', Login::redirect_target( $this->user, 'https://example.test/wp-login.php', 'link' ) );
		$this->assertSame( 'https://example.test/', Login::redirect_target( $this->user, 'https://example.test/WP-LOGIN.PHP?x=1', 'link' ) );
	}

	public function test_foreign_redirect_to_is_dropped_for_the_default(): void {
		update_option( 'magicauth_settings', [ 'redirect_to_default' => 'home' ] );
		$this->assertSame( 'https://example.test/', Login::redirect_target( $this->user, 'https://evil.example/x', 'link' ) );
	}

	public function test_same_host_redirect_to_is_kept(): void {
		$this->assertSame( 'https://example.test/course/1/', Login::redirect_target( $this->user, 'https://example.test/course/1/', 'code' ) );
	}

	public function test_default_follows_the_setting(): void {
		// auto: the subscriber can read, so the dashboard (1.0.5 behaviour).
		$this->assertSame( admin_url(), Login::redirect_target( $this->user, '', 'link' ) );
		$this->assertSame( 'https://example.test/', Login::redirect_target( null, '', 'link' ), 'no user: home' );

		update_option( 'magicauth_settings', [ 'redirect_to_default' => 'home' ] );
		$this->assertSame( 'https://example.test/', Login::redirect_target( $this->user, '', 'link' ) );

		update_option( 'magicauth_settings', [ 'redirect_to_default' => 'admin' ] );
		$this->assertSame( admin_url(), Login::redirect_target( null, '', 'link' ) );
	}

	/**
	 * r1-regress-03: home on www, admin on the bare host, no
	 * allowed_redirect_hosts. The dashboard default still lands on admin_url()
	 * (wp_safe_redirect's own fallback, the 1.0.5 result), not home.
	 */
	public function test_admin_default_on_another_host_lands_on_the_dashboard(): void {
		global $magicauth_test_state;
		$magicauth_test_state['home']    = 'https://www.example.test';
		$magicauth_test_state['siteurl'] = 'https://example.test';
		$admin                           = admin_url();
		$this->assertSame( 'example.test', parse_url( $admin, PHP_URL_HOST ) );

		$this->assertSame( $admin, Login::redirect_target( $this->user, '', 'link' ), 'auto, user can read' );
		update_option( 'magicauth_settings', [ 'redirect_to_default' => 'admin' ] );
		$this->assertSame( $admin, Login::redirect_target( null, '', 'code' ), 'admin setting' );
		$this->assertSame( $admin, Login::redirect_target( $this->user, 'https://evil.example/x', 'link' ), 'rejected redirect_to falls back to the default' );

		// Only admin_url() itself; another path on that host is still refused.
		self::deny_redirect_filter( 'https://example.test/wp-admin/profile.php' );
		$this->assertSame( home_url( '/' ), Login::redirect_target( $this->user, '', 'link' ) );
	}

	public function test_sanitize_redirect(): void {
		$this->assertSame( 'https://example.test/', Login::sanitize_redirect( '' ) );
		$this->assertSame( 'https://example.test/', Login::sanitize_redirect( '   ' ) );
		$this->assertSame( 'https://example.test/', Login::sanitize_redirect( 'https://evil.example/' ) );
		$this->assertSame( 'https://example.test/', Login::sanitize_redirect( 'javascript:alert(1)' ) );
		$this->assertSame( 'https://example.test/a/', Login::sanitize_redirect( ' https://example.test/a/ ' ) );
	}
}
