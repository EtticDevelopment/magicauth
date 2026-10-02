<?php
/**
 * Rule M and sign-in tokens (review r1-session-01): rule M (SPEC 7.6) must end every proof the old
 * mailbox holds. A link or code issued to the old address before an email
 * change must not sign in afterwards, and a sign-in made with one must not
 * count as fresh or re-stamp magicauth_email_verified_at.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Auth\Login;
use MagicAuth\Auth\TokenManager;
use MagicAuth\Passkeys\Clock;
use MagicAuth\Passkeys\Freshness;
use MagicAuth\Passkeys\Module;
use MagicAuth\Tests\Support\Ceremony;
use PHPUnit\Framework\TestCase;
use WP_Error;
use WP_User;

final class EmailChangeTokensTest extends TestCase {

	private WP_User $user;

	/** @var array<string,mixed> */
	private array $server = [];

	protected function setUp(): void {
		$this->server = $_SERVER;
		Ceremony::site();
		update_option(
			'magicauth_settings',
			[
				'passkeys_enabled' => true,
				'company_name'     => 'Example Academy',
			]
		);
		Module::reset_for_tests();
		$this->user = Ceremony::user( 7 );
		Module::setup();
		$_COOKIE = [];
	}

	protected function tearDown(): void {
		$_SERVER  = $this->server;
		$_POST    = [];
		$_REQUEST = [];
		$_COOKIE  = [];
		magicauth_test_reset_state();
	}

	/** @return array{0:string,1:string} */
	private static function sel_ver( string $url ): array {
		parse_str( (string) parse_url( $url, PHP_URL_QUERY ), $args );
		return [ (string) ( $args['s'] ?? '' ), (string) ( $args['v'] ?? '' ) ];
	}

	/** An administrator changes user 7's email; rule M runs; then nobody is signed in. */
	private static function admin_changes_email(): void {
		self::admin_changes_email_to( 'successor7@example.test' );
	}

	private static function admin_changes_email_to( string $email ): void {
		global $magicauth_test_state;
		magicauth_test_register_user( 1, 'admin@example.test', [ 'administrator' ] );
		magicauth_test_login_as( 1 );
		wp_update_user( [ 'ID' => 7, 'user_email' => $email ] );
		magicauth_test_login_as( 0 );
		unset( $magicauth_test_state['session_token'] );
	}

	public function test_old_mailbox_link_dies_on_email_change(): void {
		$issued = TokenManager::issue( 7, 'learner7@example.test' );
		$this->assertIsArray( $issued );
		[ $sel, $ver ] = self::sel_ver( $issued['link_url'] );

		// T0: the former holder signs in by link (use 1 of max_link_uses 2).
		$this->assertInstanceOf( WP_User::class, TokenManager::validate_link( $sel, $ver ) );

		Clock::set_for_tests( Ceremony::NOW + 120 );
		self::admin_changes_email();
		$this->assertSame( Ceremony::NOW + 120, get_user_meta( 7, 'magicauth_email_changed_at', true ), 'rule M ran' );

		// T0+3 min: the same link again.
		Clock::set_for_tests( Ceremony::NOW + 180 );
		$again = TokenManager::validate_link( $sel, $ver );
		$this->assertInstanceOf( WP_Error::class, $again, 'a link sent to the old mailbox must not sign in after rule M' );
	}

	public function test_old_mailbox_code_dies_on_email_change(): void {
		$issued = TokenManager::issue( 7, 'learner7@example.test' );
		$this->assertIsArray( $issued );
		$sid = bin2hex( random_bytes( 16 ) );
		set_transient(
			'magicauth_session_' . $sid,
			[
				'email'    => 'learner7@example.test',
				'selector' => (string) $issued['selector'],
				'attempts' => 0,
			],
			30 * MINUTE_IN_SECONDS
		);

		Clock::set_for_tests( Ceremony::NOW + 120 );
		self::admin_changes_email();

		$result = TokenManager::validate_code( 'learner7@example.test', $issued['code_plaintext'], $sid );
		$this->assertInstanceOf( WP_Error::class, $result, 'a code sent to the old mailbox must not sign in after rule M' );
	}

	public function test_old_mailbox_link_after_change_yields_no_fresh_session(): void {
		global $magicauth_test_state;
		$issued = TokenManager::issue( 7, 'learner7@example.test' );
		$this->assertIsArray( $issued );
		[ $sel, $ver ] = self::sel_ver( $issued['link_url'] );
		$this->assertInstanceOf( WP_User::class, TokenManager::validate_link( $sel, $ver ) );

		Clock::set_for_tests( Ceremony::NOW + 120 );
		self::admin_changes_email();

		Clock::set_for_tests( Ceremony::NOW + 180 );
		$user = TokenManager::validate_link( $sel, $ver );
		if ( ! $user instanceof WP_User ) {
			$this->assertInstanceOf( WP_Error::class, $user );
			return; // Fixed at the token layer: nothing to establish.
		}

		// What Controller does with a valid link: establish('link').
		$magicauth_test_state['cookies'] = [];
		$this->assertSame( Login::SIGNED_IN, Login::establish( $user, 'link' ) );
		$cookies = $magicauth_test_state['auth_cookies'];
		$magicauth_test_state['session_token'] = (string) end( $cookies )['token'];
		foreach ( $magicauth_test_state['cookies'] ?? [] as $c ) {
			if ( Freshness::COOKIE === ( $c['name'] ?? '' ) ) {
				$_COOKIE[ Freshness::COOKIE ] = $c['value'];
			}
		}

		$this->assertFalse( Freshness::is_fresh(), 'old-mailbox proof must not be fresh after the email change' );
		$this->assertSame( '', get_user_meta( 7, 'magicauth_email_verified_at', true ), 'rule E stamp must not come back from the old mailbox' );

		// The concrete impact: the former holder can start passkey creation.
		Ceremony::account_post();
		$r = Ceremony::call( 'register_options' );
		$this->assertNotSame( 200, $r['status'], 'register_options must refuse: ' . $r['body'] );
	}
	public function test_tokens_die_even_when_the_passkey_filter_keeps_passkeys(): void {
		add_filter( 'magicauth_passkey_revoke_on_email_change', '__return_false' );
		$issued = TokenManager::issue( 7, 'learner7@example.test' );
		$this->assertIsArray( $issued );
		[ $sel, $ver ] = self::sel_ver( $issued['link_url'] );

		self::admin_changes_email();
		$this->assertSame( '', get_user_meta( 7, 'magicauth_email_changed_at', true ), 'rule M did not run' );
		$this->assertInstanceOf( WP_Error::class, TokenManager::validate_link( $sel, $ver ) );
	}

	public function test_change_that_bypasses_profile_update_still_refuses_the_old_mailbox(): void {
		$issued = TokenManager::issue( 7, 'learner7@example.test' );
		$this->assertIsArray( $issued );
		[ $sel, $ver ] = self::sel_ver( $issued['link_url'] );
		$sid = bin2hex( random_bytes( 16 ) );
		set_transient(
			'magicauth_session_' . $sid,
			[
				'email'    => 'learner7@example.test',
				'selector' => (string) $issued['selector'],
				'attempts' => 0,
			],
			30 * MINUTE_IN_SECONDS
		);

		// Direct SQL or an importer: no profile_update, no rule M, rows untouched.
		$this->user->user_email = 'successor7@example.test';

		$this->assertInstanceOf( WP_Error::class, TokenManager::validate_code( 'learner7@example.test', $issued['code_plaintext'], $sid ) );
		$this->assertInstanceOf( WP_Error::class, TokenManager::validate_link( $sel, $ver ) );
	}

	public function test_case_only_change_keeps_the_link(): void {
		$issued = TokenManager::issue( 7, 'learner7@example.test' );
		$this->assertIsArray( $issued );
		[ $sel, $ver ] = self::sel_ver( $issued['link_url'] );

		self::admin_changes_email_to( 'Learner7@Example.test' );
		$this->assertInstanceOf( WP_User::class, TokenManager::validate_link( $sel, $ver ) );
	}

	public function test_successor_tokens_issued_after_the_change_sign_in(): void {
		self::admin_changes_email();
		$issued = TokenManager::issue( 7, 'successor7@example.test' );
		$this->assertIsArray( $issued );
		[ $sel, $ver ] = self::sel_ver( $issued['link_url'] );
		$this->assertInstanceOf( WP_User::class, TokenManager::validate_link( $sel, $ver ) );
	}
}
