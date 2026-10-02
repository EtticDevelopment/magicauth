<?php
/**
 * T-ACCT (SPEC 7.6 rule M, 4.6, 10.4, 14.1, build step 13): an email-address
 * change revokes every passkey, ends the old mailbox's proof (email
 * verification, challenges, step-up stamps), mails the old and the new
 * address and fires magicauth_passkeys_revoked. Case-only and display-name
 * changes do nothing; the filter can keep the passkeys.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Passkeys\AccountEvents;
use MagicAuth\Passkeys\ChallengeStore;
use MagicAuth\Passkeys\Clock;
use MagicAuth\Passkeys\CredentialStore;
use MagicAuth\Passkeys\Module;
use MagicAuth\Passkeys\SessionState;
use MagicAuth\Tests\Support\Ceremony;
use MagicAuth\Tests\Support\SoftAuthenticator;
use PHPUnit\Framework\TestCase;
use WP_User;

final class AccountEventsTest extends TestCase {

	private WP_User $user;

	private WP_User $other;

	/** @var array<string,mixed> */
	private array $server = [];

	protected function setUp(): void {
		$this->server = $_SERVER;
		Ceremony::site();
		update_option( 'magicauth_settings', [ 'company_name' => 'Example Academy' ] );
		$this->user  = Ceremony::user( 7 );
		$this->other = Ceremony::user( 8 );
		Module::setup();
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

	private static function enrol( WP_User $user ): int {
		return Ceremony::enrol( new SoftAuthenticator( 'ES256' ), $user );
	}

	private static function count_rows( string $table, int $uid ): int {
		global $wpdb;
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE user_id = %d", $uid ) );
	}

	/** @return array<int,array<string,mixed>> */
	private static function mails(): array {
		global $magicauth_test_state;
		return $magicauth_test_state['mail'] ?? [];
	}

	/** Signs $user in, stamps a step-up on that session and returns the session hash. */
	private static function stamped_session( WP_User $user ): string {
		Ceremony::sign_in( $user, 'password', Ceremony::NOW - 3600 );
		self::assertTrue( SessionState::stamp_reauth( 'email_code' ) );
		self::assertTrue( SessionState::set( 'prompt_done', 1 ) );
		return \MagicAuth\Passkeys\Freshness::session_hash();
	}

	/** @return array<string,mixed>|null */
	private static function state_row( string $hash ): ?array {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . SessionState::table() . ' WHERE session_hash = %s', $hash ), ARRAY_A );
		return is_array( $row ) ? $row : null;
	}

	/* ------------------------------------------------------------- rule M */

	public function test_email_change_revokes_everything_the_old_mailbox_proved(): void {
		self::enrol( $this->user );
		self::enrol( $this->user );
		// A former ID holder's row (snapshot differs): invisible, but its user_id goes too.
		$this->user->user_registered = '2025-01-01 10:00:00';
		self::enrol( $this->user );
		$this->user->user_registered = Ceremony::REGISTERED;
		self::enrol( $this->other );

		update_user_meta( 7, 'magicauth_email_verified_at', Ceremony::NOW - 50 );
		update_user_meta( 8, 'magicauth_email_verified_at', Ceremony::NOW - 50 );
		ChallengeStore::issue( 'register', 7, Ceremony::SESSION, '', '-7', 420, 'aGFuZGxl' );
		ChallengeStore::issue( 'reauth', 7, Ceremony::SESSION, '', '', 420 );
		ChallengeStore::issue_code( 7, Ceremony::SESSION );
		ChallengeStore::issue( 'complete', 7, '', Ceremony::COOKIE, '', 120 );
		ChallengeStore::issue( 'reauth', 8, Ceremony::SESSION, '', '', 420 );
		$their_challenges = self::count_rows( ChallengeStore::table(), 8 );
		$theirs           = self::stamped_session( $this->other );
		$mine   = self::stamped_session( $this->user );
		$mine2  = self::stamped_session( $this->user );

		$fired = [];
		add_action(
			'magicauth_passkeys_revoked',
			static function ( ...$args ) use ( &$fired ) {
				$fired[] = $args;
			},
			10,
			4
		);
		magicauth_test_register_user( 1, 'admin@example.test', [ 'administrator' ] );
		magicauth_test_login_as( 1 ); // An administrator edits the profile.
		Clock::set_for_tests( Ceremony::NOW + 60 );
		$this->assertSame( 7, wp_update_user( [ 'ID' => 7, 'user_email' => 'new7@example.test' ] ) );

		$this->assertSame( 0, self::count_rows( CredentialStore::table(), 7 ), 'every row, snapshot or not' );
		$this->assertSame( 1, self::count_rows( CredentialStore::table(), 8 ) );
		$this->assertSame( '', get_user_meta( 7, 'magicauth_email_verified_at', true ) );
		$this->assertSame( Ceremony::NOW - 50, get_user_meta( 8, 'magicauth_email_verified_at', true ) );
		$this->assertSame( Ceremony::NOW + 60, get_user_meta( 7, 'magicauth_email_changed_at', true ) );
		$this->assertSame( 0, self::count_rows( ChallengeStore::table(), 7 ), 'all ceremonies' );
		$this->assertSame( $their_challenges, self::count_rows( ChallengeStore::table(), 8 ) );
		foreach ( [ $mine, $mine2 ] as $hash ) {
			$row = self::state_row( $hash );
			$this->assertSame( '0', (string) $row['reauth_at'] );
			$this->assertSame( '', $row['reauth_method'] );
			$this->assertSame( '', $row['fresh_hash'] );
			$this->assertSame( '1', (string) $row['prompt_done'], 'only the step-up is cleared' );
		}
		$theirs_row = self::state_row( $theirs );
		$this->assertNotSame( '0', (string) $theirs_row['reauth_at'] );
		$this->assertSame( 64, strlen( $theirs_row['fresh_hash'] ) );

		$this->assertSame( [ [ 7, 1, 3, 'email_change' ] ], $fired );
		$mails = self::mails();
		$this->assertCount( 2, $mails, 'one mail per address' );
		$this->assertSame( [ 'learner7@example.test', 'new7@example.test' ], array_column( $mails, 'to' ) );
		foreach ( $mails as $mail ) {
			$this->assertSame( '3 passkeys were removed from your Example Academy account', $mail['subject'] );
			$this->assertStringContainsString( 'Your passkeys were removed because the email address of your account changed.', $mail['alt_body'] );
			$this->assertStringNotContainsString( 'learner7@', $mail['alt_body'] );
			$this->assertStringNotContainsString( 'new7@', $mail['alt_body'] );
		}
	}

	public function test_link_session_before_the_change_cannot_add_and_has_no_step_up(): void {
		Ceremony::enable_module();
		update_option(
			'magicauth_settings',
			[
				'passkeys_enabled' => true,
				'company_name'     => 'Example Academy',
			]
		);
		Module::reset_for_tests();
		self::enrol( $this->user );
		Ceremony::sign_in( $this->user, 'link', Ceremony::NOW );

		Clock::set_for_tests( Ceremony::NOW + 120 );
		wp_update_user( [ 'ID' => 7, 'user_email' => 'new7@example.test' ] );

		Clock::set_for_tests( Ceremony::NOW + 300 );
		Ceremony::account_post();
		$r = Ceremony::call( 'register_options' );
		$this->assertSame( 403, $r['status'], $r['body'] );
		$this->assertSame( 'reauth_required', $r['data']['code'] );
		$this->assertSame( [], $r['data']['methods'], 'no passkey left, no code from a mailbox set after this session' );
	}

	public function test_case_only_change_does_nothing(): void {
		$id = self::enrol( $this->user );
		update_user_meta( 7, 'magicauth_email_verified_at', 5 );
		wp_update_user( [ 'ID' => 7, 'user_email' => 'LEARNER7@Example.TEST' ] );
		$this->assertNotNull( Ceremony::row( $id ) );
		$this->assertSame( 5, get_user_meta( 7, 'magicauth_email_verified_at', true ) );
		$this->assertSame( '', get_user_meta( 7, 'magicauth_email_changed_at', true ) );
		$this->assertSame( [], self::mails() );
	}

	public function test_display_name_change_does_nothing(): void {
		$id    = self::enrol( $this->user );
		$fired = 0;
		add_action(
			'magicauth_passkeys_revoked',
			static function () use ( &$fired ) {
				++$fired;
			}
		);
		wp_update_user( [ 'ID' => 7, 'display_name' => 'Someone Else' ] );
		$this->assertNotNull( Ceremony::row( $id ) );
		$this->assertSame( '', get_user_meta( 7, 'magicauth_email_changed_at', true ) );
		$this->assertSame( 0, $fired );
		$this->assertSame( [], self::mails() );
	}

	public function test_filter_false_keeps_passkeys_and_sets_no_marker(): void {
		$id   = self::enrol( $this->user );
		$seen = null;
		add_filter(
			'magicauth_passkey_revoke_on_email_change',
			static function ( $revoke, $user, $old ) use ( &$seen ) {
				$seen = [ $revoke, $user->user_email, $old->user_email ];
				return false;
			},
			10,
			3
		);
		update_user_meta( 7, 'magicauth_email_verified_at', 5 );
		wp_update_user( [ 'ID' => 7, 'user_email' => 'new7@example.test' ] );

		$this->assertSame( [ true, 'new7@example.test', 'learner7@example.test' ], $seen );
		$this->assertNotNull( Ceremony::row( $id ) );
		$this->assertSame( '', get_user_meta( 7, 'magicauth_email_changed_at', true ) );
		$this->assertSame( 5, get_user_meta( 7, 'magicauth_email_verified_at', true ) );
		$this->assertSame( [], self::mails() );
	}

	public function test_filter_must_return_literal_true_semantics(): void {
		$id = self::enrol( $this->user );
		add_filter(
			'magicauth_passkey_revoke_on_email_change',
			static function () {
				return 0;
			}
		);
		wp_update_user( [ 'ID' => 7, 'user_email' => 'new7@example.test' ] );
		$this->assertNotNull( Ceremony::row( $id ), 'a falsy value keeps them' );
	}

	public function test_change_without_passkeys_sends_no_email_but_ends_the_old_proof(): void {
		update_user_meta( 7, 'magicauth_email_verified_at', 5 );
		$fired = [];
		add_action(
			'magicauth_passkeys_revoked',
			static function ( ...$args ) use ( &$fired ) {
				$fired[] = $args;
			},
			10,
			4
		);
		wp_update_user( [ 'ID' => 7, 'user_email' => 'new7@example.test' ] );
		$this->assertSame( [], self::mails() );
		$this->assertSame( '', get_user_meta( 7, 'magicauth_email_verified_at', true ) );
		$this->assertSame( Ceremony::NOW, get_user_meta( 7, 'magicauth_email_changed_at', true ) );
		$this->assertSame( [ [ 7, 0, 0, 'email_change' ] ], $fired );
	}

	public function test_delete_failure_still_ends_the_old_proof(): void {
		global $wpdb;
		$id = self::enrol( $this->user );
		ChallengeStore::issue( 'reauth', 7, Ceremony::SESSION, '', '', 420 );
		$wpdb->fail_next_query( 'DELETE FROM ' . CredentialStore::table() );
		$wpdb->show_errors( true );
		ob_start();
		wp_update_user( [ 'ID' => 7, 'user_email' => 'new7@example.test' ] );
		$this->assertSame( '', ob_get_clean(), 'nothing printed' );
		$this->assertNotNull( Ceremony::row( $id ) );
		$this->assertSame( Ceremony::NOW, get_user_meta( 7, 'magicauth_email_changed_at', true ) );
		$this->assertSame( 0, self::count_rows( ChallengeStore::table(), 7 ) );
		$this->assertSame( [], self::mails() );
	}

	public function test_registered_always_with_three_arguments(): void {
		$this->assertFalse( Module::enabled() );
		$this->assertSame( 10, has_action( 'profile_update', [ AccountEvents::class, 'on_profile_update' ] ) );
		$entries = magicauth_test_hook_entries( 'profile_update' );
		$this->assertSame( 3, $entries[0][1] ?? null, 'accepted_args' );
	}

	public function test_unusable_arguments_do_nothing(): void {
		$id = self::enrol( $this->user );
		AccountEvents::on_profile_update( 7, null, [] );
		AccountEvents::on_profile_update( 0, clone $this->user, [] );
		AccountEvents::on_profile_update( 999, clone $this->user, [] );
		$this->assertNotNull( Ceremony::row( $id ) );
	}
}
