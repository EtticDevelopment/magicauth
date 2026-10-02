<?php
/**
 * Review r1-data-01: rule M (SPEC 7.6) is a one-shot per-site DELETE with no
 * sign-in-time backstop. A credential row that survives it (failed DELETE,
 * register race, another site's table on multisite) keeps signing in after
 * the email change, although 7.6 says a synced passkey of the former holder
 * "no longer opens the successor's account".
 *
 * Fixed: CredentialStore::revoked() (created_at at or before the network-wide
 * magicauth_email_changed_at) is refused at A-9 and step-up, hidden from
 * for_user(), count_for_user() and rename(), and purged when presented;
 * store_registration() re-reads the change time after its INSERT. Review
 * r2-crypto-01: the privacy eraser keeps that time on multisite.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Passkeys\ChallengeStore;
use MagicAuth\Passkeys\Clock;
use MagicAuth\Passkeys\CredentialStore;
use MagicAuth\Passkeys\Module;
use MagicAuth\Passkeys\Options;
use MagicAuth\Passkeys\Privacy;
use MagicAuth\Passkeys\Verifier;
use MagicAuth\Tests\Support\Ceremony;
use MagicAuth\Tests\Support\SoftAuthenticator;
use PHPUnit\Framework\TestCase;
use WP_Error;
use WP_User;

final class RuleMBackstopTest extends TestCase {

	private WP_User $user;

	protected function setUp(): void {
		Ceremony::site();
		$this->user = Ceremony::user( 7 );
		Module::setup(); // profile_update -> AccountEvents::on_profile_update (always registered).
	}

	protected function tearDown(): void {
		global $wpdb, $magicauth_test_state;
		if ( 'wp_' !== $wpdb->prefix ) {
			$wpdb->prefix = 'wp_';
		}
		foreach ( [ 'magicauth_passkeys', 'magicauth_passkey_challenges', 'magicauth_passkey_sessions' ] as $name ) {
			if ( $wpdb->table_exists( 'wp_3_' . $name ) ) {
				$wpdb->query( 'DROP TABLE wp_3_' . $name );
			}
		}
		unset( $magicauth_test_state['multisite'], $magicauth_test_state['subdomain_install'] );
		$wpdb->show_errors( false );
		magicauth_test_reset_state();
	}

	/** @return array<string,mixed>|WP_Error */
	private static function sign_in( SoftAuthenticator $auth ) {
		return Verifier::verify_assertion( Ceremony::assertion( $auth ), Ceremony::COOKIE );
	}

	private static function device(): SoftAuthenticator {
		return new SoftAuthenticator(
			'ES256',
			[
				'be' => true,
				'bs' => true,
			]
		);
	}

	private function change_email(): void {
		Clock::set_for_tests( Ceremony::NOW + 60 );
		$this->assertSame( 7, wp_update_user( [ 'ID' => 7, 'user_email' => 'successor@example.test' ] ) );
		$this->assertSame( Ceremony::NOW + 60, (int) get_user_meta( 7, 'magicauth_email_changed_at', true ) );
		Clock::set_for_tests( Ceremony::NOW + 120 );
	}

	/** Case (1): rule M's DELETE fails; the row survives and still signs in. */
	public function test_row_surviving_a_failed_rule_m_delete_does_not_sign_in(): void {
		global $wpdb;
		$auth = self::device();
		$id   = Ceremony::enrol( $auth, $this->user );

		$wpdb->fail_next_query( 'DELETE FROM ' . CredentialStore::table() );
		$this->change_email();
		$this->assertNotNull( Ceremony::row( $id ), 'precondition: the DELETE failed' );

		$result = self::sign_in( $auth );
		$this->assertInstanceOf( WP_Error::class, $result, 'a passkey created before the email change must not open the account after it' );
		$this->assertSame( 'passkey_failed', $result->get_error_code() );
		$this->assertNull( Ceremony::row( $id ), 'the revoked row is purged when presented' );
	}

	/** Case (2): R-11 passed before rule M, the INSERT lands after its DELETE. */
	public function test_registration_racing_rule_m_does_not_leave_a_working_passkey(): void {
		$auth   = self::device();
		$record = Verifier::verify_registration( Ceremony::registration( $auth, $this->user ), $this->user, Ceremony::SESSION );
		$this->assertIsArray( $record, 'precondition: R-11 passed before the change' );

		$this->change_email();
		$stored = Verifier::store_registration( $record );
		if ( $stored instanceof WP_Error ) {
			$this->assertInstanceOf( WP_Error::class, $stored );
			return;
		}

		$result = self::sign_in( $auth );
		$this->assertInstanceOf( WP_Error::class, $result, 'a registration started before the email change must not yield a working passkey' );
	}

	/** Case (3): subdomain multisite, credential on site 3, email changed in site 1. */
	public function test_passkey_on_another_site_of_the_network_does_not_sign_in(): void {
		global $wpdb, $magicauth_test_state;
		$magicauth_test_state['multisite']         = true;
		$magicauth_test_state['subdomain_install'] = true;

		$wpdb->prefix = 'wp_3_';
		$wpdb->install_magicauth_passkeys_schema();
		$auth = self::device();
		$id   = Ceremony::enrol( $auth, $this->user );

		$wpdb->prefix = 'wp_'; // The email changes in the main site.
		$this->change_email();

		$wpdb->prefix = 'wp_3_';
		$this->assertNotNull( Ceremony::row( $id ), 'rule M ran against the main site table only' );
		$result = self::sign_in( $auth );
		$this->assertInstanceOf( WP_Error::class, $result, 'the network-wide email changed; site 3 passkey must not open the account' );
		$this->assertNull( Ceremony::row( $id ), 'purged from the site 3 table' );
	}

	/**
	 * Review r2-crypto-01: an erasure on the main site after the change kept
	 * deleting the network-wide change time, so site 3's pre-change passkey
	 * signed in again. The eraser now keeps it on multisite (retained).
	 */
	public function test_erasure_on_one_site_keeps_other_sites_pre_change_passkeys_revoked(): void {
		global $wpdb, $magicauth_test_state;
		$magicauth_test_state['multisite']         = true;
		$magicauth_test_state['subdomain_install'] = true;

		$wpdb->prefix = 'wp_3_';
		$wpdb->install_magicauth_passkeys_schema();
		$auth = self::device();
		$id   = Ceremony::enrol( $auth, $this->user );

		$wpdb->prefix = 'wp_';
		Ceremony::enrol( self::device(), $this->user );
		$this->change_email();
		$erased = Privacy::erase( 'successor@example.test' );
		$this->assertIsArray( $erased );
		$this->assertTrue( $erased['items_retained'] );
		$this->assertContains( 'The time of your last email address change is kept, so passkeys created before it stay blocked on the other sites of this network.', $erased['messages'] );
		$this->assertSame( Ceremony::NOW + 60, CredentialStore::email_changed_at( 7 ), 'the change time survives the erasure' );
		$this->assertSame( '', get_user_meta( 7, 'magicauth_passkey_prompt', true ) );

		$wpdb->prefix = 'wp_3_';
		$user = get_userdata( 7 );
		$this->assertInstanceOf( WP_User::class, $user );
		$this->assertSame( 0, CredentialStore::count_for_user( $user ), 'site 3 pre-change row stays hidden and uncounted' );
		$result = self::sign_in( $auth );
		$this->assertInstanceOf( WP_Error::class, $result, 'site 3 pre-change passkey must stay revoked after an erasure on the main site' );
		$this->assertNull( Ceremony::row( $id ) );
	}

	/** Single site: the erasure emptied the only table, so the change time goes too. */
	public function test_erasure_on_single_site_removes_the_change_time(): void {
		Ceremony::enrol( self::device(), $this->user );
		$this->change_email();
		$erased = Privacy::erase( 'successor@example.test' );
		$this->assertIsArray( $erased );
		$this->assertSame( 0, CredentialStore::email_changed_at( 7 ) );
		$this->assertSame( 0, Ceremony::count_rows() );
		$this->assertNotContains( 'The time of your last email address change is kept, so passkeys created before it stay blocked on the other sites of this network.', $erased['messages'] );
	}

	/** The race row is deleted, so nothing is left behind. */
	public function test_registration_racing_rule_m_leaves_no_row(): void {
		$auth   = self::device();
		$record = Verifier::verify_registration( Ceremony::registration( $auth, $this->user ), $this->user, Ceremony::SESSION );
		$this->assertIsArray( $record );
		$this->change_email();

		$stored = Verifier::store_registration( $record );
		$this->assertInstanceOf( WP_Error::class, $stored );
		$this->assertSame( 'registration_failed', $stored->get_error_code() );
		$this->assertSame( 0, Ceremony::count_rows() );
	}

	/**
	 * Review r2-crypto-02: the race DELETE fails. The row (created after the
	 * change, so not revoked()) must be blocked and the answer 503 retry,
	 * never a 400 over a live passkey.
	 */
	public function test_failed_race_delete_blocks_the_row_and_answers_retry(): void {
		global $wpdb;
		$auth   = self::device();
		$record = Verifier::verify_registration( Ceremony::registration( $auth, $this->user ), $this->user, Ceremony::SESSION );
		$this->assertIsArray( $record );
		$this->change_email();

		$wpdb->fail_next_query( 'DELETE FROM ' . CredentialStore::table() . ' WHERE id' );
		$stored = Verifier::store_registration( $record );
		$this->assertInstanceOf( WP_Error::class, $stored );
		$this->assertSame( 'retry', $stored->get_error_code() );
		$data = (array) $stored->get_error_data();
		$this->assertSame( 503, $data['status'] );
		$this->assertFalse( $data['unknown_credential'] );

		$this->assertSame( 1, Ceremony::count_rows(), 'precondition: the DELETE failed' );
		$rows = $wpdb->get_results( 'SELECT * FROM ' . CredentialStore::table(), ARRAY_A );
		$this->assertNotNull( $rows[0]['counter_anomaly_at'], 'the surviving row is durably blocked' );

		$result = self::sign_in( $auth );
		$this->assertInstanceOf( WP_Error::class, $result, 'the race row must never sign in' );
		$this->assertSame( 'passkey_failed', $result->get_error_code() );
		$this->assertSame( 'blocked', ( (array) $result->get_error_data() )['reason'] );
	}

	/** Review r2-crypto-02: DELETE and the block UPDATE both fail; still retry, not 400. */
	public function test_failed_race_delete_and_block_still_answers_retry(): void {
		global $wpdb;
		$record = Verifier::verify_registration( Ceremony::registration( self::device(), $this->user ), $this->user, Ceremony::SESSION );
		$this->assertIsArray( $record );
		$this->change_email();

		$wpdb->fail_next_query( 'DELETE FROM ' . CredentialStore::table() . ' WHERE id' );
		$wpdb->fail_next_query( 'UPDATE ' . CredentialStore::table() . ' SET counter_anomaly_at' );
		$stored = Verifier::store_registration( $record );
		$this->assertInstanceOf( WP_Error::class, $stored );
		$this->assertSame( 'retry', $stored->get_error_code() );
		$this->assertSame( 503, ( (array) $stored->get_error_data() )['status'] );
	}

	/** Review r2-crypto-02: a concurrent rule M already removed the row; 400 with the orphan flag. */
	public function test_race_row_already_gone_is_registration_failed_with_flag(): void {
		global $wpdb;
		$record = Verifier::verify_registration( Ceremony::registration( self::device(), $this->user ), $this->user, Ceremony::SESSION );
		$this->assertIsArray( $record );
		$this->change_email();

		$table = CredentialStore::table();
		$wpdb->before_next_query(
			'DELETE FROM ' . $table . ' WHERE id',
			static function () use ( $wpdb, $table ): void {
				$wpdb->query( 'DELETE FROM ' . $table );
			}
		);
		$stored = Verifier::store_registration( $record );
		$this->assertInstanceOf( WP_Error::class, $stored );
		$this->assertSame( 'registration_failed', $stored->get_error_code() );
		$data = (array) $stored->get_error_data();
		$this->assertSame( 400, $data['status'] );
		$this->assertTrue( $data['unknown_credential'] );
		$this->assertSame( 0, Ceremony::count_rows() );
	}

	/** A surviving row is hidden from lists, counts and rename, kept for the export, refused at step-up. */
	public function test_surviving_row_is_hidden_and_refused_at_step_up(): void {
		global $wpdb;
		$auth = self::device();
		$id   = Ceremony::enrol( $auth, $this->user );
		$wpdb->fail_next_query( 'DELETE FROM ' . CredentialStore::table() );
		$this->change_email();
		$user = get_userdata( 7 );
		$this->assertInstanceOf( WP_User::class, $user );

		$this->assertSame( [], CredentialStore::for_user( $user ) );
		$this->assertSame( 0, CredentialStore::count_for_user( $user ) );
		$this->assertCount( 1, (array) CredentialStore::for_user( $user, '', true ), 'the privacy exporter still sees stored data' );
		$renamed = CredentialStore::rename( 7, $id, 'Renamed' );
		$this->assertInstanceOf( WP_Error::class, $renamed );
		$this->assertSame( 'magicauth_not_found', $renamed->get_error_code() );

		$challenge = ChallengeStore::issue( 'reauth', 7, Ceremony::SESSION, '', '', ChallengeStore::TTL['reauth'] );
		$this->assertIsString( $challenge );
		$step = Verifier::verify_step_up( Ceremony::encode( $auth->assert( Options::request( $challenge ), Ceremony::ORIGIN ) ), $user, Ceremony::SESSION );
		$this->assertInstanceOf( WP_Error::class, $step );
		$this->assertSame( 'reauth_failed', $step->get_error_code() );
		$this->assertNull( Ceremony::row( $id ), 'purged when presented' );
	}

	/** No false positive: a passkey registered after the change works. */
	public function test_passkey_added_after_the_change_signs_in(): void {
		Ceremony::enrol( self::device(), $this->user );
		$this->change_email();
		$user = get_userdata( 7 );
		$this->assertInstanceOf( WP_User::class, $user );

		$auth = self::device();
		Ceremony::enrol( $auth, $user );
		$this->assertIsArray( self::sign_in( $auth ) );
		$this->assertCount( 1, (array) CredentialStore::for_user( $user ) );
		$this->assertSame( 1, CredentialStore::count_for_user( $user ) );
	}
}
