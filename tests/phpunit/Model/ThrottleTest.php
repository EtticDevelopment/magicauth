<?php
/**
 * Throttle behaviour: T13, T14, T14.5, T15, T16, T17 plus v1.3.6 changes
 * (R-1 in-memory verification, per-email cooldown, registry-based admin_flush_all,
 * emergency flush).
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Model;

use MagicAuth\Auth\Throttle;
use PHPUnit\Framework\TestCase;

final class ThrottleTest extends TestCase {

	protected function setUp(): void {
		magicauth_test_reset_state();
	}

	public function test_T13_per_ip_link_eleventh_request_throttled(): void {
		$ip_hmac = magicauth_hash_ip( '203.0.113.5' );

		for ( $i = 1; $i <= 10; $i++ ) {
			$this->assertTrue(
				Throttle::allow_link_request_ip( $ip_hmac ),
				sprintf( 'Request %d should be allowed', $i )
			);
		}
		$this->assertFalse(
			Throttle::allow_link_request_ip( $ip_hmac ),
			'11th per-IP request should be throttled'
		);
	}

	public function test_T14_per_email_cooldown_blocks_immediate_second_request(): void {
		// v1.3.6: replaced the old hard-cap-per-window with a 60s cooldown.
		// First request goes through, immediate second request denied.
		$email_hmac = magicauth_hash_email( 'alice@example.test' );

		$this->assertTrue( Throttle::allow_link_request_email( $email_hmac ) );
		$this->assertFalse(
			Throttle::allow_link_request_email( $email_hmac ),
			'Second request inside the cooldown window must be denied'
		);
	}

	public function test_T14_5_per_email_cooldown_increments_independent_of_outcome(): void {
		// Mailer-failure flow: cooldown is set on first call regardless of
		// downstream send outcome (no second budget if mail throws).
		$email_hmac = magicauth_hash_email( 'bob@example.test' );

		$pretend_mail_fails = static function () use ( $email_hmac ): bool {
			Throttle::allow_link_request_email( $email_hmac );
			return false;
		};

		$pretend_mail_fails();

		$this->assertFalse(
			Throttle::allow_link_request_email( $email_hmac ),
			'cooldown is set even when the prior send pretended to fail'
		);
	}

	public function test_per_email_cooldown_zero_disables(): void {
		update_option( 'magicauth_settings', [ 'throttle' => [ 'per_email_cooldown_sec' => 0 ] ] );
		$email_hmac = magicauth_hash_email( 'cooldown-zero@example.test' );

		// With cooldown disabled, any number of immediate requests are allowed.
		for ( $i = 0; $i < 5; $i++ ) {
			$this->assertTrue(
				Throttle::allow_link_request_email( $email_hmac ),
				sprintf( 'request %d allowed when cooldown=0', $i )
			);
		}
	}

	public function test_per_email_cooldown_respects_settings_override(): void {
		update_option( 'magicauth_settings', [ 'throttle' => [ 'per_email_cooldown_sec' => 5 ] ] );
		$email_hmac = magicauth_hash_email( 'short-cd@example.test' );

		$this->assertTrue( Throttle::allow_link_request_email( $email_hmac ) );

		$remaining = Throttle::email_cooldown_remaining( $email_hmac );
		$this->assertGreaterThan( 0, $remaining );
		$this->assertLessThanOrEqual( 5, $remaining, 'remaining must respect the configured cooldown ceiling' );
	}

	public function test_email_cooldown_remaining_returns_seconds_until_expiry(): void {
		update_option( 'magicauth_settings', [ 'throttle' => [ 'per_email_cooldown_sec' => 30 ] ] );
		$email_hmac = magicauth_hash_email( 'remaining@example.test' );

		Throttle::allow_link_request_email( $email_hmac );

		$remaining = Throttle::email_cooldown_remaining( $email_hmac );
		$this->assertGreaterThan( 28, $remaining, 'remaining should be near 30 immediately after issuance' );
		$this->assertLessThanOrEqual( 30, $remaining );

		$cleared = magicauth_hash_email( 'never-set@example.test' );
		$this->assertSame( 0, Throttle::email_cooldown_remaining( $cleared ), 'no transient → zero remaining' );
	}

	public function test_T15_per_ip_code_twenty_first_attempt_throttled(): void {
		$ip_hmac = magicauth_hash_ip( '203.0.113.5' );

		for ( $i = 1; $i <= 20; $i++ ) {
			$this->assertTrue( Throttle::allow_code_submit_ip( $ip_hmac ) );
		}
		$this->assertFalse( Throttle::allow_code_submit_ip( $ip_hmac ) );
	}

	public function test_T16_throttled_response_is_not_distinguishable_at_throttle_layer(): void {
		// Envelope identity at the response layer is a Controller test (S5).
		// At the Throttle layer the contract is: check returns bool, no leak.
		$ip_hmac    = magicauth_hash_ip( '203.0.113.6' );
		$email_hmac = magicauth_hash_email( 'carol@example.test' );

		// Throttled call still returns a boolean — never throws or echoes.
		for ( $i = 0; $i < 15; $i++ ) {
			$result = Throttle::allow_link_request_ip( $ip_hmac );
			$this->assertIsBool( $result );
		}
		for ( $i = 0; $i < 15; $i++ ) {
			$result = Throttle::allow_link_request_email( $email_hmac );
			$this->assertIsBool( $result );
		}
	}

	public function test_T17_eraser_resets_email_cooldown(): void {
		$email_hmac = magicauth_hash_email( 'dave@example.test' );

		Throttle::allow_link_request_email( $email_hmac );
		$this->assertFalse(
			Throttle::allow_link_request_email( $email_hmac ),
			'pre-erase: cooldown holds'
		);

		Throttle::reset_for_email( $email_hmac );

		$this->assertTrue(
			Throttle::allow_link_request_email( $email_hmac ),
			'post-erase: cooldown cleared'
		);
	}

	public function test_reset_for_ip_clears_both_link_and_code_counters(): void {
		$ip_hmac = magicauth_hash_ip( '203.0.113.7' );

		for ( $i = 1; $i <= 10; $i++ ) {
			Throttle::allow_link_request_ip( $ip_hmac );
		}
		for ( $i = 1; $i <= 20; $i++ ) {
			Throttle::allow_code_submit_ip( $ip_hmac );
		}
		$this->assertFalse( Throttle::allow_link_request_ip( $ip_hmac ) );
		$this->assertFalse( Throttle::allow_code_submit_ip( $ip_hmac ) );

		Throttle::reset_for_ip( $ip_hmac );

		$this->assertTrue( Throttle::allow_link_request_ip( $ip_hmac ) );
		$this->assertTrue( Throttle::allow_code_submit_ip( $ip_hmac ) );
	}

	public function test_R1_increment_stops_refreshing_ttl_when_far_over_cap(): void {
		// R-1 fix: once the counter is past max+1 we stop touching set_transient
		// so the original TTL drains. Reads expiry from the in-memory transient
		// store directly — the prior wp_options-based assertion silently skipped
		// because the timeout row wasn't always written.
		global $magicauth_test_state;

		$ip_hmac = magicauth_hash_ip( '203.0.113.99' );
		$key     = 'magicauth_throttle_link_ip_' . $ip_hmac;

		// Pin the counter all the way to the cap; cap-crossing call (count == max + 1)
		// still re-stamps the transient. After this, count == 11 (= max + 1).
		for ( $i = 1; $i <= 11; $i++ ) {
			Throttle::allow_link_request_ip( $ip_hmac );
		}

		$first_expires = (int) ( $magicauth_test_state['transients'][ $key ]['expires'] ?? 0 );
		$this->assertGreaterThan( 0, $first_expires, 'pre-condition: a transient with an expiry must exist' );

		// Sleep so any "fresh" set_transient TTL would visibly bump the expiry.
		sleep( 1 );

		// Fire 5 deeply-over-cap requests (count goes 12, 13, 14, 15, 16).
		for ( $i = 1; $i <= 5; $i++ ) {
			$this->assertFalse(
				Throttle::allow_link_request_ip( $ip_hmac ),
				'over-cap call should remain denied'
			);
		}

		$later_expires = (int) ( $magicauth_test_state['transients'][ $key ]['expires'] ?? 0 );
		$this->assertSame(
			$first_expires,
			$later_expires,
			'TTL must not be refreshed by over-cap requests (R-1 regression)'
		);
	}

	public function test_admin_flush_all_uses_registry(): void {
		Throttle::allow_link_request_ip( magicauth_hash_ip( '203.0.113.5' ) );
		Throttle::allow_code_submit_ip( magicauth_hash_ip( '203.0.113.5' ) );
		Throttle::allow_link_request_email( magicauth_hash_email( 'a@b.test' ) );

		$cleared = Throttle::admin_flush_all();
		$this->assertGreaterThanOrEqual( 3, $cleared, 'flushed at least the three registered keys' );

		// Counters re-allowed post-flush.
		$this->assertTrue( Throttle::allow_link_request_ip( magicauth_hash_ip( '203.0.113.5' ) ) );
		$this->assertTrue( Throttle::allow_link_request_email( magicauth_hash_email( 'a@b.test' ) ) );
	}

	public function test_admin_flush_all_clears_magicauth_transients(): void {
		// Pre-pin three distinct counters so there's something to clear.
		Throttle::allow_link_request_ip( magicauth_hash_ip( '203.0.113.5' ) );
		Throttle::allow_code_submit_ip( magicauth_hash_ip( '203.0.113.5' ) );
		Throttle::allow_link_request_email( magicauth_hash_email( 'a@b.test' ) );

		global $wpdb;
		$pre_count = (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE '_transient_magicauth_throttle_%'"
		);
		$this->assertGreaterThanOrEqual( 3, $pre_count, 'fixture: expected throttle transients in options' );

		$cleared = Throttle::admin_flush_all();
		$this->assertGreaterThanOrEqual( 3, $cleared, 'admin_flush_all returned the count of cleared keys' );

		$post_count = (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE '_transient_magicauth_throttle_%'"
		);
		$this->assertSame( 0, $post_count, 'all magicauth throttle transients cleared from options table' );
	}

	public function test_admin_flush_all_falls_back_to_options_scan_when_registry_empty(): void {
		// Simulate a pre-1.3.6 transient that exists in wp_options but was
		// written before the registry pattern existed. The defense-in-depth
		// LIKE scan must still pick it up so admins can recover.
		global $wpdb;
		$key = 'magicauth_throttle_link_ip_legacy_hmac';
		$wpdb->query(
			$wpdb->prepare(
				"INSERT OR REPLACE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')",
				'_transient_' . $key,
				'1'
			)
		);

		// Confirm the registry is empty.
		$this->assertSame( [], (array) get_option( Throttle::REGISTRY_OPTION, [] ) );

		$cleared = Throttle::admin_flush_all();

		$this->assertGreaterThanOrEqual( 1, $cleared, 'legacy key picked up via wp_options scan' );

		$still_there = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name = %s",
				'_transient_' . $key
			)
		);
		$this->assertSame( 0, $still_there, 'legacy transient row removed' );
	}

	public function test_admin_flush_all_fires_action_with_count_and_keys(): void {
		Throttle::allow_link_request_ip( magicauth_hash_ip( '203.0.113.5' ) );

		$captured = [ 'count' => null, 'keys' => null ];
		add_action(
			'magicauth_throttle_keys_flushed',
			static function ( $count, $keys ) use ( &$captured ): void {
				$captured['count'] = $count;
				$captured['keys']  = $keys;
			},
			10,
			2
		);

		Throttle::admin_flush_all();

		$this->assertNotNull( $captured['count'], 'magicauth_throttle_keys_flushed must fire' );
		$this->assertGreaterThanOrEqual( 1, $captured['count'] );
		$this->assertIsArray( $captured['keys'] );
		$this->assertContains(
			'magicauth_throttle_link_ip_' . magicauth_hash_ip( '203.0.113.5' ),
			$captured['keys'],
			'flushed key list includes the registered key'
		);
	}

	public function test_increment_registers_key_only_on_first_creation(): void {
		// Repeated increments of the same counter must not bloat the registry.
		$ip_hmac = magicauth_hash_ip( '203.0.113.42' );

		for ( $i = 0; $i < 5; $i++ ) {
			Throttle::allow_link_request_ip( $ip_hmac );
		}

		Throttle::flush_registry_writes();
		$registry = (array) get_option( Throttle::REGISTRY_OPTION, [] );
		$this->assertCount( 1, $registry, 'a single counter registers exactly one key' );
		$this->assertArrayHasKey( 'magicauth_throttle_link_ip_' . $ip_hmac, $registry );
	}

	public function test_registry_caps_at_max_and_evicts_oldest(): void {
		// Use the magicauth_throttle_registry_max filter to shrink the cap to
		// 10 so the test runs in milliseconds. With cap=10 we register 15
		// distinct keys; the registry must hold the latest 10 and drop the
		// oldest 5 (FIFO).
		add_filter(
			'magicauth_throttle_registry_max',
			static function (): int {
				return 10;
			}
		);

		$first_hmac = str_pad( '0', 16, '0', STR_PAD_LEFT );
		for ( $i = 0; $i < 15; $i++ ) {
			$hmac = str_pad( (string) $i, 16, '0', STR_PAD_LEFT );
			Throttle::allow_link_request_email_cooldown( $hmac );
		}

		Throttle::flush_registry_writes();
		$registry = (array) get_option( Throttle::REGISTRY_OPTION, [] );
		$this->assertSame( 10, count( $registry ), 'registry trims to the configured cap' );
		$this->assertArrayNotHasKey(
			'magicauth_throttle_link_email_cd_' . $first_hmac,
			$registry,
			'oldest entries are evicted first (FIFO)'
		);
	}

	public function test_admin_flush_all_does_not_touch_unrelated_transients(): void {
		// Decoy: a non-magicauth transient must survive an admin flush.
		set_transient( 'unrelated_decoy_key', 'preserved', 3600 );
		Throttle::allow_link_request_ip( magicauth_hash_ip( '203.0.113.5' ) );

		Throttle::admin_flush_all();

		$this->assertSame(
			'preserved',
			get_transient( 'unrelated_decoy_key' ),
			'admin_flush_all must not delete transients outside the magicauth_throttle_ namespace'
		);
	}

	public function test_admin_flush_all_returns_zero_when_nothing_to_clear(): void {
		$this->assertSame( 0, Throttle::admin_flush_all() );
	}
}
