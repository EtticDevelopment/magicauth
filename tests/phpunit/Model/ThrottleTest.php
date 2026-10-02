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

	/* ------------------------------------------- T-THR: passkey buckets (step 10) */

	/** @return array<string,mixed> */
	private static function registry_after_flush(): array {
		Throttle::flush_registry_writes();
		return (array) get_option( Throttle::REGISTRY_OPTION, [] );
	}

	/** Passkey buckets open a fixed window on their first call (r1-endpoints-02): allow 1 s of test run time. */
	private function assert_window_ttl( int $window, string $key, string $message = '' ): void {
		$ttl = self::transient_ttl( $key );
		$this->assertGreaterThanOrEqual( $window - 1, $ttl, $message );
		$this->assertLessThanOrEqual( $window, $ttl, $message );
	}

	private static function transient_ttl( string $key ): int {
		global $magicauth_test_state;
		return (int) $magicauth_test_state['transients'][ $key ]['expires'] - time();
	}

	public function test_ip_bucket_shares_one_ipv6_64(): void {
		$a = magicauth_ip_bucket( '2001:db8:1:2:3:4:5:6' );
		$b = magicauth_ip_bucket( '2001:db8:1:2:ffff:ffff:ffff:ffff' );
		$c = magicauth_ip_bucket( '2001:DB8:1:2::9' );

		$this->assertSame( '2001:db8:1:2::', $a );
		$this->assertSame( $a, $b );
		$this->assertSame( $a, $c, 'notation does not matter' );
		$this->assertSame( magicauth_hash_ip( $a ), magicauth_hash_ip( $b ) );
	}

	public function test_ip_bucket_separates_different_64s(): void {
		$this->assertNotSame( magicauth_ip_bucket( '2001:db8:1:2::1' ), magicauth_ip_bucket( '2001:db8:1:3::1' ) );
		$this->assertNotSame( magicauth_ip_bucket( '2001:db8:1:2::1' ), magicauth_ip_bucket( '2001:db9:1:2::1' ) );
	}

	public function test_ip_bucket_ipv4_is_the_address(): void {
		$this->assertSame( '203.0.113.5', magicauth_ip_bucket( '203.0.113.5' ) );
		$this->assertNotSame( magicauth_ip_bucket( '203.0.113.5' ), magicauth_ip_bucket( '203.0.113.6' ) );
	}

	/** A /64 cut of ::ffff:a.b.c.d would put every IPv4-mapped client in one bucket. */
	public function test_ip_bucket_ipv4_mapped_counts_as_ipv4(): void {
		$this->assertSame( '203.0.113.5', magicauth_ip_bucket( '::ffff:203.0.113.5' ) );
		$this->assertNotSame( magicauth_ip_bucket( '::ffff:203.0.113.5' ), magicauth_ip_bucket( '::ffff:203.0.113.6' ) );
	}

	public function test_ip_bucket_leaves_non_addresses_unchanged(): void {
		foreach ( [ '', '0.0.0.0', 'unix:', 'fe80::1%eth0', '999.1.1.1' ] as $value ) {
			$this->assertSame( $value, magicauth_ip_bucket( $value ) );
		}
	}

	public function test_options_buckets_never_grow_the_registry(): void {
		Throttle::allow_link_request_ip( magicauth_hash_ip( '203.0.113.5' ) );
		$before = self::registry_after_flush();

		for ( $i = 0; $i < 20; $i++ ) {
			$bucket = magicauth_hash_ip( magicauth_ip_bucket( "2001:db8:{$i}::1" ) );
			$this->assertTrue( Throttle::allow_passkey_options_ip( $bucket ) );
			$this->assertTrue( Throttle::allow_passkey_options_global() );
		}

		$this->assertSame( $before, self::registry_after_flush(), 'one key from the link bucket, none from the passkey options buckets' );
		$this->assertSame( 20, (int) get_transient( 'magicauth_throttle_passkey_opts_global_all' ) );
	}

	public function test_global_ceiling_default_5000_per_10_minutes(): void {
		global $magicauth_test_state;
		$start = time();
		for ( $i = 1; $i <= 5000; $i++ ) {
			if ( ! Throttle::allow_passkey_options_global() ) {
				$this->fail( "call {$i} refused below the ceiling" );
			}
		}
		$this->assertFalse( Throttle::allow_passkey_options_global(), '5001st refused' );
		// Fixed window (r1-endpoints-02): it ends 600 s after the first call.
		$expires = (int) $magicauth_test_state['transients']['magicauth_throttle_passkey_opts_global_all']['expires'];
		$this->assertGreaterThanOrEqual( $start + 600, $expires );
		$this->assertLessThanOrEqual( $start + 601, $expires );
	}

	/** Past the ceiling the counter stops at max + 1, so a flood never re-stamps the window. */
	public function test_global_ceiling_refusals_write_nothing_further(): void {
		global $wpdb;
		add_filter( 'magicauth_passkey_options_global_max', static fn() => 500 );
		for ( $i = 0; $i < 501; $i++ ) {
			Throttle::allow_passkey_options_global();
		}
		$wpdb->query_log = [];

		$this->assertFalse( Throttle::allow_passkey_options_global() );
		$this->assertFalse( Throttle::allow_passkey_options_global() );

		$this->assertSame( 501, (int) get_transient( 'magicauth_throttle_passkey_opts_global_all' ) );
		$this->assertSame( [], $wpdb->query_log, 'no write, no INSERT of any kind' );
	}

	/** @return array<string,array{0:mixed,1:int}> */
	public static function global_filter_values(): array {
		return [
			'below the floor' => [ 100, 500 ],
			'inside'          => [ 800, 800 ],
			'above the cap'   => [ 200000, 100000 ],
			'not numeric'     => [ 'lots', 5000 ],
			'numeric string'  => [ '700', 700 ],
		];
	}

	/**
	 * @dataProvider global_filter_values
	 * @param mixed $filtered
	 */
	public function test_global_ceiling_filter_is_clamped( $filtered, int $expected ): void {
		add_filter( 'magicauth_passkey_options_global_max', static fn() => $filtered );
		set_transient( 'magicauth_throttle_passkey_opts_global_all', $expected - 1, 600 );

		$this->assertTrue( Throttle::allow_passkey_options_global(), 'the limit itself is allowed' );
		$this->assertFalse( Throttle::allow_passkey_options_global(), 'one more is refused' );
	}

	public function test_options_per_network_300_then_refused_other_networks_unaffected(): void {
		$bucket = magicauth_hash_ip( magicauth_ip_bucket( '2001:db8:1:2::1' ) );
		for ( $i = 0; $i < 300; $i++ ) {
			$this->assertTrue( Throttle::allow_passkey_options_ip( $bucket ) );
		}
		$this->assertFalse( Throttle::allow_passkey_options_ip( magicauth_hash_ip( magicauth_ip_bucket( '2001:db8:1:2::ffff' ) ) ), 'same /64' );
		$this->assertTrue( Throttle::allow_passkey_options_ip( magicauth_hash_ip( magicauth_ip_bucket( '2001:db8:1:3::1' ) ) ), 'next /64' );
		$this->assert_window_ttl( 600, 'magicauth_throttle_passkey_opts_ip_' . $bucket );
	}

	/** @return array<string,array{0:mixed,1:int}> */
	public static function ip_filter_values(): array {
		return [
			'below the floor' => [ 5, 30 ],
			'above the cap'   => [ 9000, 5000 ],
			'not numeric'     => [ null, 300 ],
		];
	}

	/**
	 * @dataProvider ip_filter_values
	 * @param mixed $filtered
	 */
	public function test_options_per_network_filter_is_clamped( $filtered, int $expected ): void {
		$bucket = magicauth_hash_ip( '203.0.113.5' );
		add_filter( 'magicauth_passkey_options_ip_max', static fn() => $filtered );
		set_transient( 'magicauth_throttle_passkey_opts_ip_' . $bucket, $expected - 1, 600 );

		$this->assertTrue( Throttle::allow_passkey_options_ip( $bucket ) );
		$this->assertFalse( Throttle::allow_passkey_options_ip( $bucket ) );
	}

	public function test_failed_signins_block_after_the_setting_max_and_peek_never_counts(): void {
		$bucket = magicauth_hash_ip( magicauth_ip_bucket( '203.0.113.5' ) );
		for ( $i = 0; $i < 100; $i++ ) {
			$this->assertFalse( Throttle::passkey_signin_blocked( $bucket ), 'peeking alone never blocks' );
		}
		for ( $i = 1; $i <= 30; $i++ ) {
			$this->assertFalse( Throttle::passkey_signin_blocked( $bucket ), "attempt {$i} allowed" );
			Throttle::record_passkey_signin_failure( $bucket );
		}
		$this->assertTrue( Throttle::passkey_signin_blocked( $bucket ), 'the 31st attempt is refused' );
		$this->assert_window_ttl( 15 * 60, 'magicauth_throttle_passkey_fail_ip_' . $bucket );
		$this->assertArrayHasKey( 'magicauth_throttle_passkey_fail_ip_' . $bucket, self::registry_after_flush(), 'registered: the admin flush clears it' );
	}

	public function test_failed_signin_limits_follow_the_settings_with_clamps(): void {
		$bucket = magicauth_hash_ip( '203.0.113.7' );
		update_option(
			'magicauth_settings',
			[
				'throttle' => [
					'per_ip_passkey_max'        => 3,
					'per_ip_passkey_window_min' => 5000,
				],
			]
		);
		for ( $i = 0; $i < 3; $i++ ) {
			Throttle::record_passkey_signin_failure( $bucket );
		}
		$this->assertTrue( Throttle::passkey_signin_blocked( $bucket ) );
		$this->assert_window_ttl( 1440 * 60, 'magicauth_throttle_passkey_fail_ip_' . $bucket, 'window clamped to 1440 min' );

		update_option( 'magicauth_settings', [ 'throttle' => [ 'per_ip_passkey_max' => 0 ] ] );
		$this->assertFalse( Throttle::passkey_signin_blocked( magicauth_hash_ip( '203.0.113.8' ) ) );
		Throttle::record_passkey_signin_failure( magicauth_hash_ip( '203.0.113.8' ) );
		$this->assertTrue( Throttle::passkey_signin_blocked( magicauth_hash_ip( '203.0.113.8' ) ), 'max clamped to 1' );
	}

	/** @return array<string,array{0:string,1:int}> */
	public static function user_buckets(): array {
		return [
			'reg'         => [ Throttle::ACTION_PASSKEY_REG_USER, 20 ],
			'stale'       => [ Throttle::ACTION_PASSKEY_STALE_USER, 60 ],
			'regfail'     => [ Throttle::ACTION_PASSKEY_REGFAIL_USER, 10 ],
			'manage'      => [ Throttle::ACTION_PASSKEY_MANAGE_USER, 60 ],
			'reauth mail' => [ Throttle::ACTION_PASSKEY_REAUTH_MAIL_USER, 5 ],
			'reauth try'  => [ Throttle::ACTION_PASSKEY_REAUTH_TRY_USER, 20 ],
			'reauth opts' => [ Throttle::ACTION_PASSKEY_REAUTH_OPTS_USER, 30 ],
		];
	}

	/** @dataProvider user_buckets */
	public function test_user_bucket_limits_per_hour( string $bucket, int $max ): void {
		[ $limit, $window ] = Throttle::PASSKEY_USER_LIMITS[ $bucket ];
		$this->assertSame( $max, $limit );
		$this->assertSame( 3600, $window );

		for ( $i = 0; $i < $max; $i++ ) {
			$this->assertTrue( Throttle::allow_passkey_user( $bucket, 7, $limit, $window ) );
		}
		$this->assertFalse( Throttle::allow_passkey_user( $bucket, 7, $limit, $window ) );
		$this->assertTrue( Throttle::allow_passkey_user( $bucket, 8, $limit, $window ), 'per user' );
		$key = 'magicauth_throttle_' . $bucket . '_u7';
		$this->assert_window_ttl( 3600, $key );
		$this->assertArrayHasKey( $key, self::registry_after_flush() );
	}

	public function test_user_bucket_names_match_the_spec(): void {
		$this->assertSame(
			[
				'passkey_reg_user',
				'passkey_stale_user',
				'passkey_regfail_user',
				'passkey_manage_user',
				'passkey_reauth_mail_user',
				'passkey_reauth_try_user',
				'passkey_reauth_opts_user',
			],
			array_keys( Throttle::PASSKEY_USER_LIMITS )
		);
		$this->assertSame( 'passkey_opts_global', Throttle::ACTION_PASSKEY_OPTS_GLOBAL );
		$this->assertSame( 'passkey_opts_ip', Throttle::ACTION_PASSKEY_OPTS_IP );
		$this->assertSame( 'passkey_fail_ip', Throttle::ACTION_PASSKEY_FAIL_IP );
		$this->assertSame( 'passkey_reauth_cd', Throttle::ACTION_PASSKEY_REAUTH_CD );
	}

	/** Fetching step-up options never eats into the step-up attempts. */
	public function test_reauth_options_and_attempts_are_separate_buckets(): void {
		[ $max, $window ] = Throttle::PASSKEY_USER_LIMITS[ Throttle::ACTION_PASSKEY_REAUTH_OPTS_USER ];
		for ( $i = 0; $i < 31; $i++ ) {
			Throttle::allow_passkey_user( Throttle::ACTION_PASSKEY_REAUTH_OPTS_USER, 7, $max, $window );
		}
		$this->assertFalse( Throttle::allow_passkey_user( Throttle::ACTION_PASSKEY_REAUTH_OPTS_USER, 7, $max, $window ) );
		[ $try_max, $try_window ] = Throttle::PASSKEY_USER_LIMITS[ Throttle::ACTION_PASSKEY_REAUTH_TRY_USER ];
		$this->assertFalse( get_transient( 'magicauth_throttle_passkey_reauth_try_user_u7' ) );
		$this->assertTrue( Throttle::allow_passkey_user( Throttle::ACTION_PASSKEY_REAUTH_TRY_USER, 7, $try_max, $try_window ) );
	}

	public function test_user_bucket_refuses_unknown_buckets_and_users(): void {
		$this->assertFalse( Throttle::allow_passkey_user( 'link_ip', 7, 10, 3600 ), 'not a passkey user bucket' );
		$this->assertFalse( Throttle::allow_passkey_user( Throttle::ACTION_PASSKEY_OPTS_IP, 7, 10, 3600 ) );
		$this->assertFalse( Throttle::allow_passkey_user( Throttle::ACTION_PASSKEY_REG_USER, 0, 10, 3600 ) );
		$this->assertFalse( Throttle::allow_passkey_user( Throttle::ACTION_PASSKEY_REG_USER, -1, 10, 3600 ) );
		$this->assertSame( [], self::registry_after_flush() );
	}

	public function test_reauth_email_cooldown_60_seconds_with_remaining(): void {
		\MagicAuth\Passkeys\Clock::set_for_tests( 1790000000 );
		$this->assertSame( 0, Throttle::passkey_reauth_cooldown_remaining( 7 ) );
		$this->assertTrue( Throttle::allow_passkey_reauth_cooldown( 7 ) );
		$this->assertFalse( Throttle::allow_passkey_reauth_cooldown( 7 ) );
		$this->assertSame( 60, Throttle::passkey_reauth_cooldown_remaining( 7 ) );

		\MagicAuth\Passkeys\Clock::set_for_tests( 1790000000 + 45 );
		$this->assertSame( 15, Throttle::passkey_reauth_cooldown_remaining( 7 ) );
		$this->assertTrue( Throttle::allow_passkey_reauth_cooldown( 8 ), 'per user' );
		$this->assertFalse( Throttle::allow_passkey_reauth_cooldown( 0 ) );
		$this->assertSame( 60, self::transient_ttl( 'magicauth_throttle_passkey_reauth_cd_u7' ) );
		$this->assertArrayHasKey( 'magicauth_throttle_passkey_reauth_cd_u7', self::registry_after_flush() );
	}

	public function test_reset_for_ip_clears_the_passkey_network_buckets(): void {
		$v6     = '2001:db8:1:2::1';
		$bucket = magicauth_hash_ip( magicauth_ip_bucket( $v6 ) );
		Throttle::allow_passkey_options_ip( $bucket );
		Throttle::record_passkey_signin_failure( $bucket );

		Throttle::reset_for_ip( magicauth_hash_ip( $v6 ), $v6 );

		$this->assertFalse( get_transient( 'magicauth_throttle_passkey_opts_ip_' . $bucket ) );
		$this->assertFalse( get_transient( 'magicauth_throttle_passkey_fail_ip_' . $bucket ) );

		$v4 = magicauth_hash_ip( '203.0.113.5' );
		Throttle::record_passkey_signin_failure( $v4 );
		Throttle::reset_for_ip( $v4 );
		$this->assertFalse( get_transient( 'magicauth_throttle_passkey_fail_ip_' . $v4 ), 'IPv4: the bucket is the address' );
	}

	public function test_admin_flush_all_clears_registered_passkey_buckets(): void {
		$bucket = magicauth_hash_ip( '203.0.113.5' );
		Throttle::record_passkey_signin_failure( $bucket );
		Throttle::allow_passkey_user( Throttle::ACTION_PASSKEY_MANAGE_USER, 7, 60, 3600 );
		Throttle::allow_passkey_reauth_cooldown( 7 );
		Throttle::flush_registry_writes();

		Throttle::admin_flush_all();

		$this->assertFalse( Throttle::passkey_signin_blocked( $bucket ) );
		$this->assertFalse( get_transient( 'magicauth_throttle_passkey_fail_ip_' . $bucket ) );
		$this->assertFalse( get_transient( 'magicauth_throttle_passkey_manage_user_u7' ) );
		$this->assertTrue( Throttle::allow_passkey_reauth_cooldown( 7 ) );
	}
}
