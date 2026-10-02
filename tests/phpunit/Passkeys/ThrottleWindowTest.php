<?php
/**
 * Review r1-endpoints-02: passkey throttle buckets must count "N per window"
 * (SPEC 6.9, T14: 300 per 10 min per network), not "N per gap-free burst".
 * Every hit up to max+1 re-stamped the transient with the full TTL, so a
 * network with steady, slow traffic accumulated calls forever and was refused
 * although only a couple of calls fell inside the last window.
 *
 * Review r1-endpoints-03: the counters were a get_transient() followed by a
 * set_transient(), so parallel requests lost counts and got past the limits.
 *
 * Fixed: Throttle::bump() opens a fixed window on a bucket's first call and
 * never moves its expiry; increments are atomic (UPDATE option_value + 1 on
 * the transient row, or wp_cache_incr() on a persistent object cache).
 *
 * Time is advanced by moving every stored transient expiry back (the test
 * transient store reads time()) and by moving the Clock seam forward by the
 * same amount, so a fix keyed on either clock sees a consistent timeline.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Auth\Throttle;
use MagicAuth\Passkeys\Clock;
use MagicAuth\Passkeys\SignInEndpoints;
use MagicAuth\Tests\Stubs\JsonResponseSent;
use MagicAuth\Tests\Support\Ceremony;
use PHPUnit\Framework\TestCase;

final class ThrottleWindowTest extends TestCase {

	/** @var array<string,mixed> */
	private array $server = [];

	private int $now = 0;

	protected function setUp(): void {
		$this->server = $_SERVER;
		Ceremony::site();
		Ceremony::enable_module();
		$_COOKIE   = [];
		$this->now = time();
		Clock::set_for_tests( $this->now );
	}

	protected function tearDown(): void {
		global $magicauth_test_state;
		$magicauth_test_state['ext_object_cache'] = false;
		$_SERVER  = $this->server;
		$_POST    = [];
		$_REQUEST = [];
		$_COOKIE  = [];
		magicauth_test_reset_state();
	}

	/** Advance the timeline by $seconds for transients and the Clock seam. */
	private function advance( int $seconds ): void {
		global $magicauth_test_state;
		foreach ( $magicauth_test_state['transients'] as $key => $entry ) {
			if ( $entry['expires'] > 0 ) {
				$magicauth_test_state['transients'][ $key ]['expires'] = $entry['expires'] - $seconds;
			}
		}
		$this->now += $seconds;
		Clock::set_for_tests( $this->now );
	}

	private static function options( string $ip ): int {
		global $magicauth_test_state;
		$_SERVER['REMOTE_ADDR']    = $ip;
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$_SERVER['HTTP_ORIGIN']    = Ceremony::ORIGIN;
		$_POST                     = [];
		$_REQUEST                  = [];
		$_COOKIE[ SignInEndpoints::BIND_COOKIE ] = Ceremony::COOKIE;
		$magicauth_test_state['cookies']         = [];
		$magicauth_test_state['headers']         = [];
		ob_start();
		try {
			SignInEndpoints::options();
		} catch ( JsonResponseSent $sent ) {
			ob_end_clean();
			return $sent->status;
		}
		ob_end_clean();
		throw new \RuntimeException( 'options sent no response' );
	}

	public function test_slow_steady_traffic_never_exceeds_the_per_window_cap(): void {
		add_filter( 'magicauth_passkey_options_ip_max', static fn() => 30 );
		$bucket = 'r1-endpoints-02-net';

		// 30 calls, 590 s apart: never more than 2 inside any 600 s window.
		for ( $i = 1; $i <= 30; $i++ ) {
			$this->assertTrue( Throttle::allow_passkey_options_ip( $bucket ), "slow call $i allowed" );
			$this->advance( 590 );
		}
		$this->assertTrue(
			Throttle::allow_passkey_options_ip( $bucket ),
			'call 31 refused although only 2 calls fell inside the last 600 s (window slides on every hit)'
		);
	}

	public function test_slow_network_gets_options_after_hours_of_light_use(): void {
		add_filter( 'magicauth_passkey_options_ip_max', static fn() => 30 );
		add_filter( 'magicauth_passkey_options_global_max', static fn() => 500 );

		for ( $i = 1; $i <= 30; $i++ ) {
			$this->assertSame( 200, self::options( '203.0.113.20' ), "options call $i allowed" );
			$this->advance( 590 );
		}
		$this->assertSame(
			200,
			self::options( '203.0.113.20' ),
			'options call 31 got 429 after ~5 hours of one call per 590 s'
		);
	}

	/** A bucket's window ends where it began, whatever the refused calls in it. */
	public function test_refusals_never_extend_the_window(): void {
		global $magicauth_test_state;
		add_filter( 'magicauth_passkey_options_ip_max', static fn() => 30 );
		$bucket = 'fixed-window-net';
		$key    = 'magicauth_throttle_passkey_opts_ip_' . $bucket;
		for ( $i = 1; $i <= 30; $i++ ) {
			$this->assertTrue( Throttle::allow_passkey_options_ip( $bucket ) );
		}
		$opened = $magicauth_test_state['transients'][ $key ]['expires'];
		$this->advance( 300 );
		for ( $i = 0; $i < 5; $i++ ) {
			$this->assertFalse( Throttle::allow_passkey_options_ip( $bucket ) );
		}
		$this->assertSame( $opened - 300, $magicauth_test_state['transients'][ $key ]['expires'], 'expiry not moved' );
		$this->assertSame( 31, (int) get_transient( $key ), 'stops at max + 1' );
		$this->advance( 301 );
		$this->assertTrue( Throttle::allow_passkey_options_ip( $bucket ), 'a new window 600 s after the first call' );
	}

	public function test_failure_and_user_buckets_use_fixed_windows_too(): void {
		$bucket = magicauth_hash_ip( '203.0.113.30' );
		for ( $i = 1; $i <= 30; $i++ ) {
			Throttle::record_passkey_signin_failure( $bucket );
			$this->advance( 60 ); // 30 failures in 30 minutes: at most 16 in any one window.
		}
		$this->assertFalse( Throttle::passkey_signin_blocked( $bucket ), 'never 30 inside one 15-minute window' );

		[ $max, $window ] = Throttle::PASSKEY_USER_LIMITS[ Throttle::ACTION_PASSKEY_REGFAIL_USER ];
		for ( $i = 1; $i <= $max; $i++ ) {
			$this->assertTrue( Throttle::allow_passkey_user( Throttle::ACTION_PASSKEY_REGFAIL_USER, 7, $max, $window ) );
			$this->advance( 500 ); // 10 calls in 5000 s: at most 8 in any one window.
		}
		$this->assertFalse( Throttle::passkey_user_exhausted( Throttle::ACTION_PASSKEY_REGFAIL_USER, 7, $max ) );
	}

	/** Two requests that read the same count both land: exactly one gets the last slot. */
	public function test_parallel_increments_are_not_lost_on_the_database_path(): void {
		global $wpdb;
		add_filter( 'magicauth_passkey_options_ip_max', static fn() => 30 );
		$bucket = 'parallel-net';
		$key    = 'magicauth_throttle_passkey_opts_ip_' . $bucket;
		set_transient( $key, 29, 600 );

		$inner = null;
		$wpdb->before_next_query(
			'option_value = option_value + 1',
			static function () use ( $bucket, &$inner ): void {
				$inner = Throttle::allow_passkey_options_ip( $bucket );
			}
		);
		$outer = Throttle::allow_passkey_options_ip( $bucket );

		$this->assertTrue( $inner, 'the request that incremented first gets slot 30' );
		$this->assertFalse( $outer, 'the other one sees 31 although it read 29' );
		$this->assertSame( 31, (int) get_transient( $key ) );
	}

	public function test_a_failed_increment_query_counts_like_a_read_then_write(): void {
		global $wpdb;
		$key = 'magicauth_throttle_passkey_opts_global_all';
		set_transient( $key, 7, 600 );
		$wpdb->fail_next_query( 'option_value = option_value + 1' );
		$this->assertTrue( Throttle::allow_passkey_options_global() );
		$this->assertTrue( Throttle::allow_passkey_options_global() );
		$this->assertSame( 8, (int) get_transient( $key ), 'the next call counts again' );
	}

	public function test_object_cache_path_is_atomic_and_keeps_the_expiry(): void {
		global $magicauth_test_state;
		$magicauth_test_state['ext_object_cache'] = true;
		add_filter( 'magicauth_passkey_options_ip_max', static fn() => 30 );
		$bucket = 'cache-net';
		$key    = 'magicauth_throttle_passkey_opts_ip_' . $bucket;

		for ( $i = 1; $i <= 30; $i++ ) {
			$this->assertTrue( Throttle::allow_passkey_options_ip( $bucket ) );
		}
		$entry = $magicauth_test_state['object_cache']['transient'][ $key ];
		$this->assertSame( 30, $entry[0] );
		$this->assertSame( time() + 600, $entry[1], 'expiry set once, by wp_cache_add' );
		$this->assertArrayNotHasKey( $key, $magicauth_test_state['transients'], 'nothing in the options table' );

		$magicauth_test_state['object_cache']['transient'][ $key ][1] = time() + 5;
		$this->assertFalse( Throttle::allow_passkey_options_ip( $bucket ) );
		$this->assertFalse( Throttle::allow_passkey_options_ip( $bucket ) );
		$this->assertSame( [ 31, time() + 5 ], $magicauth_test_state['object_cache']['transient'][ $key ], 'stops at max + 1, expiry kept' );

		// Evicted between the peek and the incr: a new window.
		$fail = 'cache-fail';
		Throttle::record_passkey_signin_failure( $fail );
		$magicauth_test_state['fail_cache_incr'] = true;
		Throttle::record_passkey_signin_failure( $fail );
		$this->assertSame( 1, $magicauth_test_state['object_cache']['transient'][ 'magicauth_throttle_passkey_fail_ip_' . $fail ][0] );
		$this->assertFalse( Throttle::passkey_signin_blocked( $fail ) );

		// A drop-in that cannot increment still counts and still refuses.
		$magicauth_test_state['cache_incr_broken'] = true;
		update_option( 'magicauth_settings', [ 'throttle' => [ 'per_ip_passkey_max' => 3 ] ] );
		$broken = 'cache-broken';
		for ( $i = 0; $i < 3; $i++ ) {
			$this->assertFalse( Throttle::passkey_signin_blocked( $broken ) );
			Throttle::record_passkey_signin_failure( $broken );
		}
		$this->assertTrue( Throttle::passkey_signin_blocked( $broken ) );
	}
}
