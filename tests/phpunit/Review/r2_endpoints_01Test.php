<?php
/**
 * r2-endpoints-01: Throttle::bump_cache() assumes wp_cache_incr() returns
 * false on a missing key (core, Memcached). The Redis Object Cache drop-in
 * (rhubarbgroup/redis-cache, includes/object-cache.php increment()) runs
 * INCRBY, which on a missing key creates it at the offset with no TTL and
 * returns that value (its igbinary path does GET then SET without px when
 * pttl is -2, same result). When a bucket expires or is evicted between the
 * peek and the incr, the add-on-false recovery never runs and the bucket is
 * left without an expiry: once it reaches max + 1 it refuses for good.
 *
 * The race is modelled by wrapping the test state for one call: the second
 * read of ext_object_cache in that call is Throttle::bump() choosing the
 * cache path, after peek() read the count and before bump_cache() increments.
 * At that point the key is dropped and replaced by what INCRBY sees on a
 * missing key (value 0, no expiry), so the stub's incr behaves like Redis.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Review;

use MagicAuth\Auth\Throttle;
use MagicAuth\Passkeys\Clock;
use MagicAuth\Tests\Support\Ceremony;
use PHPUnit\Framework\TestCase;

/** Test state that runs a callback on the Nth read of one key. */
final class R2Endpoints01State extends \ArrayObject {

	/** @var callable|null */
	public $on_read = null;

	public string $watch = '';

	public int $reads = 0;

	/** @param mixed $key */
	#[\ReturnTypeWillChange]
	public function offsetExists( $key ) {
		if ( $key === $this->watch && null !== $this->on_read ) {
			++$this->reads;
			( $this->on_read )( $this, $this->reads );
		}
		return parent::offsetExists( $key );
	}
}

final class r2_endpoints_01Test extends TestCase {

	protected function setUp(): void {
		global $magicauth_test_state;
		Ceremony::site();
		Ceremony::enable_module();
		Clock::set_for_tests( time() );
		$magicauth_test_state['ext_object_cache'] = true;
	}

	protected function tearDown(): void {
		global $magicauth_test_state;
		if ( $magicauth_test_state instanceof \ArrayObject ) {
			$magicauth_test_state = $magicauth_test_state->getArrayCopy();
		}
		$magicauth_test_state['ext_object_cache'] = false;
		magicauth_test_reset_state();
	}

	/** Shift every object cache expiry back by $seconds (the stub reads time()). */
	private static function advance( int $seconds ): void {
		global $magicauth_test_state;
		foreach ( $magicauth_test_state['object_cache'] as $group => $entries ) {
			foreach ( $entries as $key => $entry ) {
				if ( $entry[1] > 0 ) {
					$magicauth_test_state['object_cache'][ $group ][ $key ][1] = $entry[1] - $seconds;
				}
			}
		}
		Clock::set_for_tests( Clock::now() + $seconds );
	}

	/**
	 * Run $call with the bucket $key expiring between peek and incr, Redis
	 * style: INCRBY on a missing key starts from 0 and sets no TTL.
	 */
	private static function with_redis_expiry_race( string $key, callable $call ): mixed {
		global $magicauth_test_state;
		$state          = new R2Endpoints01State( $magicauth_test_state );
		$state->watch   = 'ext_object_cache';
		$state->on_read = static function ( \ArrayObject $s, int $reads ) use ( $key ): void {
			if ( 2 === $reads ) {
				$cache                      = $s['object_cache'] ?? [];
				$cache['transient'][ $key ] = [ 0, 0 ];
				$s['object_cache']          = $cache;
			}
		};
		$magicauth_test_state = $state;
		try {
			return $call();
		} finally {
			$magicauth_test_state = $state->getArrayCopy();
		}
	}

	public function test_options_ip_bucket_recreated_by_redis_incr_still_expires(): void {
		global $magicauth_test_state;
		add_filter( 'magicauth_passkey_options_ip_max', static fn() => 30 );
		$bucket = 'r2-endpoints-01-net';
		$key    = 'magicauth_throttle_passkey_opts_ip_' . $bucket;

		for ( $i = 1; $i <= 5; $i++ ) {
			$this->assertTrue( Throttle::allow_passkey_options_ip( $bucket ) );
		}
		$this->assertSame( 5, $magicauth_test_state['object_cache']['transient'][ $key ][0] );

		// The window ends between this call's peek and its incr.
		$this->assertTrue(
			self::with_redis_expiry_race( $key, static fn() => Throttle::allow_passkey_options_ip( $bucket ) )
		);

		// Fill the bucket past its cap.
		for ( $i = 0; $i < 40; $i++ ) {
			Throttle::allow_passkey_options_ip( $bucket );
		}
		$this->assertFalse( Throttle::allow_passkey_options_ip( $bucket ), 'refused once past the cap' );

		self::advance( 3600 );
		$this->assertTrue(
			Throttle::allow_passkey_options_ip( $bucket ),
			'still refused an hour later: the bucket INCRBY recreated has no expiry ('
				. var_export( $magicauth_test_state['object_cache']['transient'][ $key ] ?? null, true ) . ')'
		);
	}

	public function test_user_bucket_recreated_by_redis_incr_still_expires(): void {
		global $magicauth_test_state;
		$bucket          = Throttle::ACTION_PASSKEY_REGFAIL_USER;
		[ $max, $window ] = Throttle::PASSKEY_USER_LIMITS[ $bucket ];
		$key             = 'magicauth_throttle_' . $bucket . '_u7';

		$this->assertTrue( Throttle::allow_passkey_user( $bucket, 7, $max, $window ) );
		$this->assertArrayHasKey( $key, $magicauth_test_state['object_cache']['transient'] );

		self::with_redis_expiry_race( $key, static fn() => Throttle::allow_passkey_user( $bucket, 7, $max, $window ) );

		for ( $i = 0; $i < $max + 2; $i++ ) {
			Throttle::allow_passkey_user( $bucket, 7, $max, $window );
		}
		$this->assertTrue( Throttle::passkey_user_exhausted( $bucket, 7, $max ) );

		self::advance( $window * 10 );
		$this->assertFalse(
			Throttle::passkey_user_exhausted( $bucket, 7, $max ),
			'per-user bucket still exhausted ten windows later: no expiry ('
				. var_export( $magicauth_test_state['object_cache']['transient'][ $key ] ?? null, true ) . ')'
		);
	}

	/**
	 * Opening call: peek saw no bucket, the add then fails (the key exists
	 * again) and the incr runs on a key with no expiry, returning 1. The
	 * window must still get its TTL.
	 */
	public function test_opening_call_with_recreated_key_still_sets_the_window(): void {
		global $magicauth_test_state;
		$bucket           = Throttle::ACTION_PASSKEY_REGFAIL_USER;
		[ $max, $window ] = Throttle::PASSKEY_USER_LIMITS[ $bucket ];
		$key              = 'magicauth_throttle_' . $bucket . '_u8';

		$this->assertTrue(
			self::with_redis_expiry_race( $key, static fn() => Throttle::allow_passkey_user( $bucket, 8, $max, $window ) )
		);
		$entry = $magicauth_test_state['object_cache']['transient'][ $key ] ?? null;
		$this->assertIsArray( $entry );
		$this->assertSame( 1, $entry[0] );
		$this->assertGreaterThan( 0, $entry[1], 'the opening call left the bucket without an expiry' );

		for ( $i = 0; $i < $max + 2; $i++ ) {
			Throttle::allow_passkey_user( $bucket, 8, $max, $window );
		}
		$this->assertTrue( Throttle::passkey_user_exhausted( $bucket, 8, $max ) );
		self::advance( $window + 1 );
		$this->assertFalse( Throttle::passkey_user_exhausted( $bucket, 8, $max ) );
	}

	/** A normal incr on a live bucket keeps the window's original expiry. */
	public function test_normal_incr_keeps_the_window_expiry(): void {
		global $magicauth_test_state;
		$bucket           = Throttle::ACTION_PASSKEY_REGFAIL_USER;
		[ $max, $window ] = Throttle::PASSKEY_USER_LIMITS[ $bucket ];
		$key              = 'magicauth_throttle_' . $bucket . '_u9';

		$this->assertTrue( Throttle::allow_passkey_user( $bucket, 9, $max, $window ) );
		$expiry = $magicauth_test_state['object_cache']['transient'][ $key ][1];
		self::advance( 5 );
		$this->assertTrue( Throttle::allow_passkey_user( $bucket, 9, $max, $window ) );
		$this->assertSame( [ 2, $expiry - 5 ], $magicauth_test_state['object_cache']['transient'][ $key ] );
	}
}
