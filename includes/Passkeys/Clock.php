<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Passkeys;

defined( 'ABSPATH' ) || exit;

/**
 * Current Unix time for every TTL and window computation of the passkey
 * module and the upgrade lock. Tests pin it with set_for_tests(); the
 * override is ignored outside MAGICAUTH_TESTING.
 */
final class Clock {

	/**
	 * Pinned time; only read under MAGICAUTH_TESTING.
	 *
	 * @var ?int
	 */
	private static ?int $now = null;

	/** Unix time; the pinned value under MAGICAUTH_TESTING. */
	public static function now(): int {
		if ( null !== self::$now && self::testing() ) {
			return self::$now;
		}
		return time();
	}

	/**
	 * Test-only: pin now(). No-op outside MAGICAUTH_TESTING.
	 *
	 * @param ?int $now Unix time to return, or null to follow time() again.
	 */
	public static function set_for_tests( ?int $now ): void {
		if ( ! self::testing() ) {
			return;
		}
		self::$now = $now;
	}

	/** Whether the test harness is running. */
	private static function testing(): bool {
		return defined( 'MAGICAUTH_TESTING' ) && MAGICAUTH_TESTING;
	}
}
