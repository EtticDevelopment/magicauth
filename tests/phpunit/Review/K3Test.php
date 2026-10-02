<?php
/**
 * K3: the emailed verify link must carry redirect_to intact. Core
 * add_query_arg() does not encode values, so a deep link holding & or #
 * is split into extra query args or cut off as a fragment.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Review;

use MagicAuth\Auth\TokenManager;
use PHPUnit\Framework\TestCase;

final class K3Test extends TestCase {

	protected function setUp(): void {
		magicauth_test_reset_state();
	}

	protected function tearDown(): void {
		magicauth_test_reset_state();
	}

	/** Parse the link the way PHP fills $_GET on the verify request. */
	private static function query_args( string $url ): array {
		$query = (string) parse_url( $url, PHP_URL_QUERY );
		parse_str( $query, $args );
		return $args;
	}

	public function test_redirect_to_with_ampersand_survives_round_trip(): void {
		$dest = home_url( '/courses/intro/?lesson=3&step=2' );
		$url  = TokenManager::build_verify_url( 'selector123', 'verifier456', $dest );
		$args = self::query_args( $url );

		$this->assertSame( $dest, (string) ( $args['redirect_to'] ?? '' ), 'deep link with & must reach the verify handler intact' );
		$this->assertArrayNotHasKey( 'step', $args, 'redirect_to parameters must not leak into the verify URL as top-level args' );
	}

	public function test_redirect_to_with_fragment_survives_round_trip(): void {
		$dest = home_url( '/courses/intro/lesson-3/#quiz' );
		$url  = TokenManager::build_verify_url( 'selector123', 'verifier456', $dest );

		$this->assertNull( parse_url( $url, PHP_URL_FRAGMENT ), 'redirect_to fragment must not become the verify URL fragment' );
		$args = self::query_args( $url );
		$this->assertSame( $dest, (string) ( $args['redirect_to'] ?? '' ), 'deep link with # must reach the verify handler intact' );
	}

	public function test_redirect_to_after_selector_does_not_override_verify_args(): void {
		// A redirect_to whose query names a verify arg must not clobber it.
		$dest = home_url( '/courses/?ref=mail&s=search-term' );
		$url  = TokenManager::build_verify_url( 'selector123', 'verifier456', $dest );
		$args = self::query_args( $url );

		$this->assertSame( 'selector123', (string) ( $args['s'] ?? '' ), 'selector must not be overwritten by redirect_to contents' );
		$this->assertSame( $dest, (string) ( $args['redirect_to'] ?? '' ) );
	}
}
