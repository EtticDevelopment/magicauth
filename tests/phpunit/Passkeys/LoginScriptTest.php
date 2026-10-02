<?php
/**
 * The login script's lifecycle (SPEC 2.2, 8.4, 8.6, 8.9, 8.12, build step
 * 12): every scenario of js/login-lifecycle.js runs the shipped core and
 * login scripts in node against a fake DOM, fetch, navigator.credentials and
 * virtual timers. Covers the restart budget (one recovery per planned start,
 * expiry and button restarts spend none), the idle refresh cap, the button
 * handoff order (options fetch inside the gesture, the conditional request
 * settled before the modal get()), the completion form, the 60 s throttle,
 * the return error and the signals call. Skipped (not passed) without node.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use PHPUnit\Framework\TestCase;

final class LoginScriptTest extends TestCase {

	private const HARNESS = __DIR__ . '/js/login-lifecycle.js';

	private static function node(): ?string {
		$path = trim( (string) shell_exec( 'command -v node 2>/dev/null' ) );
		return '' !== $path && is_executable( $path ) ? $path : null;
	}

	/** @return array<string,array{string}> */
	public static function scenarios(): array {
		$node = self::node();
		if ( null === $node ) {
			return [ 'node missing' => [ '' ] ];
		}
		$list = (string) shell_exec( escapeshellarg( $node ) . ' ' . escapeshellarg( self::HARNESS ) . ' ' . escapeshellarg( MAGICAUTH_DIR ) . ' --list 2>&1' );
		$out  = [];
		foreach ( array_filter( array_map( 'trim', explode( "\n", $list ) ) ) as $name ) {
			$out[ $name ] = [ $name ];
		}
		return $out;
	}

	/** @dataProvider scenarios */
	public function test_scenario( string $name ): void {
		$node = self::node();
		if ( null === $node || '' === $name ) {
			$this->markTestSkipped( 'node is not installed' );
		}
		$cmd    = escapeshellarg( $node ) . ' ' . escapeshellarg( self::HARNESS ) . ' ' . escapeshellarg( MAGICAUTH_DIR ) . ' ' . escapeshellarg( $name ) . ' 2>&1';
		$output = (string) shell_exec( $cmd );
		$this->assertSame( "ok\n", $output, $name );
	}

	public function test_the_harness_lists_the_scenarios(): void {
		if ( null === self::node() ) {
			$this->markTestSkipped( 'node is not installed' );
		}
		$this->assertGreaterThanOrEqual( 35, count( self::scenarios() ) );
	}
}
