<?php
/**
 * Controller pre_throttle_gates: T37, T38, T39.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Model;

use MagicAuth\Auth\Controller;
use PHPUnit\Framework\TestCase;

final class ControllerTest extends TestCase {

	private function valid_post_and_server( int $rendered_at ): array {
		$post = [
			'magicauth_email'   => 'a@example.test',
			'magicauth_website' => '',
			'magicauth_ts'      => (string) $rendered_at,
		];
		$server = [
			'HTTP_ORIGIN'  => 'https://example.test',
			'HTTP_REFERER' => 'https://example.test/sign-in/',
		];
		return [ $post, $server ];
	}

	public function test_T37_honeypot_filled_returns_false(): void {
		[ $post, $server ]      = $this->valid_post_and_server( time() - 10 );
		$post['magicauth_website'] = 'https://attacker.example/';

		$this->assertFalse( Controller::pre_throttle_gates( $post, $server ) );
	}

	public function test_T38_origin_mismatch_returns_false(): void {
		[ $post, $server ]    = $this->valid_post_and_server( time() - 10 );
		$server['HTTP_ORIGIN']  = 'https://attacker.example';
		$server['HTTP_REFERER'] = 'https://attacker.example/spoof/';

		$this->assertFalse( Controller::pre_throttle_gates( $post, $server ) );
	}

	public function test_T38_origin_missing_returns_false(): void {
		[ $post, $server ] = $this->valid_post_and_server( time() - 10 );
		unset( $server['HTTP_ORIGIN'], $server['HTTP_REFERER'] );

		$this->assertFalse( Controller::pre_throttle_gates( $post, $server ) );
	}

	public function test_T39_time_to_fill_below_floor_returns_false(): void {
		[ $post, $server ] = $this->valid_post_and_server( time() );

		$this->assertFalse(
			Controller::pre_throttle_gates( $post, $server ),
			'Form submitted in same second as render: bot pattern'
		);
	}

	public function test_T39_time_to_fill_missing_returns_false(): void {
		[ $post, $server ] = $this->valid_post_and_server( time() - 10 );
		unset( $post['magicauth_ts'] );

		$this->assertFalse( Controller::pre_throttle_gates( $post, $server ) );
	}

	public function test_T39_time_to_fill_non_numeric_returns_false(): void {
		[ $post, $server ] = $this->valid_post_and_server( time() - 10 );
		$post['magicauth_ts'] = 'abc';

		$this->assertFalse( Controller::pre_throttle_gates( $post, $server ) );
	}

	public function test_happy_path_returns_true(): void {
		[ $post, $server ] = $this->valid_post_and_server( time() - 10 );

		$this->assertTrue( Controller::pre_throttle_gates( $post, $server ) );
	}

	public function test_referer_only_is_acceptable(): void {
		[ $post, $server ] = $this->valid_post_and_server( time() - 10 );
		unset( $server['HTTP_ORIGIN'] );

		$this->assertTrue( Controller::pre_throttle_gates( $post, $server ) );
	}
}
