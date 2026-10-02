<?php
/**
 * Review r1-endpoints-01: calls one network was already refused for must not
 * count toward the site-wide signin_options ceiling, or a single host can
 * exhaust it and throttle every visitor (SPEC T14, 6.2: only a distributed
 * flood may reach the ceiling).
 *
 * Fixed: SignInEndpoints::options() checks passkey_opts_ip first and counts
 * a call toward passkey_opts_global only when its network passed.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Passkeys\SignInEndpoints;
use MagicAuth\Tests\Stubs\JsonResponseSent;
use MagicAuth\Tests\Support\Ceremony;
use PHPUnit\Framework\TestCase;

final class OptionsCeilingOrderTest extends TestCase {

	/** @var array<string,mixed> */
	private array $server = [];

	protected function setUp(): void {
		$this->server = $_SERVER;
		Ceremony::site();
		Ceremony::enable_module();
		$_COOKIE = [];
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

	private static function options( string $ip ): ?int {
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

	public function test_one_refused_network_cannot_exhaust_the_global_ceiling(): void {
		add_filter( 'magicauth_passkey_options_global_max', static fn() => 500 );
		add_filter( 'magicauth_passkey_options_ip_max', static fn() => 30 );

		$statuses = [];
		for ( $i = 1; $i <= 501; $i++ ) {
			$statuses[] = self::options( '203.0.113.10' );
		}
		$this->assertSame( 200, $statuses[29], 'call 30 from A allowed' );
		$this->assertSame( 429, $statuses[30], 'call 31 from A refused by its network bucket' );

		$this->assertSame( 200, self::options( '198.51.100.7' ), 'another network still gets options after one host was refused' );
	}
}
