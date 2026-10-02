<?php
/**
 * T-RP (SPEC 7.1, 4.5, 6.1): RP ID, the single allowed origin, the request
 * Origin gate including navigation mode, and Module::available() with S8a to
 * S8g in their fixed order; Module::max_per_user() and supported_algs().
 * MAGICAUTH_PASSKEY_RP_ID cases run in separate processes (a constant cannot
 * be undefined again).
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Passkeys\Module;
use MagicAuth\Passkeys\RelyingParty;
use PHPUnit\Framework\TestCase;
use WP_Error;

final class RelyingPartyTest extends TestCase {

	private const HOME = 'https://academy.example.com';

	protected function setUp(): void {
		global $magicauth_test_state;
		magicauth_test_reset_state();
		$magicauth_test_state['home']   = self::HOME;
		$magicauth_test_state['is_ssl'] = true; // An https request, as on the academy.
		update_option( 'magicauth_db_version', 2 );
	}

	protected function tearDown(): void {
		magicauth_test_reset_state();
	}

	/** Home and site URLs; the request is https when the home is (unless $ssl says otherwise). */
	private static function site( string $home, ?string $siteurl = null, ?bool $ssl = null ): void {
		global $magicauth_test_state;
		$magicauth_test_state['home']   = $home;
		$magicauth_test_state['is_ssl'] = $ssl ?? ( 0 === strpos( $home, 'https:' ) );
		if ( null !== $siteurl ) {
			$magicauth_test_state['siteurl'] = $siteurl;
		} else {
			unset( $magicauth_test_state['siteurl'] );
		}
	}

	/** @param true|WP_Error $result */
	private function assert_unavailable( $result, string $code ): void {
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( $code, $result->get_error_code() );
		$this->assertNotSame( '', $result->get_error_message() );
	}

	/* ------------------------------------------------------------------ RP ID */

	public function test_rp_id_is_the_home_host(): void {
		$this->assertSame( 'academy.example.com', RelyingParty::id() );
		$this->assertSame( 'academy.example.com', RelyingParty::host() );
		$this->assertNull( RelyingParty::config_error() );
		$this->assertTrue( Module::available() );
	}

	public function test_localhost(): void {
		self::site( 'http://localhost:9400' );
		$this->assertSame( 'localhost', RelyingParty::id() );
		$this->assertSame( 'http://localhost:9400', RelyingParty::origin() );
		$this->assertTrue( RelyingParty::origin_allowed( 'http://localhost:9400' ) );
		$this->assertFalse( RelyingParty::origin_allowed( 'http://localhost:9401' ) );
		$this->assertTrue( Module::available(), 'http allowed for localhost only' );
	}

	public function test_upper_case_host_is_normalised(): void {
		self::site( 'https://Academy.Example.COM' );
		$this->assertSame( 'academy.example.com', RelyingParty::id() );
		$this->assertSame( 'https://academy.example.com', RelyingParty::origin() );
		$this->assertTrue( Module::available() );
	}

	/** @return array<string,array{string}> */
	public static function invalid_hosts(): array {
		return [
			'trailing dot' => [ 'https://academy.example.com.' ],
			'double dot'   => [ 'https://academy..example.com' ],
			'single label' => [ 'https://intranet' ],
			'underscore'   => [ 'https://my_site.example' ],
		];
	}

	/** @dataProvider invalid_hosts */
	public function test_invalid_hosts_give_no_rp_id( string $home ): void {
		self::site( $home );
		$this->assertSame( '', RelyingParty::id() );
		$this->assertInstanceOf( WP_Error::class, RelyingParty::config_error() );
		$this->assert_unavailable( Module::available(), 'magicauth_pk_rp_id_invalid' );
	}

	/** @return array<string,array{string,string,bool}> */
	public static function rp_ids(): array {
		return [
			'equal'              => [ 'academy.example.com', 'academy.example.com', true ],
			'parent suffix'      => [ 'example.com', 'academy.example.com', true ],
			'not a suffix'       => [ 'evil.com', 'academy.example.com', false ],
			'label suffix only'  => [ 'lem.com', 'academy.example.com', false ],
			'longer than host'   => [ 'x.academy.example.com', 'academy.example.com', false ],
			'trailing dot'       => [ 'example.com.', 'academy.example.com', false ],
			'leading dot'        => [ '.example.com', 'academy.example.com', false ],
			'double dot'         => [ 'example..com', 'academy.example..com', false ],
			'upper case'         => [ 'Example.com', 'academy.example.com', false ],
			'single label'       => [ 'com', 'academy.example.com', false ],
			'localhost'          => [ 'localhost', 'localhost', true ],
			'IPv4'               => [ '127.0.0.1', '127.0.0.1', false ],
			'IPv6 bracketed'     => [ '::1', '[::1]', false ],
			'punycode A-label'   => [ 'xn--bcher-kva.example', 'xn--bcher-kva.example', true ],
			'unicode'            => [ 'bücher.example', 'bücher.example', false ],
			'empty'              => [ '', 'academy.example.com', false ],
		];
	}

	/** @dataProvider rp_ids */
	public function test_is_valid_rp_id( string $rp, string $host, bool $valid ): void {
		$this->assertSame( $valid, RelyingParty::is_valid_rp_id( $rp, $host ) );
	}

	/** @return array<string,array{string,string}> */
	public static function constants(): array {
		return [
			'suffix'          => [ 'example.com', 'example.com' ],
			'upper case'      => [ 'EXAMPLE.com', 'example.com' ],
			'the host itself' => [ 'academy.example.com', 'academy.example.com' ],
			'evil.com'        => [ 'evil.com', '' ],
			'com'             => [ 'com', '' ],
			'trailing dot'    => [ 'example.com.', '' ],
			'empty'           => [ '', '' ],
		];
	}

	/**
	 * MAGICAUTH_PASSKEY_RP_ID: a suffix of the host with two labels or more,
	 * else S8g and no RP ID. S6b shows when the RP ID differs from the host.
	 *
	 * @dataProvider constants
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_rp_id_constant( string $constant, string $expected ): void {
		global $magicauth_test_state;
		define( 'MAGICAUTH_PASSKEY_RP_ID', $constant );
		magicauth_test_reset_state();
		$magicauth_test_state['home']   = self::HOME;
		$magicauth_test_state['is_ssl'] = true;
		update_option( 'magicauth_db_version', 2 );

		$this->assertSame( $expected, RelyingParty::id() );
		$this->assertSame( 'https://academy.example.com', RelyingParty::origin(), 'the origin never changes' );
		if ( '' === $expected ) {
			$this->assert_unavailable( Module::available(), 'magicauth_pk_rp_id_invalid' );
			$this->assertSame( 'MAGICAUTH_PASSKEY_RP_ID is not a valid suffix of the site host.', RelyingParty::config_error()->get_error_message() );
		} else {
			$this->assertTrue( Module::available() );
			$this->assertSame( 'academy.example.com' !== $expected, RelyingParty::id() !== RelyingParty::host(), 'S6b condition' );
		}
	}

	/**
	 * The constant needs two labels even where the host is localhost (which
	 * is a valid RP ID without the constant).
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_rp_id_constant_localhost_is_refused(): void {
		global $magicauth_test_state;
		define( 'MAGICAUTH_PASSKEY_RP_ID', 'localhost' );
		magicauth_test_reset_state();
		$magicauth_test_state['home'] = 'http://localhost:9400';
		update_option( 'magicauth_db_version', 2 );

		$this->assertTrue( RelyingParty::is_valid_rp_id( 'localhost', 'localhost' ) );
		$this->assertSame( '', RelyingParty::id() );
		$this->assert_unavailable( Module::available(), 'magicauth_pk_rp_id_invalid' );
	}

	/* ------------------------------------------------------------------ origins */

	/** @return array<string,array{string,?string}> */
	public static function origins(): array {
		return [
			'plain'               => [ 'https://academy.example.com', 'https://academy.example.com' ],
			'default port 443'    => [ 'https://academy.example.com:443', 'https://academy.example.com' ],
			'default port 80'     => [ 'http://academy.example.com:80/', 'http://academy.example.com' ],
			'other port'          => [ 'https://academy.example.com:8443', 'https://academy.example.com:8443' ],
			'path and query'      => [ 'https://academy.example.com/login/?x=1#y', 'https://academy.example.com' ],
			'upper case'          => [ 'HTTPS://Academy.Example.Com', 'https://academy.example.com' ],
			'IPv6'                => [ 'https://[::1]:8443', 'https://[::1]:8443' ],
			'null'                => [ 'null', null ],
			'empty'               => [ '', null ],
			'no scheme'           => [ 'academy.example.com', null ],
			'scheme-relative'     => [ '//academy.example.com', null ],
			'ftp'                 => [ 'ftp://academy.example.com', null ],
			'javascript'          => [ 'javascript:alert(1)', null ],
			'userinfo'            => [ 'https://user@academy.example.com', null ],
			'port 0'              => [ 'https://academy.example.com:0', null ],
			'whitespace'          => [ ' https://academy.example.com', null ],
			'unparsable'          => [ 'https://:443', null ],
		];
	}

	/** @dataProvider origins */
	public function test_normalise_origin( string $url, ?string $expected ): void {
		$this->assertSame( $expected, RelyingParty::normalise_origin( $url ) );
	}

	public function test_origin_allowed_is_an_exact_compare(): void {
		$this->assertSame( 'https://academy.example.com', RelyingParty::origin() );
		$this->assertTrue( RelyingParty::origin_allowed( 'https://academy.example.com' ) );
		foreach ( [ 'https://academy.example.com/', 'https://academy.example.com:443', 'https://Academy.example.com', 'http://academy.example.com', 'https://academy.example.com:8443', 'https://x.academy.example.com', 'https://example.com', '' ] as $origin ) {
			$this->assertFalse( RelyingParty::origin_allowed( $origin ), $origin );
		}

		// Home with an explicit default port: the same origin.
		self::site( 'https://academy.example.com:443' );
		$this->assertSame( 'https://academy.example.com', RelyingParty::origin() );
		$this->assertTrue( Module::available() );
	}

	/* ------------------------------------------------------------------ request Origin gate */

	/** @return array<string,array{array<string,string>,bool,bool}> server, ok, ok in navigation mode */
	public static function requests(): array {
		$nav = [
			'HTTP_SEC_FETCH_SITE' => 'same-origin',
			'HTTP_SEC_FETCH_MODE' => 'navigate',
		];
		return [
			'Origin'                           => [ [ 'HTTP_ORIGIN' => self::HOME ], true, true ],
			'Origin with default port'         => [ [ 'HTTP_ORIGIN' => self::HOME . ':443' ], true, true ],
			'Origin foreign'                   => [ [ 'HTTP_ORIGIN' => 'https://evil.example' ], false, false ],
			'Origin subdomain'                 => [ [ 'HTTP_ORIGIN' => 'https://x.academy.example.com' ], false, false ],
			'Origin http'                      => [ [ 'HTTP_ORIGIN' => 'http://academy.example.com' ], false, false ],
			'Origin foreign, valid Referer'    => [ [ 'HTTP_ORIGIN' => 'https://evil.example', 'HTTP_REFERER' => self::HOME . '/login/' ], false, false ],
			'Origin unparsable, valid Referer' => [ [ 'HTTP_ORIGIN' => '%%%', 'HTTP_REFERER' => self::HOME . '/login/' ], false, false ],
			'Origin empty, valid Referer'      => [ [ 'HTTP_ORIGIN' => '', 'HTTP_REFERER' => self::HOME . '/login/' ], false, false ],
			'Referer only'                     => [ [ 'HTTP_REFERER' => self::HOME . '/login/?a=1' ], true, true ],
			'Referer foreign'                  => [ [ 'HTTP_REFERER' => 'https://evil.example/academy.example.com' ], false, false ],
			'neither'                          => [ [], false, false ],
			'null with valid Referer'          => [ [ 'HTTP_ORIGIN' => 'null', 'HTTP_REFERER' => self::HOME . '/' ], false, false ],
			'null, fetch metadata'             => [ [ 'HTTP_ORIGIN' => 'null' ] + $nav, false, true ],
			'null, same-site'                  => [ [ 'HTTP_ORIGIN' => 'null', 'HTTP_SEC_FETCH_SITE' => 'same-site', 'HTTP_SEC_FETCH_MODE' => 'navigate' ], false, false ],
			'null, cross-site'                 => [ [ 'HTTP_ORIGIN' => 'null', 'HTTP_SEC_FETCH_SITE' => 'cross-site', 'HTTP_SEC_FETCH_MODE' => 'navigate' ], false, false ],
			'null, none'                       => [ [ 'HTTP_ORIGIN' => 'null', 'HTTP_SEC_FETCH_SITE' => 'none', 'HTTP_SEC_FETCH_MODE' => 'navigate' ], false, false ],
			'null, mode cors'                  => [ [ 'HTTP_ORIGIN' => 'null', 'HTTP_SEC_FETCH_SITE' => 'same-origin', 'HTTP_SEC_FETCH_MODE' => 'cors' ], false, false ],
			'null, site header only'           => [ [ 'HTTP_ORIGIN' => 'null', 'HTTP_SEC_FETCH_SITE' => 'same-origin' ], false, false ],
			'null, mode header only'           => [ [ 'HTTP_ORIGIN' => 'null', 'HTTP_SEC_FETCH_MODE' => 'navigate' ], false, false ],
			'null, upper-case metadata'        => [ [ 'HTTP_ORIGIN' => 'null', 'HTTP_SEC_FETCH_SITE' => 'Same-Origin', 'HTTP_SEC_FETCH_MODE' => 'navigate' ], false, false ],
			'NULL upper case'                  => [ [ 'HTTP_ORIGIN' => 'NULL' ] + $nav, false, false ],
		];
	}

	/**
	 * @dataProvider requests
	 * @param array<string,string> $server
	 */
	public function test_request_origin_ok( array $server, bool $ok, bool $navigation_ok ): void {
		$this->assertSame( $ok, RelyingParty::request_origin_ok( $server ), 'fetch mode' );
		$this->assertSame( $navigation_ok, RelyingParty::request_origin_ok( $server, true ), 'navigation mode' );
	}

	public function test_request_origin_rejects_non_string_headers_and_a_misconfigured_site(): void {
		$this->assertFalse( RelyingParty::request_origin_ok( [ 'HTTP_ORIGIN' => [ self::HOME ] ] ) );
		$this->assertFalse( RelyingParty::request_origin_ok( [ 'HTTP_REFERER' => [ self::HOME ] ] ) );
		self::site( 'not a url' );
		$this->assertFalse( RelyingParty::request_origin_ok( [ 'HTTP_ORIGIN' => 'not a url' ] ) );
	}

	/* ------------------------------------------------------------------ available() */

	public function test_ip_hosts_are_s8a(): void {
		foreach ( [ 'https://127.0.0.1', 'https://[::1]', 'https://10.0.0.5:8443' ] as $home ) {
			self::site( $home );
			$this->assert_unavailable( Module::available(), 'magicauth_pk_ip_host' );
		}
	}

	public function test_http_is_s8d(): void {
		self::site( 'http://academy.example.com' );
		$this->assert_unavailable( Module::available(), 'magicauth_pk_not_https' );
	}

	/** @return array<string,array{string}> */
	public static function other_site_urls(): array {
		return [
			'host'   => [ 'https://www.academy.example.com' ],
			'scheme' => [ 'http://academy.example.com' ],
			'port'   => [ 'https://academy.example.com:8443' ],
		];
	}

	/**
	 * A stored http site URL differs only on an http request: site_url()
	 * follows the request scheme.
	 *
	 * @dataProvider other_site_urls
	 */
	public function test_home_and_site_origin_mismatch_is_s8b( string $siteurl ): void {
		self::site( self::HOME, $siteurl, 0 !== strpos( $siteurl, 'http:' ) );
		$this->assert_unavailable( Module::available(), 'magicauth_pk_origin_mismatch' );
	}

	/**
	 * site_url() follows the request scheme (core set_url_scheme()), home_url()
	 * keeps the stored one: on a plain-http request to an https site the two
	 * origins differ and the module is unavailable for that request.
	 */
	public function test_plain_http_request_to_an_https_site_is_s8b(): void {
		global $magicauth_test_state;
		$magicauth_test_state['is_ssl'] = false;
		$this->assert_unavailable( Module::available(), 'magicauth_pk_origin_mismatch' );
	}

	public function test_site_url_in_a_subfolder_is_one_origin(): void {
		self::site( self::HOME, self::HOME . '/wp' );
		$this->assertTrue( Module::available() );
	}

	public function test_shared_host_is_s8e(): void {
		global $magicauth_test_state;

		self::site( self::HOME . '/blog/', self::HOME . '/blog' );
		$this->assert_unavailable( Module::available(), 'magicauth_pk_shared_host' );

		self::site( self::HOME . '/' );
		$this->assertTrue( Module::available(), 'home path "/"' );

		// Subdirectory multisite with two sites on the host.
		self::site( self::HOME );
		$magicauth_test_state['multisite'] = true;
		$magicauth_test_state['sites']     = [
			[
				'domain' => 'academy.example.com',
				'path'   => '/',
			],
			[
				'domain' => 'academy.example.com',
				'path'   => '/nl/',
			],
			[
				'domain' => 'other.example',
				'path'   => '/',
			],
		];
		$this->assert_unavailable( Module::available(), 'magicauth_pk_shared_host' );

		// One site on this host: available.
		array_splice( $magicauth_test_state['sites'], 1, 1 );
		$this->assertTrue( Module::available() );

		// Subdomain multisite: every site has its own host.
		$magicauth_test_state['subdomain_install'] = true;
		$magicauth_test_state['sites'][]           = [
			'domain' => 'academy.example.com',
			'path'   => '/',
		];
		$this->assertTrue( Module::available() );
	}

	public function test_missing_schema_is_s8f(): void {
		update_option( 'magicauth_db_version', 1 );
		$this->assert_unavailable( Module::available(), 'magicauth_pk_schema' );
		delete_option( 'magicauth_db_version' );
		$this->assert_unavailable( Module::available(), 'magicauth_pk_schema' );
		update_option( 'magicauth_db_version', '2' );
		$this->assertTrue( Module::available() );
	}

	public function test_missing_openssl_is_s8c(): void {
		Module::set_openssl_for_tests( false );
		$this->assert_unavailable( Module::available(), 'magicauth_pk_no_openssl' );
		Module::set_openssl_for_tests( null );
		$this->assertTrue( Module::available() );
	}

	/** Precedence S8c, S8a, S8d, S8b, S8g, S8e, S8f with every later condition also true. */
	public function test_available_precedence(): void {
		global $magicauth_test_state;
		$magicauth_test_state['multisite'] = true;
		$magicauth_test_state['sites']     = [
			[ 'domain' => '10.0.0.5' ],
			[ 'domain' => '10.0.0.5' ],
		];
		update_option( 'magicauth_db_version', 1 );
		Module::set_openssl_for_tests( false );
		self::site( 'http://10.0.0.5/blog/', 'http://10.0.0.6/blog' );

		$steps = [
			'magicauth_pk_no_openssl'      => static function (): void {
				Module::set_openssl_for_tests( true );
			},
			'magicauth_pk_ip_host'         => static function (): void {
				self::site( 'http://academy..example.com/blog/', 'https://academy..example.com:8443/blog' );
			},
			'magicauth_pk_not_https'       => static function (): void {
				self::site( 'https://academy..example.com/blog/', 'https://academy..example.com:8443/blog' );
			},
			'magicauth_pk_origin_mismatch' => static function (): void {
				self::site( 'https://academy..example.com/blog/', 'https://academy..example.com/blog' );
			},
			'magicauth_pk_rp_id_invalid'   => static function () use ( &$magicauth_test_state ): void {
				self::site( 'https://academy.example.com/blog/', 'https://academy.example.com/blog' );
				$magicauth_test_state['sites'] = [
					[ 'domain' => 'academy.example.com' ],
					[ 'domain' => 'academy.example.com' ],
				];
			},
			'magicauth_pk_shared_host'     => static function () use ( &$magicauth_test_state ): void {
				self::site( 'https://academy.example.com/blog/', 'https://academy.example.com/blog' );
				self::site( self::HOME );
				$magicauth_test_state['sites'] = [];
			},
			'magicauth_pk_schema'          => static function (): void {
				update_option( 'magicauth_db_version', 2 );
			},
		];
		foreach ( $steps as $code => $fix ) {
			$this->assert_unavailable( Module::available(), $code );
			$fix();
		}
		$this->assertTrue( Module::available() );
	}

	public function test_available_messages(): void {
		Module::set_openssl_for_tests( false );
		$this->assertSame( 'the PHP OpenSSL extension is missing.', Module::available()->get_error_message() );
		Module::set_openssl_for_tests( null );
		self::site( 'http://academy.example.com' );
		$this->assertSame( 'the site is not served over HTTPS.', Module::available()->get_error_message() );
	}

	/** set_openssl_for_tests() is a no-op outside MAGICAUTH_TESTING. */
	public function test_openssl_seam_is_inert_in_production(): void {
		$script = 'define( "ABSPATH", "/" ); require ' . var_export( MAGICAUTH_DIR . 'includes/Passkeys/Module.php', true ) . ';'
			. ' MagicAuth\Passkeys\Module::set_openssl_for_tests( false );'
			. ' $p = new ReflectionProperty( MagicAuth\Passkeys\Module::class, "openssl_for_tests" );'
			. ' if ( PHP_VERSION_ID < 80100 ) { $p->setAccessible( true ); }'
			. ' echo var_export( $p->getValue(), true );';
		$out = shell_exec( escapeshellarg( PHP_BINARY ) . ' -n -r ' . escapeshellarg( $script ) . ' 2>&1' );
		$this->assertSame( 'NULL', trim( (string) $out ) );
	}

	/* ------------------------------------------------------------------ Module helpers */

	public function test_max_per_user(): void {
		$this->assertSame( 10, Module::MAX_PER_USER );
		$this->assertSame( 10, Module::max_per_user() );
		$cases = [
			[ 3, 3 ],
			[ 25, 25 ],
			[ 26, 25 ],
			[ 0, 1 ],
			[ -5, 1 ],
			[ '7', 7 ],
			[ 'many', 10 ],
			[ null, 10 ],
		];
		foreach ( $cases as [ $value, $expected ] ) {
			$filter = static function () use ( $value ) {
				return $value;
			};
			add_filter( 'magicauth_passkey_max_per_user', $filter );
			$this->assertSame( $expected, Module::max_per_user(), var_export( $value, true ) );
			remove_filter( 'magicauth_passkey_max_per_user', $filter );
		}
	}

	public function test_supported_algs(): void {
		$eddsa = function_exists( 'sodium_crypto_sign_verify_detached' ) || defined( 'OPENSSL_KEYTYPE_ED25519' );
		$this->assertSame( $eddsa ? [ -7, -8, -257 ] : [ -7, -257 ], Module::supported_algs() );
	}
}
