<?php
/**
 * Review r1-crypto-02: ext-mbstring is optional in WordPress (compat.php
 * polyfills only mb_substr and mb_strlen), so the passkey code may call no
 * other mb_* function unguarded. client_data() validates UTF-8 with PCRE,
 * display_name() cuts on a UTF-8 boundary without mb_strcut, and name
 * comparisons go through Presenter::name_key(). Each replacement must agree
 * with the mbstring result it replaced.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Passkeys\Base64Url;
use MagicAuth\Passkeys\Options;
use MagicAuth\Passkeys\Presenter;
use MagicAuth\Passkeys\Verifier;
use MagicAuth\Tests\Support\Ceremony;
use PHPUnit\Framework\TestCase;

final class NoMbstringTest extends TestCase {

	/** Polyfilled by wp-includes/compat.php. */
	private const POLYFILLED = [ 'mb_substr', 'mb_strlen' ];

	protected function setUp(): void {
		Ceremony::site();
	}

	protected function tearDown(): void {
		magicauth_test_reset_state();
	}

	/** Every production mb_* call is polyfilled by core or guarded by function_exists() in its file. */
	public function test_no_unguarded_mbstring_call_in_production_code(): void {
		$root  = dirname( __DIR__, 3 ) . '/';
		$files = [ $root . 'magicauth.php', $root . 'uninstall.php' ];
		foreach ( [ 'includes', 'templates' ] as $dir ) {
			$it = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $root . $dir, \FilesystemIterator::SKIP_DOTS ) );
			foreach ( $it as $file ) {
				$path = (string) $file;
				if ( '.php' === substr( $path, -4 ) && false === strpos( $path, '/includes/ThirdParty/' ) ) {
					$files[] = $path;
				}
			}
		}
		$this->assertGreaterThan( 40, count( $files ) );

		$unguarded = [];
		foreach ( $files as $path ) {
			$source = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
			$tokens = token_get_all( $source );
			foreach ( $tokens as $i => $token ) {
				if ( ! is_array( $token ) || T_STRING !== $token[0] || 0 !== strpos( strtolower( $token[1] ), 'mb_' ) ) {
					continue;
				}
				$name = strtolower( $token[1] );
				$next = $tokens[ $i + 1 ] ?? null;
				if ( '(' !== $next || in_array( $name, self::POLYFILLED, true ) ) {
					continue;
				}
				if ( false === strpos( $source, "function_exists( '" . $name . "' )" ) ) {
					$unguarded[] = substr( $path, strlen( $root ) ) . ':' . $token[2] . ' ' . $name;
				}
			}
		}
		$this->assertSame( [], $unguarded );
	}

	/** @return array<string,array{string,bool}> */
	public static function utf8_members(): array {
		return [
			'multibyte'         => [ "\u{e9}\u{20ac}\u{1f600}", true ],
			'overlong'          => [ "\xc0\xaf", false ],
			'surrogate'         => [ "\xed\xa0\x80", false ],
			'above U+10FFFF'    => [ "\xf4\x90\x80\x80", false ],
			'truncated'         => [ "\xe2\x82", false ],
			'lone continuation' => [ "\x80", false ],
			'invalid lead'      => [ "\xff", false ],
		];
	}

	/** @dataProvider utf8_members */
	public function test_client_data_utf8_check_matches_mbstring( string $member, bool $valid ): void {
		$json = (string) json_encode( // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode
			[
				'type'      => 'webauthn.get',
				'challenge' => Base64Url::encode( str_repeat( "\xab", 32 ) ),
				'origin'    => 'https://academy.example.com',
				'x'         => 'MEMBER',
			],
			JSON_UNESCAPED_SLASHES
		);
		$json = str_replace( 'MEMBER', $member, $json );
		if ( function_exists( 'mb_check_encoding' ) ) {
			$this->assertSame( $valid, mb_check_encoding( $json, 'UTF-8' ), 'test data agrees with mbstring' );
		}
		$this->assertSame( $valid, null !== Verifier::client_data( $json, 'webauthn.get' ) );
	}

	/** @return array<string,array{string,string}> */
	public static function long_names(): array {
		return [
			'2-byte split'  => [ str_repeat( 'a', 127 ) . "\u{e9}", str_repeat( 'a', 127 ) ],
			'3-byte split'  => [ str_repeat( 'a', 126 ) . "\u{20ac}", str_repeat( 'a', 126 ) ],
			'4-byte split'  => [ str_repeat( 'a', 125 ) . "\u{1f600}x", str_repeat( 'a', 125 ) ],
			'4-byte fits'   => [ str_repeat( 'a', 124 ) . "\u{1f600}x", str_repeat( 'a', 124 ) . "\u{1f600}" ],
			'boundary at N' => [ str_repeat( 'a', 128 ) . "\u{e9}", str_repeat( 'a', 128 ) ],
			'all 3-byte'    => [ str_repeat( "\u{20ac}", 50 ), str_repeat( "\u{20ac}", 42 ) ],
		];
	}

	/** @dataProvider long_names */
	public function test_display_name_cut_matches_mb_strcut( string $raw, string $expected ): void {
		$user               = Ceremony::user( 7 );
		$user->display_name = $raw;
		if ( function_exists( 'mb_strcut' ) ) {
			$this->assertSame( $expected, mb_strcut( $raw, 0, 128, 'UTF-8' ), 'test data agrees with mbstring' );
		}
		$this->assertSame( $expected, Options::display_name( $user ) );
	}

	public function test_name_key_folds_case(): void {
		$this->assertSame( Presenter::name_key( 'Passkey on Mac' ), Presenter::name_key( 'PASSKEY ON MAC' ) );
		$this->assertNotSame( Presenter::name_key( 'Passkey' ), Presenter::name_key( 'Passkey (2)' ) );
		if ( function_exists( 'mb_strtolower' ) ) {
			$this->assertSame( Presenter::name_key( "\u{c9}cole" ), Presenter::name_key( "\u{e9}cole" ) );
		}
		// default_name() de-duplicates through the same key.
		$this->assertSame( 'Passkey (2)', Presenter::default_name( '', '', '', [ 'PASSKEY' ] ) );
	}
}
