<?php
/**
 * Release prep (SPEC 15 step 17): version 1.1.1 in the header, the constant
 * and the readme (the CI version-consistency job's extraction), the changelog,
 * the catalogue headers, and the zip that tools/build-release.sh makes from
 * this tree: one magicauth/ folder with the allowlist only, the vendored
 * library with its LICENSE, no tools/, vendor/ or tests/, and a .mo compiled
 * for every .po.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use PHPUnit\Framework\TestCase;

final class ReleaseTest extends TestCase {

	private const VERSION = '1.1.1';

	/** The passkeys release: its changelog entry stays complete under the newer ones. */
	private const PASSKEYS_VERSION = '1.1.0';

	private const ROOT = __DIR__ . '/../../..';

	private const ALLOWLIST = [ 'LICENSE', 'assets', 'includes', 'languages', 'magicauth.php', 'readme.txt', 'templates', 'uninstall.php' ];

	/** Output of the msgfmt stand-in, so the test can tell a compiled .mo from a copied one. */
	private const STUB_MO = 'compiled by the test msgfmt';

	/** @var string */
	private $tmp = '';

	protected function setUp(): void {
		$base = realpath( sys_get_temp_dir() );
		$this->assertIsString( $base );
		$this->tmp = $base . '/magicauth release ' . bin2hex( random_bytes( 6 ) );
		$this->assertTrue( mkdir( $this->tmp, 0700 ) );
	}

	protected function tearDown(): void {
		if ( '' !== $this->tmp ) {
			self::remove( $this->tmp );
		}
	}

	/** The three strings the CI `version-consistency` job compares, extracted as it does. */
	public function test_header_constant_and_stable_tag_are_the_release_version(): void {
		$main   = self::read( 'magicauth.php' );
		$readme = self::read( 'readme.txt' );

		$this->assertSame( 1, preg_match( '/^\s*\*\s*Version:\s*(\S+)/m', $main, $header ) );
		$this->assertSame( 1, preg_match( "/define\(\s*'MAGICAUTH_VERSION',\s*'([^']+)'/", $main, $constant ) );
		$this->assertSame( 1, preg_match( '/^Stable tag:\s*(\S+)/m', $readme, $stable ) );

		$this->assertSame( self::VERSION, $header[1] );
		$this->assertSame( self::VERSION, $constant[1] );
		$this->assertSame( self::VERSION, $stable[1] );
		$this->assertSame( 1, preg_match_all( '/^\s*\*\s*Version:/m', $main ), 'one Version header' );
		$this->assertSame( 1, preg_match_all( "/define\(\s*'MAGICAUTH_VERSION'/", $main ), 'one constant' );
	}

	/** The changelog leads with the release, newest first, and the readme header still parses. */
	public function test_changelog_leads_with_the_release(): void {
		$readme = self::read( 'readme.txt' );
		$this->assertSame( 1, preg_match( '/^== Changelog ==\n(.*?)(?=^== |\z)/ms', $readme, $section ) );
		$this->assertGreaterThan( 0, (int) preg_match_all( '/^= ([0-9.]+) =$/m', $section[1], $versions ) );

		$this->assertSame( self::VERSION, $versions[1][0] );
		$sorted = $versions[1];
		usort( $sorted, static fn( string $a, string $b ): int => version_compare( $b, $a ) );
		$this->assertSame( $sorted, $versions[1], 'newest first' );
		$this->assertSame( count( $versions[1] ), count( array_unique( $versions[1] ) ) );

		$this->assertSame( 1, preg_match( '/^= ' . preg_quote( self::VERSION, '/' ) . ' =\n((?:\* .+\n)+)/m', $section[1], $entry ) );
		$this->assertGreaterThanOrEqual( 1, preg_match_all( '/^\* /m', $entry[1] ) );
		$this->assertSame( 1, preg_match( '/^= ' . preg_quote( self::PASSKEYS_VERSION, '/' ) . ' =\n((?:\* .+\n)+)/m', $section[1], $passkeys ) );
		$this->assertGreaterThanOrEqual( 10, preg_match_all( '/^\* /m', $passkeys[1] ), 'the passkeys release keeps its entry' );

		$this->assertSame( 1, preg_match( '/^Tested up to:\s*(\d+\.\d+)$/m', $readme, $tested ) );
		$this->assertSame( 1, preg_match( '/^Requires at least:\s*(\d+\.\d+)$/m', $readme, $requires ) );
		$this->assertTrue( version_compare( $tested[1], $requires[1], '>=' ) );
	}

	/**
	 * K6: an Upgrade Notice for the release follows the changelog, within the
	 * 300 characters WordPress.org shows, and names the first-request database
	 * upgrade and the B2/B3 behaviour changes.
	 */
	public function test_upgrade_notice_names_the_release(): void {
		$readme = self::read( 'readme.txt' );
		$this->assertSame( 1, preg_match_all( '/^== Upgrade Notice ==$/m', $readme ) );
		$this->assertGreaterThan( (int) strpos( $readme, '== Changelog ==' ), (int) strpos( $readme, '== Upgrade Notice ==' ), 'after the changelog' );
		$this->assertSame( 1, preg_match( '/^== Upgrade Notice ==\n(.*?)(?=^== |\z)/ms', $readme, $section ) );
		$this->assertSame( 1, preg_match( '/^= ([0-9.]+) =\n(.+)\n/m', $section[1], $entry ) );

		$this->assertSame( self::VERSION, $entry[1], 'leads with the release' );
		$notice = $entry[2];
		$this->assertLessThanOrEqual( 300, strlen( $notice ) );
		$this->assertStringContainsString( 'off by default', $notice );
		$this->assertStringContainsString( 'database upgrades itself on the first request', $notice );
		$this->assertStringContainsString( 'signed in as another account is now refused', $notice, 'B2' );
		$this->assertStringContainsString( 'links and codes already sent', $notice, 'B3' );
	}

	/** The .pot, each .po and each .l10n.php name the release in Project-Id-Version. */
	public function test_catalogues_name_the_release(): void {
		$files = array_merge(
			[ 'languages/magicauth.pot' ],
			array_map( static fn( string $f ): string => 'languages/' . basename( $f ), (array) glob( self::ROOT . '/languages/*.po' ) )
		);
		$this->assertCount( 4, $files );
		foreach ( $files as $file ) {
			$this->assertStringContainsString( '"Project-Id-Version: MagicAuth ' . self::VERSION . '\n"', self::read( $file ), $file );
		}

		$l10n = (array) glob( self::ROOT . '/languages/*.l10n.php' );
		$this->assertCount( 3, $l10n );
		foreach ( $l10n as $file ) {
			$data = require (string) $file;
			$this->assertIsArray( $data );
			$this->assertSame( 'MagicAuth ' . self::VERSION, $data['project-id-version'] ?? null, (string) $file );
		}
	}

	/** SPEC 15 row 17: the zip from tools/build-release.sh, built from this tree. */
	public function test_release_zip_contents(): void {
		$stub = $this->tmp . '/msgfmt';
		file_put_contents(
			$stub,
			"#!/bin/sh\n# msgfmt stand-in: -c -o <mo> <po>\nwhile [ \$# -gt 0 ]; do case \"\$1\" in -o) out=\"\$2\"; shift 2;; *) shift;; esac; done\nprintf '%s' '" . self::STUB_MO . "' > \"\$out\"\n"
		);
		chmod( $stub, 0700 );

		[ $code, $stdout, $stderr ] = self::shell(
			'MSGFMT=' . escapeshellarg( $stub ) . ' bash ' . escapeshellarg( self::ROOT . '/tools/build-release.sh' )
			. ' --out ' . escapeshellarg( $this->tmp . '/out' ) . ' --zip'
		);
		$this->assertSame( 0, $code, $stdout . $stderr );
		$this->assertStringContainsString( '(MagicAuth ' . self::VERSION . ',', $stdout );

		$zip = $this->tmp . '/out/magicauth-' . self::VERSION . '.zip';
		$this->assertFileExists( $zip );
		[ $code, $list, $stderr ] = self::shell( 'unzip -Z1 ' . escapeshellarg( $zip ) );
		$this->assertSame( 0, $code, $stderr );
		$entries = array_values( array_filter( explode( "\n", $list ), static fn( string $e ): bool => '' !== $e ) );
		$files   = array_values( array_filter( $entries, static fn( string $e ): bool => '/' !== substr( $e, -1 ) ) );

		// One top-level folder holding exactly the allowlist.
		$top = [];
		foreach ( $entries as $entry ) {
			$parts = explode( '/', $entry );
			$this->assertSame( 'magicauth', $parts[0], $entry );
			if ( isset( $parts[1] ) && '' !== $parts[1] ) {
				$top[ $parts[1] ] = true;
			}
		}
		$top = array_keys( $top );
		sort( $top );
		$this->assertSame( self::ALLOWLIST, $top );

		// No dev directory or dev file at any depth.
		foreach ( $entries as $entry ) {
			foreach ( explode( '/', rtrim( $entry, '/' ) ) as $segment ) {
				$this->assertNotContains( strtolower( $segment ), [ 'vendor', 'tests', 'tools', 'node_modules', '.git', '.github', '_dev', 'build' ], $entry );
				$this->assertStringStartsNotWith( '.', $segment, $entry );
			}
			$this->assertDoesNotMatchRegularExpression( '/\.(sh|dist|neon|lock|patch|orig|rej|mjs)$|composer\.json$|package(-lock)?\.json$|CLAUDE\.md$|README\.md$/i', $entry );
		}

		// The vendored library ships whole, with its licence and notices.
		foreach ( [ 'LICENSE', 'NOTICE.md', 'VENDORED.md', 'WebAuthn.php', 'WebAuthnException.php', 'CBOR/CborDecoder.php', 'Binary/ByteBuffer.php', 'Attestation/AttestationObject.php', 'Attestation/AuthenticatorData.php' ] as $lib ) {
			$this->assertContains( 'magicauth/includes/ThirdParty/Passkeys/' . $lib, $files );
		}

		// Every tracked plugin file is in the zip, and the zip holds nothing else but compiled .mo files.
		[ $code, $tracked, $stderr ] = self::shell( 'git -C ' . escapeshellarg( self::ROOT ) . ' ls-files -co --exclude-standard -- ' . implode( ' ', array_map( 'escapeshellarg', self::ALLOWLIST ) ) );
		$this->assertSame( 0, $code, $stderr );
		// The script drops the same debris (.gitkeep, .DS_Store, ._*, *.orig, *.rej).
		$shipped  = array_filter(
			explode( "\n", $tracked ),
			static fn( string $f ): bool => '' !== $f && 1 !== preg_match( '#(^|/)(\.gitkeep|\.DS_Store|\._[^/]*|[^/]*\.orig|[^/]*\.rej)$#', $f )
		);
		$expected = array_map( static fn( string $f ): string => 'magicauth/' . $f, array_values( $shipped ) );
		$pos      = (array) glob( self::ROOT . '/languages/*.po' );
		$this->assertCount( 3, $pos );
		foreach ( $pos as $po ) {
			$expected[] = 'magicauth/languages/' . basename( (string) $po, '.po' ) . '.mo';
		}
		$expected = array_values( array_unique( $expected ) );
		sort( $expected );
		$actual = $files;
		sort( $actual );
		$this->assertSame( $expected, $actual );

		// The .mo files were compiled at build time, not copied from the working tree.
		foreach ( $pos as $po ) {
			[ $code, $mo ] = self::shell( 'unzip -p ' . escapeshellarg( $zip ) . ' ' . escapeshellarg( 'magicauth/languages/' . basename( (string) $po, '.po' ) . '.mo' ) );
			$this->assertSame( 0, $code );
			$this->assertSame( self::STUB_MO, $mo );
		}

		// Shipped files are the repo's bytes.
		foreach ( [ 'magicauth.php', 'readme.txt', 'includes/ThirdParty/Passkeys/LICENSE', 'languages/magicauth-nl_NL.l10n.php' ] as $file ) {
			[ $code, $bytes ] = self::shell( 'unzip -p ' . escapeshellarg( $zip ) . ' ' . escapeshellarg( 'magicauth/' . $file ) );
			$this->assertSame( 0, $code );
			$this->assertSame( self::read( $file ), $bytes, $file );
		}

		[ $code, , $stderr ] = self::shell( 'unzip -tq ' . escapeshellarg( $zip ) );
		$this->assertSame( 0, $code, $stderr );
	}

	private static function read( string $file ): string {
		$bytes = file_get_contents( self::ROOT . '/' . $file );
		return false === $bytes ? '' : $bytes;
	}

	/** @return array{0:int,1:string,2:string} Exit code, stdout, stderr. */
	private static function shell( string $cmd ): array {
		$pipes = [];
		$proc  = proc_open( $cmd, [ 1 => [ 'pipe', 'w' ], 2 => [ 'pipe', 'w' ] ], $pipes );
		if ( ! is_resource( $proc ) ) {
			return [ -1, '', 'proc_open failed' ];
		}
		$stdout = (string) stream_get_contents( $pipes[1] );
		$stderr = (string) stream_get_contents( $pipes[2] );
		fclose( $pipes[1] );
		fclose( $pipes[2] );
		return [ proc_close( $proc ), $stdout, $stderr ];
	}

	/** Recursive delete that unlinks symlinks instead of following them. */
	private static function remove( string $path ): void {
		if ( is_link( $path ) || is_file( $path ) ) {
			unlink( $path );
			return;
		}
		if ( ! is_dir( $path ) ) {
			return;
		}
		foreach ( array_diff( (array) scandir( $path ), [ '.', '..' ] ) as $name ) {
			self::remove( $path . '/' . $name );
		}
		rmdir( $path );
	}
}
