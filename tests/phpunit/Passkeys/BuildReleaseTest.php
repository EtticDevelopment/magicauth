<?php
/**
 * tools/build-release.sh (SPEC 15 step 1, 4.9): the allowlisted tree, every
 * failure path, and the refusal to let `rm -rf <out>/magicauth` reach a source
 * tree. Each case runs a copy of the script inside a throwaway fake repo, so a
 * broken guard can only ever delete temp files.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use PHPUnit\Framework\TestCase;

final class BuildReleaseTest extends TestCase {

	private const SCRIPT = __DIR__ . '/../../../tools/build-release.sh';

	/** @var string */
	private $tmp = '';

	protected function setUp(): void {
		$base = realpath( sys_get_temp_dir() );
		$this->assertIsString( $base );
		$this->tmp = $base . '/magicauth build release ' . bin2hex( random_bytes( 6 ) );
		$this->assertTrue( mkdir( $this->tmp, 0700 ) );
	}

	protected function tearDown(): void {
		if ( '' !== $this->tmp ) {
			self::remove( $this->tmp );
		}
	}

	public function test_builds_the_allowlisted_tree(): void {
		$repo = $this->fake_repo( 'repo' );
		touch( $repo . '/assets/.DS_Store' );
		touch( $repo . '/includes/x.php.orig' );
		file_put_contents( $repo . '/stray.txt', 'not allowlisted' );

		[ $code, $stdout, $stderr ] = self::build( $repo, [ '--out', $this->tmp . '/out' ] );

		$this->assertSame( 0, $code, $stderr );
		$this->assertStringContainsString( 'MagicAuth 9.9.9', $stdout );
		$tree = $this->tmp . '/out/magicauth';
		$this->assertSame(
			[ 'LICENSE', 'assets', 'includes', 'languages', 'magicauth.php', 'readme.txt', 'templates', 'uninstall.php' ],
			self::entries( $tree )
		);
		$this->assertFileDoesNotExist( $tree . '/assets/.DS_Store' );
		$this->assertFileDoesNotExist( $tree . '/includes/x.php.orig' );
		$this->assertFileExists( $tree . '/includes/x.php' );
	}

	/** @return array<string,array{0:string,1:int,2:string}> Breakage, exit code, message. */
	public static function failures(): array {
		return [
			'missing allowlisted path' => [ 'rm readme.txt', 1, 'missing allowlisted path: readme.txt' ],
			'vendor directory'         => [ 'mkdir includes/Vendor', 1, 'forbidden directories' ],
			'tests directory'          => [ 'mkdir includes/tests', 1, 'forbidden directories' ],
			'node_modules directory'   => [ 'mkdir assets/node_modules', 1, 'forbidden directories' ],
			'library without LICENSE'  => [ 'mkdir -p includes/ThirdParty/Passkeys', 1, 'includes/ThirdParty/Passkeys has no LICENSE' ],
			'no Version header'        => [ 'printf "<?php\n" > magicauth.php', 1, 'no Version header' ],
			'unknown argument'         => [ 'true', 2, 'unknown argument: --bogus' ],
		];
	}

	/** @dataProvider failures */
	public function test_failure_paths( string $breakage, int $expected, string $message ): void {
		$repo = $this->fake_repo( 'repo' );
		[ $code, , $stderr ] = self::shell( 'cd ' . escapeshellarg( $repo ) . ' && ' . $breakage );
		$this->assertSame( 0, $code, $stderr );

		$args = [ '--out', $this->tmp . '/out' ];
		if ( 'true' === $breakage ) {
			$args[] = '--bogus';
		}
		[ $code, , $stderr ] = self::build( $repo, $args );

		$this->assertSame( $expected, $code );
		$this->assertStringContainsString( 'build-release: ' . $message, $stderr );
		$this->assertFileExists( $repo . '/tools/build-release.sh' );
	}

	/** --zip compiles a .mo for every .po into the tree (WordPress before 6.5 reads only .mo); a stale copy never ships. */
	public function test_zip_compiles_a_mo_per_po(): void {
		$repo = $this->fake_repo( 'repo' );
		file_put_contents( $repo . '/languages/magicauth-nl_NL.po', "msgid \"\"\nmsgstr \"\"\n" );
		file_put_contents( $repo . '/languages/magicauth-nl_NL.mo', 'stale' );
		file_put_contents( $repo . '/languages/magicauth-de_DE.po', "msgid \"\"\nmsgstr \"\"\n" );
		$stub = $this->msgfmt_stub( 0 );

		[ $code, $stdout, $stderr ] = self::build( $repo, [ '--out', $this->tmp . '/out', '--zip' ], [ 'MSGFMT' => $stub ] );

		$this->assertSame( 0, $code, $stderr );
		$tree = $this->tmp . '/out/magicauth/languages';
		$this->assertSame( 'mo:' . $tree . '/magicauth-nl_NL.po', file_get_contents( $tree . '/magicauth-nl_NL.mo' ) );
		$this->assertSame( 'mo:' . $tree . '/magicauth-de_DE.po', file_get_contents( $tree . '/magicauth-de_DE.mo' ) );
		$calls = (string) file_get_contents( $this->tmp . '/msgfmt.log' );
		$this->assertSame(
			"-c -o {$tree}/magicauth-de_DE.mo {$tree}/magicauth-de_DE.po\n-c -o {$tree}/magicauth-nl_NL.mo {$tree}/magicauth-nl_NL.po\n",
			$calls
		);
		$this->assertSame( 'stale', file_get_contents( $repo . '/languages/magicauth-nl_NL.mo' ), 'the source tree is not touched' );
		$this->assertStringContainsString( 'magicauth-9.9.9.zip', $stdout );
		$this->assertFileExists( $this->tmp . '/out/magicauth-9.9.9.zip' );
	}

	/** Without --zip (the E2E tree) nothing is compiled and the tree is the working tree's copy. */
	public function test_tree_without_zip_compiles_nothing(): void {
		$repo = $this->fake_repo( 'repo' );
		file_put_contents( $repo . '/languages/magicauth-nl_NL.po', "msgid \"\"\nmsgstr \"\"\n" );
		file_put_contents( $repo . '/languages/magicauth-nl_NL.mo', 'local' );
		$stub = $this->msgfmt_stub( 0 );

		[ $code, , $stderr ] = self::build( $repo, [ '--out', $this->tmp . '/out' ], [ 'MSGFMT' => $stub ] );

		$this->assertSame( 0, $code, $stderr );
		$this->assertSame( 'local', file_get_contents( $this->tmp . '/out/magicauth/languages/magicauth-nl_NL.mo' ) );
		$this->assertFileDoesNotExist( $this->tmp . '/msgfmt.log' );
	}

	/** @return array<string,array{0:string,1:string}> MSGFMT kind, expected message. */
	public static function msgfmt_failures(): array {
		return [
			'msgfmt missing' => [ 'missing', 'msgfmt not found' ],
			'msgfmt fails'   => [ 'fails', 'msgfmt failed for languages/magicauth-nl_NL.po' ],
		];
	}

	/** @dataProvider msgfmt_failures */
	public function test_zip_fails_without_a_working_msgfmt( string $kind, string $message ): void {
		$repo = $this->fake_repo( 'repo' );
		file_put_contents( $repo . '/languages/magicauth-nl_NL.po', "msgid \"\"\nmsgstr \"\"\n" );
		$msgfmt = 'missing' === $kind ? $this->tmp . '/no-such-msgfmt' : $this->msgfmt_stub( 1 );

		[ $code, , $stderr ] = self::build( $repo, [ '--out', $this->tmp . '/out', '--zip' ], [ 'MSGFMT' => $msgfmt ] );

		$this->assertSame( 1, $code );
		$this->assertStringContainsString( 'build-release: ' . $message, $stderr );
		$this->assertFileDoesNotExist( $this->tmp . '/out/magicauth-9.9.9.zip' );
	}

	/** A tree without .po files needs no msgfmt. */
	public function test_zip_without_po_needs_no_msgfmt(): void {
		$repo = $this->fake_repo( 'repo' );

		[ $code, , $stderr ] = self::build( $repo, [ '--out', $this->tmp . '/out', '--zip' ], [ 'MSGFMT' => $this->tmp . '/no-such-msgfmt' ] );

		$this->assertSame( 0, $code, $stderr );
		$this->assertFileExists( $this->tmp . '/out/magicauth-9.9.9.zip' );
	}

	public function test_refuses_the_repo_root_as_out(): void {
		$repo = $this->fake_repo( 'repo' );
		$this->assert_refused( $repo, [ '--out', $repo ], [ $repo ] );
	}

	public function test_refuses_the_src_root_as_out(): void {
		$repo = $this->fake_repo( 'repo' );
		$src  = $this->fake_repo( 'src' );
		$this->assert_refused( $repo, [ '--src', $src, '--out', $src ], [ $repo, $src ] );
	}

	/** The verifier's case: --out .. from a repo whose folder is named magicauth. */
	public function test_refuses_when_dest_is_the_repo(): void {
		$repo = $this->fake_repo( 'magicauth' );
		$this->assert_refused( $repo, [ '--out', $repo . '/..' ], [ $repo ] );
	}

	public function test_refuses_when_dest_contains_the_repo(): void {
		$repo = $this->fake_repo( 'magicauth/checkouts/MagicAuth' );
		$this->assert_refused( $repo, [ '--out', $this->tmp ], [ $repo ] );
	}

	/** The step 16 recipe gone wrong: a 1.0.5 worktree at <dir>/magicauth built with --out <dir>. */
	public function test_refuses_when_dest_is_the_src_worktree(): void {
		$repo = $this->fake_repo( 'repo' );
		$src  = $this->fake_repo( 'wt/magicauth' );
		$this->assert_refused( $repo, [ '--src', $src, '--out', $this->tmp . '/wt' ], [ $repo, $src ] );
	}

	public function test_refuses_through_a_symlinked_out(): void {
		$repo = $this->fake_repo( 'real/magicauth' );
		$this->assertTrue( symlink( $this->tmp . '/real', $this->tmp . '/alias' ) );
		$this->assert_refused( $repo, [ '--out', $this->tmp . '/alias' ], [ $repo ] );
	}

	/** On a case-insensitive file system (macOS default) <out>/magicauth is <out>/MagicAuth. */
	public function test_case_insensitive_dest_is_refused_where_it_aliases(): void {
		$repo        = $this->fake_repo( 'MagicAuth' );
		$insensitive = is_dir( $this->tmp . '/magicauth' );

		[ $code, , $stderr ] = self::build( $repo, [ '--out', $this->tmp ] );

		if ( $insensitive ) {
			$this->assertSame( 1, $code );
			$this->assertStringContainsString( 'refusing', $stderr );
		} else {
			$this->assertSame( 0, $code, $stderr );
		}
		$this->assertFileExists( $repo . '/tools/build-release.sh' );
		$this->assertFileExists( $repo . '/magicauth.php' );
	}

	/**
	 * @param array<int,string> $args
	 * @param array<int,string> $trees Trees that must survive untouched.
	 */
	private function assert_refused( string $repo, array $args, array $trees ): void {
		$before = [];
		foreach ( $trees as $tree ) {
			$before[ $tree ] = self::entries( $tree );
		}

		[ $code, $stdout, $stderr ] = self::build( $repo, $args );

		$this->assertSame( 1, $code, $stdout . $stderr );
		$this->assertStringContainsString( 'build-release: refusing', $stderr );
		foreach ( $trees as $tree ) {
			$this->assertSame( $before[ $tree ], self::entries( $tree ), $tree );
			$this->assertFileExists( $tree . '/magicauth.php' );
		}
	}

	/** A minimal plugin tree with a copy of the script under tools/. */
	private function fake_repo( string $rel ): string {
		$dir = $this->tmp . '/' . $rel;
		foreach ( [ 'assets', 'includes', 'languages', 'templates', 'tools' ] as $sub ) {
			$this->assertTrue( mkdir( $dir . '/' . $sub, 0700, true ) );
		}
		file_put_contents( $dir . '/LICENSE', "GPL\n" );
		file_put_contents( $dir . '/readme.txt', "=== MagicAuth ===\n" );
		file_put_contents( $dir . '/uninstall.php', "<?php\n" );
		file_put_contents( $dir . '/magicauth.php', "<?php\n/**\n * Plugin Name: MagicAuth\n * Version: 9.9.9\n */\n" );
		file_put_contents( $dir . '/includes/x.php', "<?php\n" );
		$this->assertTrue( copy( self::SCRIPT, $dir . '/tools/build-release.sh' ) );
		return $dir;
	}

	/** A msgfmt stand-in that logs its arguments and writes "mo:<po>" to the -o file, or exits $exit. */
	private function msgfmt_stub( int $exit ): string {
		$stub = $this->tmp . '/msgfmt-stub';
		$log  = escapeshellarg( $this->tmp . '/msgfmt.log' );
		file_put_contents(
			$stub,
			"#!/bin/sh\necho \"\$*\" >> {$log}\n" . ( 0 !== $exit ? "exit {$exit}\n" : '' )
			. "while [ \$# -gt 0 ]; do case \"\$1\" in -o) out=\"\$2\"; shift 2;; *) po=\"\$1\"; shift;; esac; done\nprintf 'mo:%s' \"\$po\" > \"\$out\"\n"
		);
		chmod( $stub, 0700 );
		return $stub;
	}

	/**
	 * @param array<int,string>    $args
	 * @param array<string,string> $env
	 * @return array{0:int,1:string,2:string}
	 */
	private static function build( string $repo, array $args, array $env = [] ): array {
		$cmd = '';
		foreach ( $env as $name => $value ) {
			$cmd .= $name . '=' . escapeshellarg( $value ) . ' ';
		}
		$cmd .= 'bash ' . escapeshellarg( $repo . '/tools/build-release.sh' );
		foreach ( $args as $arg ) {
			$cmd .= ' ' . escapeshellarg( $arg );
		}
		return self::shell( $cmd );
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

	/** @return array<int,string> Sorted top-level names. */
	private static function entries( string $dir ): array {
		$names = array_values( array_diff( (array) scandir( $dir ), [ '.', '..' ] ) );
		sort( $names );
		return $names;
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
