<?php
/**
 * Capture the golden fixtures from a plugin tree (SPEC 15 step 1).
 *
 *   php tests/phpunit/fixtures/capture-golden.php <plugin-dir> <out-dir> <source-commit>
 *
 * <plugin-dir> is a checkout of the reference version (a detached git worktree
 * of the 1.0.5 commit); its includes/ and templates/ are what render. The
 * harness (stubs, Support) comes from this tree, so the same harness renders
 * the comparison later. Runs without Composer so no autoloader can resolve
 * MagicAuth\ classes to this tree instead of <plugin-dir>.
 *
 * Writes one file per Golden::files() entry plus MANIFEST.json (source commit,
 * PHP version, sha256 per file).
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

if ( PHP_SAPI !== 'cli' || $argc < 4 ) {
	fwrite( STDERR, "usage: php capture-golden.php <plugin-dir> <out-dir> <source-commit>\n" );
	exit( 2 );
}

$magicauth_plugin = realpath( $argv[1] );
$magicauth_out    = $argv[2];
if ( false === $magicauth_plugin || ! is_file( $magicauth_plugin . '/magicauth.php' ) ) {
	fwrite( STDERR, "not a MagicAuth tree: {$argv[1]}\n" );
	exit( 2 );
}
if ( ! is_dir( $magicauth_out ) && ! mkdir( $magicauth_out, 0755, true ) ) {
	fwrite( STDERR, "cannot create {$magicauth_out}\n" );
	exit( 2 );
}

define( 'MAGICAUTH_DIR', $magicauth_plugin . '/' );
require dirname( __DIR__ ) . '/bootstrap.php';
require dirname( __DIR__ ) . '/Support/Normalise.php';
require dirname( __DIR__ ) . '/Support/Golden.php';

$magicauth_files = [];
foreach ( MagicAuth\Tests\Support\Golden::render_all() as $magicauth_name => $magicauth_content ) {
	file_put_contents( $magicauth_out . '/' . $magicauth_name, $magicauth_content );
	$magicauth_files[ $magicauth_name ] = hash( 'sha256', $magicauth_content );
}

$magicauth_manifest = [
	'source_commit' => $argv[3],
	'captured_at'   => gmdate( 'Y-m-d\TH:i:s\Z' ),
	'php'           => PHP_VERSION,
	'command'       => 'php tests/phpunit/fixtures/capture-golden.php <worktree of source_commit> tests/phpunit/fixtures/1.0.5 ' . $argv[3],
	'files'         => $magicauth_files,
];
file_put_contents(
	$magicauth_out . '/MANIFEST.json',
	json_encode( $magicauth_manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n"
);
fwrite( STDOUT, 'wrote ' . count( $magicauth_files ) . " fixtures to {$magicauth_out}\n" );
