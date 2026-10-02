// E0: the Playground under test (SPEC 14.2 setup): release tree, crypto paths, module on.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { fixture, BASE, stopOnExit } from '../lib/harness.mjs';

stopOnExit( after );

test( 'E0 release tree and PHP crypto (openssl, Ed25519 path)', async () => {
	const env = await fixture.get( 'env' );
	const php = process.env.MAGICAUTH_E2E_PHP;
	if ( php ) {
		assert.ok( env.php.startsWith( php + '.' ), `PHP ${ env.php } is ${ php }` );
	}
	// The release tree from tools/build-release.sh: no vendor/, tests/ or tools/; the library's LICENSE ships.
	assert.deepEqual( env.plugin_dirs, { vendor: false, tests: false, tools: false, thirdparty: true } );
	const shipped = await fetch( `${ BASE }/wp-content/plugins/magicauth/readme.txt`, { redirect: 'manual' } );
	assert.equal( shipped.status, 200, 'readme.txt is served' );
	for ( const path of [ 'vendor/autoload.php', 'tests/e2e/run.mjs', 'tools/build-release.sh', 'composer.json' ] ) {
		const res = await fetch( `${ BASE }/wp-content/plugins/magicauth/${ path }`, { redirect: 'manual' } );
		assert.notEqual( res.status, 200, `${ path } is not in the tree` );
	}
	// Blocker B-7: openssl for ES256/RS256 and an Ed25519 path (sodium or sodium_compat, or OpenSSL Ed25519).
	assert.equal( env.openssl, true, 'openssl_verify available' );
	assert.ok( env.sodium || env.openssl_ed25519, 'an Ed25519 path exists' );
	assert.deepEqual( env.algs, [ -7, -8, -257 ] );
	assert.equal( env.available, true );
	assert.equal( env.enabled, true );
	assert.equal( env.rp_id, 'localhost' );
	assert.equal( env.db_version, 2 );
	console.log( `  PHP ${ env.php } (sodium ext ${ env.sodium_ext }, sodium_compat or ext ${ env.sodium }, OpenSSL Ed25519 ${ env.openssl_ed25519 }), WordPress ${ env.wp }` );
} );
