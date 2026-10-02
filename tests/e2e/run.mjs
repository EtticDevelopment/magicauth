#!/usr/bin/env node
// MagicAuth passkeys E2E suite runner (SPEC 14.2, build step 16).
//
//   cd tests/e2e && npm ci && node run.mjs [--php=8.3] [--wp=7.1] [--smoke] [--grep=<test name regex>]
//
// Builds the release tree with tools/build-release.sh, serves it from WordPress
// Playground at http://localhost:9400 (never 127.0.0.1: not a valid RP ID) with the
// E2E blueprint and mu-plugin, then runs specs/*.test.mjs with node:test against it.
// --smoke runs the PHP 8.0 smoke subset (E0, E2, E6). Chrome comes from
// MAGICAUTH_E2E_CHROME (default: the macOS install path). Outputs (release tree,
// Playground logs) go to MAGICAUTH_E2E_OUT (default: build/e2e in the repo).
// Every server started here is stopped on exit.
import { spawn } from 'node:child_process';
import { mkdirSync, readdirSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { buildTree, startServer, E2E_DIR, REPO } from './lib/server.mjs';

const args = Object.fromEntries( process.argv.slice( 2 ).map( ( a ) => {
	const [ k, v ] = a.replace( /^--/, '' ).split( '=' );
	return [ k, v === undefined ? true : v ];
} ) );
const php = String( args.php || ( args.smoke ? '8.0' : '8.3' ) );
const wp = String( args.wp || '7.1' );
const port = Number( args.port || 9400 );
const out = process.env.MAGICAUTH_E2E_OUT || join( REPO, 'build', 'e2e' );
const logDir = join( out, 'logs' );
mkdirSync( logDir, { recursive: true } );

const servers = [];
function stopAll() {
	for ( const s of servers ) {
		s.stop();
	}
	servers.length = 0;
}
process.on( 'exit', stopAll );
for ( const sig of [ 'SIGINT', 'SIGTERM' ] ) {
	process.on( sig, () => {
		stopAll();
		process.exit( 130 );
	} );
}

const tree = buildTree( REPO, join( out, 'current' ) );
console.log( `e2e: starting Playground (PHP ${ php }, WordPress ${ wp }) on http://localhost:${ port }` );
const main = await startServer( { port, php, wp, plugin: tree, logDir } );
servers.push( main );
console.log( `e2e: ready: PHP ${ main.env.php }, WordPress ${ main.env.wp }, MagicAuth ${ main.env.magicauth }` );
if ( ! main.env.php.startsWith( php + '.' ) ) {
	console.error( `e2e: Playground runs PHP ${ main.env.php }, not ${ php }` );
	process.exit( 1 );
}

const events = join( logDir, 'credential-added-logged-out.jsonl' );
writeFileSync( events, '' );

const specs = readdirSync( join( E2E_DIR, 'specs' ) ).filter( ( f ) => f.endsWith( '.test.mjs' ) ).sort().map( ( f ) => join( 'specs', f ) );
const nodeArgs = [ '--test', '--test-concurrency=1', '--test-timeout=900000', '--test-reporter=spec' ];
const grep = args.grep || ( args.smoke ? '^E(0|2|6)\\b' : '' );
if ( grep ) {
	nodeArgs.push( `--test-name-pattern=${ grep }` );
}
const env = Object.assign( {}, process.env, {
	MAGICAUTH_E2E_BASE: main.url,
	MAGICAUTH_E2E_TREE: tree,
	MAGICAUTH_E2E_OUT: out,
	MAGICAUTH_E2E_LOGS: logDir,
	MAGICAUTH_E2E_EVENTS: events,
	MAGICAUTH_E2E_PHP: php,
	MAGICAUTH_E2E_WP: wp,
	MAGICAUTH_E2E_SMOKE: args.smoke ? '1' : '',
} );
const code = await new Promise( ( resolve ) => {
	const child = spawn( process.execPath, [ ...nodeArgs, ...specs ], { cwd: E2E_DIR, env, stdio: 'inherit' } );
	child.on( 'exit', ( c ) => resolve( c === null ? 1 : c ) );
} );
stopAll();
if ( ! args.keep ) {
	rmSync( join( out, 'current' ), { recursive: true, force: true } );
}
console.log( `e2e: node --test exited with ${ code }` );
process.exit( code );
