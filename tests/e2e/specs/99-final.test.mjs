// Suite-wide checks (SPEC 14.2): E1 across every logged-out visit of the whole run, and no PHP
// warning, notice or deprecation from the plugin in the server's debug log.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fixture } from '../lib/harness.mjs';

test( 'E1 (whole suite) credentialAdded never fired on a logged-out page', () => {
	const file = process.env.MAGICAUTH_E2E_EVENTS;
	assert.ok( file && existsSync( file ), 'event log of the run exists (run through run.mjs)' );
	const lines = readFileSync( file, 'utf8' ).split( '\n' ).filter( Boolean );
	assert.deepEqual( lines, [], `credentialAdded while logged out:\n${ lines.join( '\n' ) }` );
} );

test( 'E0 no PHP warning, notice or deprecation in debug.log', async () => {
	const { log } = await fixture.get( 'debug_log' );
	const php = log.split( '\n' ).filter( ( l ) => /PHP (Warning|Notice|Deprecated|Fatal error|Parse error)/.test( l ) );
	assert.deepEqual( php, [], php.join( '\n' ) );
} );
