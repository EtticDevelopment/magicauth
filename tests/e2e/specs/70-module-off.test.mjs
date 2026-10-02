// Module off (SPEC 1.2 G6, 8.11): E26, the normalised server output of this build with
// passkeys off against MagicAuth 1.0.5 on the same WordPress, PHP and blueprint.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request } from 'playwright-core';
import { BASE, fixture, stopOnExit, sleep } from '../lib/harness.mjs';
import { E2E_DIR, buildTree, startServer, worktree, removeWorktree } from '../lib/server.mjs';

stopOnExit( after );

// The 1.0.5 release (no v1.0.5 tag exists; d8c8d7d is the commit the step 1 fixtures came from).
const BASELINE = process.env.MAGICAUTH_E2E_BASELINE_REF || 'd8c8d7de18a6659f351455d77b69c51240fad6ac';
const PAGES = [ '/login/', '/login/?magicauth_step=password', '/wp-login.php?action=magicauth', '/wp-login.php?action=lostpassword', '/wall/', '/deep/link/', '/terms/' ];

/** Raw server HTML of every page, logged out, plus state B (a real request) and the signed-in notice. */
async function capture( base ) {
	const out = {};
	const api = await request.newContext( { baseURL: base } );
	try {
		for ( const path of PAGES ) {
			out[ path ] = await ( await api.get( path ) ).text();
		}
		// State B: the code step after a real email request (time-to-fill gate: 2 s).
		await reset( base );
		const a = await ( await api.get( '/login/' ) ).text();
		const field = ( name ) => ( a.match( new RegExp( `name="${ name }"[^>]*value="([^"]*)"` ) ) || a.match( new RegExp( `value="([^"]*)"[^>]*name="${ name }"` ) ) || [] )[ 1 ];
		await sleep( 2200 );
		const posted = await api.post( '/wp-admin/admin-post.php', {
			form: { action: 'magicauth_request', redirect_to: `${ base }/login/`, magicauth_nonce: field( 'magicauth_nonce' ), magicauth_website: '', magicauth_ts: field( 'magicauth_ts' ), magicauth_email: 'student-a@example.com' },
			maxRedirects: 0,
		} );
		const step = posted.headers().location || '';
		assert.match( step, /magicauth_step=code/, `${ base }: state B redirect (${ posted.status() })` );
		out[ 'state B' ] = await ( await api.get( step ) ).text();
		// Signed in (core password form): the shortcode's notice.
		await api.get( '/wp-login.php?magicauth=off' );
		await api.post( '/wp-login.php?magicauth=off', { form: { log: 'student-a', pwd: 'password', 'wp-submit': 'Log In', testcookie: '1', redirect_to: `${ base }/terms/` }, maxRedirects: 0 } );
		out[ 'signed in /login/' ] = await ( await api.get( '/login/' ) ).text();
	} finally {
		await api.dispose();
	}
	return out;
}

async function reset( base ) {
	await fetch( `${ base }/wp-admin/admin-ajax.php`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams( { action: 'magicauth_e2e_set', data: JSON.stringify( { op: 'reset' } ) } ) } );
}

/** Normalise.php, then: the site origin, and the B5 fix (Appendix D: the submit button is no longer disabled in the markup). */
function normalise( pages, origin ) {
	const raw = execFileSync( 'php', [ join( E2E_DIR, 'tools', 'normalise.php' ) ], { input: JSON.stringify( pages ), maxBuffer: 64 * 1024 * 1024 } ).toString();
	const out = {};
	const host = new URL( origin ).host;
	for ( const [ name, html ] of Object.entries( JSON.parse( raw ) ) ) {
		out[ name ] = [ host, encodeURIComponent( host ), encodeURIComponent( host ).toLowerCase() ].reduce( ( h, x ) => h.split( x ).join( '{{host}}' ), html )
			// load-styles.php?c= follows core's can_compress_scripts option, a per-site environment probe.
			.replace( /(load-(?:styles|scripts)\.php\?c=)[01]/g, '$1{{c}}' )
			.split( '\n' )
			.map( ( l ) => /^\s*<button [^>]*class="magicauth-button"[^>]*type="submit"/.test( l ) ? l.replace( ' aria-disabled="true"', '' ).replace( ' disabled="disabled"', '' ) : l );
	}
	return out;
}

function firstDiff( a, b ) {
	for ( let i = 0; i < Math.max( a.length, b.length ); i++ ) {
		if ( a[ i ] !== b[ i ] ) {
			return `line ${ i + 1 }:\n  1.0.5: ${ a[ i ] }\n  now:   ${ b[ i ] }`;
		}
	}
	return '';
}

test( 'E26 module off: server output equals 1.0.5 apart from the Appendix D fixes', async () => {
	const dir = mkdtempSync( join( tmpdir(), 'magicauth-e2e-' ) );
	const src = join( dir, 'magicauth-1.0.5-src' );
	let base = null;
	try {
		worktree( BASELINE, src );
		const tree = buildTree( src, join( dir, 'out' ) );
		base = await startServer( { port: 9403, php: process.env.MAGICAUTH_E2E_PHP || '8.3', wp: process.env.MAGICAUTH_E2E_WP || '7.1', plugin: tree, logDir: process.env.MAGICAUTH_E2E_LOGS || dir } );
		assert.equal( base.env.magicauth, '1.0.5' );
		await fixture.settings( { passkeys_enabled: false } );
		const env = await fixture.get( 'env' );
		assert.equal( env.enabled, false, 'module off on the build under test' );

		const before = normalise( await capture( base.url ), base.url );
		const now = normalise( await capture( BASE ), BASE );
		const diffs = Object.keys( before ).filter( ( name ) => firstDiff( before[ name ], now[ name ] ) !== '' ).map( ( name ) => `${ name }: ${ firstDiff( before[ name ], now[ name ] ) }` );
		assert.deepEqual( diffs, [], `differences from 1.0.5:\n${ diffs.join( '\n' ) }` );
		assert.deepEqual( Object.keys( now ).sort(), Object.keys( before ).sort() );
		// G6: no passkey asset, config or markup from the plugin with the module off (the wall's
		// own theme markup carries the contract attributes, so they count only elsewhere).
		for ( const [ name, lines ] of Object.entries( now ) ) {
			const html = lines.join( '\n' );
			assert.ok( ! /magicauth-passkeys|magicauthPasskeysConfig|data-magicauth-pk/.test( html ), `${ name }: no passkey output` );
			if ( name !== '/wall/' && name !== '/deep/link/' ) {
				assert.ok( ! /data-magicauth-passkey|webauthn/.test( html ), `${ name }: no sign-in passkey markup` );
			}
		}
		// G6: an email sign-in with the module off sets no magicauth_pk_fresh cookie.
		const api = await request.newContext( { baseURL: BASE } );
		try {
			const mails = await fixture.mails();
			const after = mails.length ? mails[ mails.length - 1 ].seq : '';
			await fixture.set( 'send_link', { user: 'student-b' } );
			let mail = null;
			for ( let i = 0; i < 40 && ! mail; i++ ) {
				mail = ( await fixture.mails( { to: 'student-b@example.com', after } ) ).find( ( m ) => /code|sign/i.test( m.subject ) ) || null;
				if ( ! mail ) {
					await sleep( 250 );
				}
			}
			assert.ok( mail, 'sign-in mail' );
			const link = mail.message.match( /href="([^"]*magicauth=verify[^"]*)"/ )[ 1 ].replace( /&#0?38;|&amp;/g, '&' );
			const res = await api.get( link, { maxRedirects: 0 } );
			const cookies = res.headersArray().filter( ( h ) => h.name.toLowerCase() === 'set-cookie' ).map( ( h ) => h.value );
			assert.ok( cookies.some( ( c ) => /^wordpress_logged_in_/.test( c ) ), 'signed in' );
			assert.ok( ! cookies.some( ( c ) => /^magicauth_pk_/.test( c ) ), `no passkey cookie: ${ cookies.map( ( c ) => c.split( '=' )[ 0 ] ).join( ', ' ) }` );
		} finally {
			await api.dispose();
		}
	} finally {
		await fixture.settings( { passkeys_enabled: true } );
		if ( base ) {
			base.stop();
		}
		removeWorktree( src );
		rmSync( dir, { recursive: true, force: true } );
	}
} );
