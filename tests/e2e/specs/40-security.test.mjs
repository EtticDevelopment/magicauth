// Logged-out rule, CSRF, misconfiguration, no-JS (SPEC 2.6, 6.1, 6.13, 4.5, 8.10, 8.13): E1, E1b, E19, E20, E23a, E23b, E25.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { join } from 'node:path';
import {
	BASE, AJAX, client, newUser, fixture, go, signInByLink, signInByPassword, signInByCode, signOut, loggedIn, ajaxResponse,
	waitText, text, addPasskey, stopOnExit, sleep, isAction, until, config, onNextAction, cookie, PAGESHOW, pageshows,
	addedWhileLoggedOut, getBrowser,
} from '../lib/harness.mjs';
import { startServer } from '../lib/server.mjs';

stopOnExit( after );

// Logged-out pages of the fixture site, plus core's login screens.
const LOGGED_OUT = [ '/', '/login/', '/wall/', '/deep/link/', '/account/', '/account-tpl/', '/terms/', '/wp-login.php', '/wp-login.php?action=magicauth', '/wp-login.php?action=lostpassword', '/login/?magicauth_step=password', '/no-such-page/' ];
// English creation copy (P1, P1b, P2, P4, P8, M2 to M4, M24, E4); none of it may reach a logged-out page.
const CREATION = /create a passkey|add a passkey|passkey created|passkey added|sign in faster next time|create one|lets you sign in with your fingerprint/i;

test( 'E1 logged-out rule: no creation copy, registration endpoints answer 0/400, no credentialAdded', async () => {
	const c = await client();
	try {
		for ( const path of LOGGED_OUT ) {
			await go( c.page, path );
			await sleep( 300 );
			const body = await c.page.evaluate( () => document.documentElement.outerHTML );
			assert.ok( ! CREATION.test( body ), `no creation copy on ${ path }` );
			const cfg = await config( c.page );
			if ( cfg ) {
				assert.deepEqual( Object.keys( cfg ).sort(), [ 'actions', 'ajaxUrl', 'homeUrl', 'i18n', 'rpId' ], `login config only on ${ path }` );
				assert.deepEqual( Object.values( cfg.actions ).sort(), [ 'magicauth_passkey_complete', 'magicauth_passkey_signin', 'magicauth_passkey_signin_options' ] );
			}
		}
		assert.equal( c.auth.events.added.length, 0 );
	} finally {
		await c.close();
	}
	// Creation endpoints are wp_ajax_ only: admin-ajax answers 0 with 400 for a logged-out caller.
	for ( const action of [ 'magicauth_passkey_register_options', 'magicauth_passkey_register', 'magicauth_passkey_reauth_email', 'magicauth_passkey_prompt' ] ) {
		const res = await fetch( AJAX, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: BASE }, body: new URLSearchParams( { action } ) } );
		assert.equal( res.status, 400, action );
		assert.equal( ( await res.text() ).trim(), '0', action );
	}
	assert.deepEqual( addedWhileLoggedOut(), [], 'credentialAdded never fired on a logged-out page in this file' );
} );

test( 'E1b back/forward after sign-out never offers creation; a stale click shows X1', async () => {
	// Management page: sign out, Back: no creation control, the page is reloaded or restored and reloaded.
	const user = await newUser( 'e1b' );
	const c = await client( { bfcache: true, init: [ PAGESHOW ] } );
	try {
		await signInByLink( c.page, user, { redirectTo: '/account/' } );
		await c.page.locator( '[data-magicauth-pk-add]' ).waitFor( { state: 'visible' } );
		await signOut( c.page );
		await c.page.goBack( { waitUntil: 'commit' } );
		await c.page.waitForLoadState( 'load' );
		await sleep( 1000 );
		assert.equal( await c.page.locator( '[data-magicauth-pk-add]:visible, [data-magicauth-pk-create]:visible' ).count(), 0, 'no creation control after Back' );
		console.log( `  E1b pageshow: ${ JSON.stringify( ( await pageshows( c.page ) ).slice( -2 ) ) }; not restored because: ${ JSON.stringify( c.bfcache ) }` );
	} finally {
		await c.close();
	}

	// A page still open after sign-out elsewhere: Add posts, admin-ajax answers 0, X1 shows; nothing is created.
	const u2 = await newUser( 'e1b-stale' );
	const d = await client();
	try {
		await signInByLink( d.page, u2, { redirectTo: '/account/' } );
		const other = await d.tab();
		await signOut( other.page );
		await d.page.bringToFront(); // A background tab gets no animation frames (clicks wait for them).
		const r = await ajaxResponse( d.page, 'magicauth_passkey_register_options', () => d.page.click( '[data-magicauth-pk-add]' ) );
		assert.equal( r.status, 400 );
		const cfg = await config( d.page );
		assert.equal( await waitText( d.page, '[data-magicauth-pk-manage] [data-magicauth-pk-alert]' ), cfg.i18n.X1 );
		assert.ok( ! CREATION.test( cfg.i18n.X1 ) );
		assert.equal( d.auth.events.added.length, 0 );
	} finally {
		await d.close();
	}

	// The same with the prompt open.
	const u3 = await newUser( 'e1b-prompt' );
	const e = await client();
	try {
		await signInByLink( e.page, u3 );
		await e.page.waitForSelector( '[data-magicauth-pk-prompt][open]' );
		const other = await e.tab();
		await signOut( other.page );
		await e.page.bringToFront();
		await e.page.click( '[data-magicauth-pk-view="offer"] [data-magicauth-pk-create]' );
		const cfg = await config( e.page );
		await e.page.waitForSelector( '[data-magicauth-pk-view="error"]:not([hidden])' );
		assert.equal( ( await text( e.page, '[data-magicauth-pk-error-text]' ) ).trim(), cfg.i18n.X1 );
		assert.equal( e.auth.events.added.length, 0 );
		// Navigate away and Back: the signed-out page has no prompt.
		await go( e.page, '/terms/' );
		await e.page.goBack( { waitUntil: 'commit' } );
		await e.page.waitForLoadState( 'load' );
		await sleep( 1000 );
		assert.equal( await e.page.locator( '[data-magicauth-pk-prompt][open]' ).count(), 0 );
		assert.equal( await e.page.locator( '[data-magicauth-pk-create]:visible' ).count(), 0 );
	} finally {
		await e.close();
	}
	assert.deepEqual( addedWhileLoggedOut(), [] );
} );

test( 'E19 RP misconfiguration: an IP site refuses to enable (S8a); a foreign rpId gives L7 and hides the button', async () => {
	// A second Playground served at an IP address (blocked by S8a, first in the 4.5 precedence).
	const port = 9402;
	const ip = await startServer( { port, host: '127.0.0.1', php: process.env.MAGICAUTH_E2E_PHP || '8.3', wp: process.env.MAGICAUTH_E2E_WP || '7.1', plugin: process.env.MAGICAUTH_E2E_TREE, logDir: process.env.MAGICAUTH_E2E_LOGS } );
	try {
		assert.equal( ip.env.enabled, false );
		assert.equal( ip.env.available, 'the site address is an IP address.' );
		const b = await getBrowser();
		const ctx = await b.newContext();
		try {
			const page = await ctx.newPage();
			await page.goto( `${ ip.url }/wp-login.php?magicauth=off`, { waitUntil: 'load' } );
			await page.fill( '#user_login', 'admin' );
			await page.fill( '#user_pass', 'password' );
			await Promise.all( [ page.waitForNavigation( { waitUntil: 'load' } ), page.click( '#wp-submit' ) ] );
			await page.goto( `${ ip.url }/wp-admin/options-general.php?page=magicauth`, { waitUntil: 'load' } );
			await page.check( 'input[type="checkbox"][name="magicauth_settings[passkeys_enabled]"]', { force: true } );
			const form = page.locator( 'form[action="options.php"]' ).first();
			await Promise.all( [ page.waitForNavigation( { waitUntil: 'load' } ), form.evaluate( ( f ) => f.requestSubmit() ) ] );
			const notices = await page.locator( '.magicauth-notice, .notice, .settings-error' ).allTextContents();
			const all = notices.join( ' | ' );
			assert.match( all, /Passkeys cannot be turned on: the site address is an IP address\./, all );
			assert.ok( ! /not served over HTTPS/.test( all ), 'S8d not shown' );
			const env = await ( await fetch( `${ ip.url }/wp-admin/admin-ajax.php`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams( { action: 'magicauth_e2e_get', data: JSON.stringify( { op: 'env' } ) } ) } ) ).json();
			assert.equal( env.data.settings.passkeys_enabled, false, 'stored off' );
		} finally {
			await ctx.close();
		}
	} finally {
		ip.stop();
	}

	// A valid site whose options name another RP ID: get() throws SecurityError.
	const c = await client();
	try {
		await fixture.flags( { rp_override: true } );
		await go( c.page, '/login/' );
		const l = ( await config( c.page ) ).i18n;
		await sleep( 1500 );
		assert.equal( ( await text( c.page, '[data-magicauth-passkey-error]' ) ).trim(), '', 'conditional SecurityError: autofill stops silently' );
		await c.page.click( '[data-magicauth-passkey-signin]' );
		assert.equal( await waitText( c.page, '[data-magicauth-passkey-error]' ), l.L7 );
		assert.equal( await c.page.locator( '[data-magicauth-passkey-signin]' ).isHidden(), true, 'button hidden' );
	} finally {
		await fixture.flags( {} );
		await c.close();
	}
} );

test( 'E20 no JavaScript: no passkey button even against theme CSS; the email flow completes', async () => {
	const user = await newUser( 'e20' );
	await fixture.flags( { theme_css: true } );
	const c = await client( { js: false } );
	try {
		await go( c.page, '/login/' );
		assert.ok( await c.page.locator( '#magicauth-e2e-theme' ).count(), 'theme stylesheet present' );
		const display = await c.page.locator( '[data-magicauth-passkey-signin]' ).evaluate( ( el ) => getComputedStyle( el ).display );
		assert.equal( display, 'none', 'state rule beats the theme display:flex' );
		const rootDisplay = await c.page.locator( '[data-magicauth-passkey-root]' ).evaluate( ( el ) => getComputedStyle( el ).display );
		assert.equal( rootDisplay, 'none' );
		assert.equal( await c.page.locator( '.magicauth-form button[type="submit"]' ).isDisabled(), false, 'B5: the submit button is enabled without JS' );
		await signInByCode( c.page, user, '/login/', { js: false } );
		assert.ok( await loggedIn( c.context ) );
	} finally {
		await fixture.flags( {} );
		await c.close();
	}
} );

/** A cross-site page on 127.0.0.1:9401 (a site apart from localhost) that auto-posts a form. */
function attackerServer() {
	let html = '<!doctype html><title>attacker</title>';
	const server = createServer( ( req, res ) => {
		res.writeHead( 200, { 'Content-Type': 'text/html; charset=utf-8' } );
		res.end( html );
	} );
	return new Promise( ( resolve ) => {
		server.listen( 9401, '127.0.0.1', () => resolve( {
			url: 'http://127.0.0.1:9401/',
			set( fields ) {
				const inputs = Object.entries( fields ).map( ( [ k, v ] ) => `<input type="hidden" name="${ k }" value="${ String( v ).replace( /&/g, '&amp;' ).replace( /"/g, '&quot;' ) }">` ).join( '' );
				html = `<!doctype html><title>attacker</title><form id="f" method="post" action="${ AJAX }">${ inputs }</form><script>document.getElementById('f').submit();</script>`;
			},
			close: () => new Promise( ( r ) => server.close( r ) ),
		} ) );
	} );
}

/**
 * Page script on a page of the site without the login script (no pending autofill request):
 * fresh sign-in options (sets this browser's binding cookie), then a modal get().
 */
async function obtainAssertion( page ) {
	return page.evaluate( async () => {
		const body = new URLSearchParams( { action: 'magicauth_passkey_signin_options' } );
		const res = await fetch( '/wp-admin/admin-ajax.php', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body } );
		const opts = ( await res.json() ).data;
		const cred = await navigator.credentials.get( { publicKey: PublicKeyCredential.parseRequestOptionsFromJSON( opts.publicKey ) } );
		return JSON.stringify( cred.toJSON() );
	} );
}

async function postVerify( page, credential ) {
	return page.evaluate( async ( cred ) => {
		const body = new URLSearchParams( { action: 'magicauth_passkey_signin', credential: cred, redirect_to: location.href } );
		const res = await fetch( '/wp-admin/admin-ajax.php', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body } );
		return { status: res.status, body: await res.json() };
	}, credential );
}

test( 'E23a login CSRF, cross-site: verify and complete posted from another site are refused', async () => {
	const attacker = await attackerServer();
	// The attacker's own browser and authenticator, with a passkey for the attacker's account.
	const att = await client();
	const victim = await client();
	try {
		const user = await newUser( 'e23a' );
		await signInByLink( att.page, user, { redirectTo: '/account/' } );
		await addPasskey( att.page, user );
		await signOut( att.page );
		await fixture.reset();
		await go( att.page, '/terms/' );
		const assertion = await obtainAssertion( att.page );
		const second = await obtainAssertion( att.page );
		const verified = await postVerify( att.page, second ); // A completion token bound to the attacker's cookie.
		assert.equal( verified.status, 200 );
		const token = verified.body.data.complete;
		assert.ok( token );

		// The victim visited the site (has its own SameSite=Strict binding cookie), then the attacker page.
		await victim.auth.presence( false );
		await go( victim.page, '/login/' );
		await victim.page.waitForResponse( isAction( 'magicauth_passkey_signin_options' ) );
		assert.ok( await cookie( victim.context, 'magicauth_pk_bind' ) );

		attacker.set( { action: 'magicauth_passkey_signin', credential: assertion, redirect_to: `${ BASE }/terms/` } );
		const v = victim.page.waitForResponse( ( r ) => r.url() === AJAX );
		await victim.page.goto( attacker.url );
		const vr = await v;
		assert.ok( vr.status() >= 400, `cross-site verify refused (${ vr.status() })` );
		assert.equal( ( await vr.json() ).data.code, 'passkey_failed' );

		attacker.set( { action: 'magicauth_passkey_complete', token, redirect_to: `${ BASE }/terms/`, return_to: `${ BASE }/login/` } );
		const cr = victim.page.waitForResponse( ( r ) => r.url() === AJAX );
		await victim.page.goto( attacker.url );
		const comp = await cr;
		const loc = ( await comp.allHeaders() ).location || '';
		await victim.page.waitForLoadState( 'load' );
		assert.ok( ! /\/terms\//.test( loc ), `no completion redirect to the target (${ comp.status() } ${ loc })` );
		console.log( `  E23a cross-site verify: ${ vr.status() }; cross-site complete: ${ comp.status() } ${ loc }` );
		assert.equal( await loggedIn( victim.context ), false, 'victim not signed in' );
		assert.equal( ( await fixture.user( user ) ).sessions.length, 0, 'no session for the account' );
	} finally {
		await att.close();
		await victim.close();
		await attacker.close();
	}
} );

test( 'E23b login CSRF, binding only: a valid assertion without the binding cookie fails at A-3', async () => {
	const c = await client();
	try {
		const user = await newUser( 'e23b' );
		await signInByLink( c.page, user, { redirectTo: '/account/' } );
		await addPasskey( c.page, user );
		await signOut( c.page );
		await fixture.reset();
		await go( c.page, '/terms/' );
		const assertion = await obtainAssertion( c.page );
		await c.context.clearCookies( { name: 'magicauth_pk_bind' } );
		const r = await postVerify( c.page, assertion );
		assert.equal( r.status, 400 );
		assert.equal( r.body.data.code, 'passkey_failed' );
		assert.equal( r.body.data.complete, undefined );
		assert.equal( await loggedIn( c.context ), false );
		assert.equal( ( await fixture.user( user ) ).sessions.length, 0 );
	} finally {
		await c.close();
	}
} );

test( 'E25 logged-out scan: no account script, no passkeys stylesheet, no creation strings', async () => {
	const c = await client();
	const loaded = [];
	c.page.on( 'request', ( r ) => loaded.push( r.url() ) );
	try {
		for ( const path of LOGGED_OUT ) {
			loaded.length = 0;
			await go( c.page, path );
			await sleep( 300 );
			const bad = loaded.filter( ( u ) => /magicauth-passkeys-account\.js|magicauth-passkeys\.css/.test( u ) );
			assert.deepEqual( bad, [], `no account assets on ${ path }` );
			const textContent = await c.page.evaluate( () => document.body ? document.body.innerText : '' );
			assert.ok( ! CREATION.test( textContent ), `no creation text on ${ path }` );
			const html = await c.page.content();
			assert.ok( ! /data-magicauth-pk-(prompt|manage|add|create)/.test( html ), `no account markup on ${ path }` );
		}
	} finally {
		await c.close();
	}
} );
