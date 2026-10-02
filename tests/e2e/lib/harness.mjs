// Browser, virtual authenticator and site helpers for the E2E suite (SPEC 14.2).
// Chrome through playwright-core; one CDP virtual authenticator per tab
// (ctap2_1, internal, resident key, UV, isUserVerified), its events recorded.
import { chromium } from 'playwright-core';
import { appendFileSync } from 'node:fs';
import assert from 'node:assert/strict';

export const BASE = process.env.MAGICAUTH_E2E_BASE || 'http://localhost:9400';
export const CHROME = process.env.MAGICAUTH_E2E_CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
export const AJAX = `${ BASE }/wp-admin/admin-ajax.php`;
const EVENTS = process.env.MAGICAUTH_E2E_EVENTS || '';

export const sleep = ( ms ) => new Promise( ( r ) => setTimeout( r, ms ) );
export const b64u = ( s ) => String( s ).replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=+$/, '' );
export const b64 = ( s ) => {
	const t = String( s ).replace( /-/g, '+' ).replace( /_/g, '/' );
	return t + '='.repeat( ( 4 - ( t.length % 4 ) ) % 4 );
};

/* ------------------------------------------------------------------ E2E fixture API */

async function call( action, data ) {
	const res = await fetch( AJAX, {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams( { action, data: JSON.stringify( data || {} ) } ),
	} );
	const text = await res.text();
	let json;
	try {
		json = JSON.parse( text );
	} catch ( e ) {
		throw new Error( `${ action } ${ data && data.op }: not JSON (${ res.status }): ${ text.slice( 0, 300 ) }` );
	}
	if ( ! json.success ) {
		throw new Error( `${ action } ${ data && data.op }: ${ JSON.stringify( json.data ) }` );
	}
	return json.data;
}

export const fixture = {
	get: ( op, data ) => call( 'magicauth_e2e_get', Object.assign( { op }, data ) ),
	set: ( op, data ) => call( 'magicauth_e2e_set', Object.assign( { op }, data ) ),
	mails: ( data ) => call( 'magicauth_e2e_mail', data || {} ).then( ( d ) => d.mails ),
	user: ( user ) => call( 'magicauth_e2e_get', { op: 'user', user: user.login || user } ),
	flags: ( flags ) => call( 'magicauth_e2e_set', { op: 'flags', flags } ),
	settings: ( set ) => call( 'magicauth_e2e_set', { op: 'settings', set } ),
	reset: () => call( 'magicauth_e2e_set', { op: 'reset' } ),
};

let userSeq = 0;
/** A new subscriber for one test, so cadence, passkeys and throttles never leak between tests. */
export async function newUser( prefix = 'student', extra = {} ) {
	userSeq++;
	const login = `${ prefix }-${ Date.now().toString( 36 ) }${ userSeq }${ Math.floor( Math.random() * 1e4 ) }`;
	return fixture.set( 'create_user', Object.assign( { login, display_name: `${ prefix } ${ userSeq }` }, extra ) );
}

/* ------------------------------------------------------------------ mail */

export function lastSeq( mails ) {
	return mails.length ? mails[ mails.length - 1 ].seq : '';
}

export async function mailMark() {
	return lastSeq( await fixture.mails() );
}

/** Wait for a mail to `to` after `after` matching `subject` (RegExp). */
export async function waitMail( to, { after = '', subject = null, timeout = 20000 } = {} ) {
	const until = Date.now() + timeout;
	while ( Date.now() < until ) {
		const mails = await fixture.mails( { to: String( to ).toLowerCase(), after } );
		const hit = mails.find( ( m ) => ! subject || subject.test( m.subject ) );
		if ( hit ) {
			return hit;
		}
		await sleep( 300 );
	}
	throw new Error( `no mail to ${ to } (${ subject })` );
}

export async function mailsTo( to, after = '' ) {
	return fixture.mails( { to: String( to ).toLowerCase(), after } );
}

const decode = ( s ) => s.replace( /&#0?38;/g, '&' ).replace( /&amp;/g, '&' );

export function mailLink( mail ) {
	const m = mail.message.match( /href="([^"]*magicauth=verify[^"]*)"/ );
	assert.ok( m, 'sign-in link in mail' );
	return decode( m[ 1 ] );
}

export function mailText( mail ) {
	return decode( mail.message.replace( /<style[\s\S]*?<\/style>/gi, ' ' ).replace( /<[^>]+>/g, ' ' ) ).replace( /\s+/g, ' ' ).trim();
}

/** The 6-character code (shown as ABC-DEF or ABCDEF). */
export function mailCode( mail ) {
	const text = mailText( mail );
	const m = text.match( /\b([0-9A-HJKMNP-TV-Z]{3})-?([0-9A-HJKMNP-TV-Z]{3})\b/ );
	assert.ok( m, `code in mail: ${ text.slice( 0, 200 ) }` );
	return m[ 1 ] + m[ 2 ];
}

/* ------------------------------------------------------------------ browser */

const browsers = {};
/** Chrome; `bfcache` keeps the back/forward cache on (Playwright turns it off by default). */
export async function getBrowser( bfcache = false ) {
	const key = bfcache ? 'bfcache' : 'default';
	if ( ! browsers[ key ] ) {
		browsers[ key ] = await chromium.launch( {
			executablePath: CHROME,
			headless: true,
			ignoreDefaultArgs: bfcache ? [ '--disable-back-forward-cache' ] : [],
		} );
	}
	return browsers[ key ];
}

export async function closeBrowser() {
	for ( const key of Object.keys( browsers ) ) {
		await browsers[ key ].close().catch( () => {} );
		delete browsers[ key ];
	}
}

/** Records pageshow events (persisted or not) of the tab in sessionStorage. */
export const PAGESHOW = `addEventListener( 'pageshow', ( e ) => {
	try {
		const list = JSON.parse( sessionStorage.getItem( 'e2e:pageshow' ) || '[]' );
		list.push( { persisted: e.persisted, path: location.pathname } );
		sessionStorage.setItem( 'e2e:pageshow', JSON.stringify( list ) );
	} catch ( err ) {}
} );`;

export async function pageshows( page ) {
	return page.evaluate( () => JSON.parse( sessionStorage.getItem( 'e2e:pageshow' ) || '[]' ) );
}

// nojsonapi mode (14.2): the fallback serialiser used by Safari before 18.4 runs.
export const NOJSONAPI = `( () => {
	if ( window.PublicKeyCredential ) {
		delete PublicKeyCredential.parseCreationOptionsFromJSON;
		delete PublicKeyCredential.parseRequestOptionsFromJSON;
		delete PublicKeyCredential.prototype.toJSON;
	}
} )();`;

const violations = [];
export function addedWhileLoggedOut() {
	return violations.slice();
}

/** One virtual authenticator on one tab, with its CDP events. */
export class Authenticator {
	static async attach( page, opts = {} ) {
		const cdp = await page.context().newCDPSession( page );
		await cdp.send( 'WebAuthn.enable', { enableUI: false } );
		const { authenticatorId } = await cdp.send( 'WebAuthn.addVirtualAuthenticator', {
			options: Object.assign( {
				protocol: 'ctap2',
				ctap2Version: 'ctap2_1',
				transport: 'internal',
				hasResidentKey: true,
				hasUserVerification: true,
				isUserVerified: true,
				automaticPresenceSimulation: true,
			}, opts ),
		} );
		return new Authenticator( page, cdp, authenticatorId );
	}

	constructor( page, cdp, id ) {
		this.page = page;
		this.cdp = cdp;
		this.id = id;
		this.events = { added: [], asserted: [], deleted: [], updated: [] };
		cdp.on( 'WebAuthn.credentialAdded', async ( e ) => {
			const cookies = await page.context().cookies( BASE ).catch( () => [] );
			const loggedIn = cookies.some( ( c ) => c.name.startsWith( 'wordpress_logged_in_' ) );
			const rec = { id: b64u( e.credential.credentialId ), rk: e.credential.isResidentCredential, url: page.url(), loggedIn };
			this.events.added.push( rec );
			if ( ! loggedIn ) {
				violations.push( rec );
				if ( EVENTS ) {
					appendFileSync( EVENTS, JSON.stringify( rec ) + '\n' );
				}
			}
		} );
		cdp.on( 'WebAuthn.credentialAsserted', ( e ) => this.events.asserted.push( { id: b64u( e.credential.credentialId ), signCount: e.credential.signCount } ) );
		cdp.on( 'WebAuthn.credentialDeleted', ( e ) => this.events.deleted.push( { id: b64u( e.credentialId ) } ) );
		cdp.on( 'WebAuthn.credentialUpdated', ( e ) => this.events.updated.push( { id: b64u( e.credential.credentialId ), name: e.credential.userName, displayName: e.credential.userDisplayName } ) );
	}

	async credentials() {
		const { credentials } = await this.cdp.send( 'WebAuthn.getCredentials', { authenticatorId: this.id } );
		return credentials.map( ( c ) => Object.assign( {}, c, { b64uId: b64u( c.credentialId ) } ) );
	}

	presence( enabled ) {
		return this.cdp.send( 'WebAuthn.setAutomaticPresenceSimulation', { authenticatorId: this.id, enabled } );
	}

	uv( isUserVerified ) {
		return this.cdp.send( 'WebAuthn.setUserVerified', { authenticatorId: this.id, isUserVerified } );
	}

	overrides( bits ) {
		return this.cdp.send( 'WebAuthn.setResponseOverrideBits', Object.assign( { authenticatorId: this.id }, bits ) );
	}

	props( credentialId, props ) {
		return this.cdp.send( 'WebAuthn.setCredentialProperties', Object.assign( { authenticatorId: this.id, credentialId: b64( credentialId ) }, props ) );
	}

	/** Copy a credential (from getCredentials of another authenticator) into this one. */
	add( credential, overrides = {} ) {
		const c = {
			credentialId: credential.credentialId,
			isResidentCredential: credential.isResidentCredential,
			rpId: credential.rpId,
			privateKey: credential.privateKey,
			userHandle: credential.userHandle,
			signCount: credential.signCount,
		};
		if ( typeof credential.backupEligibility === 'boolean' ) {
			c.backupEligibility = credential.backupEligibility;
		}
		if ( typeof credential.backupState === 'boolean' ) {
			c.backupState = credential.backupState;
		}
		return this.cdp.send( 'WebAuthn.addCredential', { authenticatorId: this.id, credential: Object.assign( c, overrides ) } );
	}

	remove( credentialId ) {
		return this.cdp.send( 'WebAuthn.removeCredential', { authenticatorId: this.id, credentialId: b64( credentialId ) } );
	}
}

/** Console messages of a page (type and text). */
function watchConsole( page ) {
	const out = [];
	page.on( 'console', ( m ) => out.push( { type: m.type(), text: m.text() } ) );
	page.on( 'pageerror', ( e ) => out.push( { type: 'pageerror', text: String( e && e.message ) } ) );
	return out;
}

/**
 * A browser context with one tab and its own authenticator.
 * opts: mode ('native' | 'nojsonapi'), js, presence, init (scripts), locale, authenticator (options) or false.
 */
export async function client( opts = {} ) {
	const b = await getBrowser( opts.bfcache === true );
	const context = await b.newContext( {
		baseURL: BASE,
		javaScriptEnabled: opts.js !== false,
		locale: opts.locale || 'en-US',
		viewport: opts.viewport || { width: 1100, height: 900 },
	} );
	context.setDefaultTimeout( opts.timeout || 30000 );
	if ( opts.mode === 'nojsonapi' ) {
		await context.addInitScript( NOJSONAPI );
	}
	for ( const s of opts.init || [] ) {
		await context.addInitScript( s );
	}
	const c = { context, tabs: [] };
	c.tab = async ( tabOpts = {} ) => {
		const page = await context.newPage();
		const consoleLog = watchConsole( page );
		const auth = tabOpts.authenticator === false ? null : await Authenticator.attach( page, Object.assign( {}, opts.authenticator, tabOpts.authenticator ) );
		if ( auth && ( tabOpts.presence === false || ( tabOpts.presence === undefined && opts.presence === false ) ) ) {
			await auth.presence( false );
		}
		const t = { page, auth, console: consoleLog, bfcache: [] };
		if ( opts.bfcache ) {
			// Why Chrome did not restore a page from the back/forward cache (logged by the tests).
			const pageCdp = await context.newCDPSession( page );
			await pageCdp.send( 'Page.enable' );
			pageCdp.on( 'Page.backForwardCacheNotUsed', ( e ) => t.bfcache.push( ( e.notRestoredExplanations || [] ).map( ( x ) => x.reason ) ) );
		}
		c.tabs.push( t );
		return t;
	};
	const first = await c.tab();
	c.page = first.page;
	c.auth = first.auth;
	c.console = first.console;
	c.bfcache = first.bfcache;
	c.close = () => context.close().catch( () => {} );
	return c;
}

/* ------------------------------------------------------------------ site helpers */

export async function loggedIn( context ) {
	const cookies = await context.cookies( BASE );
	return cookies.some( ( c ) => c.name.startsWith( 'wordpress_logged_in_' ) );
}

/** A cookie of the site host, any path (magicauth_pk_bind and _fresh live on the admin-ajax path). */
export async function cookie( context, name ) {
	const host = new URL( BASE ).hostname;
	const cookies = await context.cookies();
	return cookies.find( ( c ) => c.name === name && c.domain.replace( /^\./, '' ) === host ) || null;
}

/** The admin-ajax action of a request ('' for anything else). */
export function actionOf( request ) {
	if ( ! request.url().startsWith( AJAX ) ) {
		return '';
	}
	try {
		return new URLSearchParams( request.postData() || '' ).get( 'action' ) || '';
	} catch ( e ) {
		return '';
	}
}

export function isAction( action ) {
	return ( r ) => actionOf( r.request() ) === action;
}

/** Wait for an admin-ajax response of `action`; returns { status, json }. */
export async function ajaxResponse( page, action, run, timeout = 30000 ) {
	const wait = page.waitForResponse( isAction( action ), { timeout } );
	if ( run ) {
		await run();
	}
	const res = await wait;
	// Chrome does not always hand a body to CDP (seen for admin-ajax's bare "0" with 400): give up after 5 s.
	const body = await Promise.race( [ res.text().catch( () => null ), sleep( 5000 ).then( () => null ) ] );
	let json = null;
	try {
		json = body === null ? null : JSON.parse( body );
	} catch ( e ) {
		json = null;
	}
	return { status: res.status(), json, body, headers: res.headers(), response: res };
}

/** Count admin-ajax requests of an action on a page from now on. */
export function countRequests( page, action ) {
	const box = { n: 0 };
	page.on( 'request', ( r ) => {
		if ( actionOf( r ) === action ) {
			box.n++;
		}
	} );
	return box;
}

export async function go( page, path ) {
	return page.goto( path.startsWith( 'http' ) ? path : BASE + path, { waitUntil: 'load' } );
}

/** Email sign-in by link: the mail the email form sends, then the click (method link). */
export async function signInByLink( page, user, { redirectTo = '', wait = true } = {} ) {
	const after = await mailMark();
	await fixture.set( 'send_link', { user: user.login, redirect_to: redirectTo ? BASE + redirectTo : '' } );
	const mail = await waitMail( user.email, { after, subject: /code|sign/i } );
	const res = await page.goto( mailLink( mail ), { waitUntil: 'load' } );
	if ( wait ) {
		assert.ok( await loggedIn( page.context() ), `signed in by link as ${ user.login }` );
	}
	return res;
}

/** Email sign-in through the real form: request, then the code from the mail (method code). */
export async function signInByCode( page, user, path = '/login/', { js = true } = {} ) {
	await fixture.reset();
	await go( page, path );
	const after = await mailMark();
	await page.fill( 'input[name="magicauth_email"]', user.email );
	await sleep( 2200 ); // Time-to-fill gate (hygiene fields).
	await Promise.all( [ page.waitForURL( /magicauth_step=code/ ), page.click( '.magicauth-form button[type="submit"]' ) ] );
	const mail = await waitMail( user.email, { after, subject: /code|sign/i } );
	await sleep( 2200 ); // The code form has the same time-to-fill gate.
	// The landing URL is the form's redirect_to, which can be this same code-step URL.
	const landed = page.waitForNavigation( { waitUntil: 'load' } );
	// With JavaScript, magicauth.js submits the form once six characters are in; without it, the button does.
	await page.fill( 'input[name="magicauth_code"]', mailCode( mail ) );
	if ( ! js ) {
		await page.click( '.magicauth-form button[type="submit"]' );
	}
	await landed;
	assert.ok( await loggedIn( page.context() ), `signed in by code as ${ user.login }` );
}

/** Core password form (never fresh, never prompted). */
export async function signInByPassword( page, login, password = 'password' ) {
	await go( page, '/wp-login.php?magicauth=off' );
	await page.fill( '#user_login', login );
	await page.fill( '#user_pass', password );
	await Promise.all( [ page.waitForNavigation( { waitUntil: 'load' } ), page.click( '#wp-submit' ) ] );
	assert.ok( await loggedIn( page.context() ), `signed in by password as ${ login }` );
}

export async function signOut( page ) {
	// One navigation when the page carries core's nonce'd logout link (admin bar), so Back returns to it.
	const bar = page.locator( '#wp-admin-bar-logout a' );
	if ( page.url().startsWith( BASE ) && await bar.count() ) {
		await go( page, await bar.first().getAttribute( 'href' ) );
		assert.equal( await loggedIn( page.context() ), false, 'signed out' );
		return;
	}
	await go( page, '/wp-login.php?action=logout' );
	const link = page.locator( 'a[href*="action=logout"]' );
	if ( await link.count() ) {
		await Promise.all( [ page.waitForNavigation( { waitUntil: 'load' } ), link.first().click() ] );
	}
	assert.equal( await loggedIn( page.context() ), false, 'signed out' );
}

/**
 * Whether the account script opened the prompt dialog within `timeout`. A boolean on
 * purpose: a failing assert.equal() on a Locator serialises the whole Playwright
 * object graph into its message and can exhaust memory.
 */
export async function promptOpened( page, timeout = 8000 ) {
	try {
		await page.waitForSelector( '[data-magicauth-pk-prompt][open]', { timeout } );
		return true;
	} catch ( e ) {
		return false;
	}
}

export async function config( page ) {
	return page.evaluate( () => window.magicauthPasskeysConfig || null );
}

/** Add a passkey from the management page (fresh session); returns the stored row. */
export async function addPasskey( page, user, path = '/account/' ) {
	if ( ! page.url().startsWith( BASE + path ) ) {
		await go( page, path );
	}
	const add = page.locator( '[data-magicauth-pk-add]' );
	await add.waitFor( { state: 'visible' } );
	const r = await ajaxResponse( page, 'magicauth_passkey_register', () => add.click() );
	assert.equal( r.status, 200, `register: ${ JSON.stringify( r.json ) }` );
	await page.waitForFunction( () => document.querySelector( '[data-magicauth-pk-status]' ) && document.querySelector( '[data-magicauth-pk-status]' ).textContent !== '' );
	// Another Playground worker may answer the fixture read before the write is visible there.
	const id = r.json.data.passkey.id;
	const state = await until( async () => {
		const st = await fixture.user( user );
		return st.passkeys.some( ( p ) => Number( p.id ) === Number( id ) ) ? st : null;
	} );
	return state.passkeys.find( ( p ) => Number( p.id ) === Number( id ) );
}

/** Poll fn until it returns a truthy value; throws after timeout. */
export async function until( fn, timeout = 10000, every = 250 ) {
	const end = Date.now() + timeout;
	let last;
	while ( Date.now() < end ) {
		last = await fn();
		if ( last ) {
			return last;
		}
		await sleep( every );
	}
	throw new Error( 'until: condition not met' );
}

/** Text of the first matching element, '' when absent. */
export async function text( page, selector ) {
	const loc = page.locator( selector ).first();
	return ( await loc.count() ) ? ( await loc.textContent() ) || '' : '';
}

/** Wait until an element's text is not empty; returns it. */
export async function waitText( page, selector, timeout = 15000 ) {
	await page.waitForFunction( ( sel ) => {
		const el = document.querySelector( sel );
		return !! el && el.textContent.trim() !== '';
	}, selector, { timeout } );
	return ( await page.locator( selector ).first().textContent() ).trim();
}

/** Sign-in strings of the login config (en or the site locale). */
export async function loginStrings( page ) {
	const cfg = await config( page );
	assert.ok( cfg && cfg.i18n, 'login config present' );
	return cfg.i18n;
}

/** Shared per-file setup: browser launched lazily, closed after the file. */
export function stopOnExit( after ) {
	after( async () => {
		await closeBrowser();
	} );
}

/** In nojsonapi mode the native JSON helpers are gone, so the fallback serialiser runs. */
export async function assertMode( page, mode ) {
	const native = await page.evaluate( () => [
		typeof PublicKeyCredential.parseCreationOptionsFromJSON,
		typeof PublicKeyCredential.parseRequestOptionsFromJSON,
		typeof PublicKeyCredential.prototype.toJSON,
	] );
	assert.deepEqual( native, mode === 'nojsonapi' ? [ 'undefined', 'undefined', 'undefined' ] : [ 'function', 'function', 'function' ], `${ mode } mode` );
}

/**
 * Hold (per tab, while sessionStorage 'e2e:hold' is '1'): a conditional get() runs for
 * real, but the page sees its result only after window.__e2eRelease(), the moment the
 * user "picks" the passkey. A CDP authenticator resolves a conditional request at once,
 * and re-enabling presence never resolves a request that is already pending.
 */
export const HOLD = `( () => {
	const orig = navigator.credentials.get.bind( navigator.credentials );
	const held = [];
	navigator.credentials.get = function ( opts ) {
		let hold = false;
		try {
			hold = sessionStorage.getItem( 'e2e:hold' ) === '1';
		} catch ( e ) {}
		if ( ! hold || ! opts || opts.mediation !== 'conditional' ) {
			return orig( opts );
		}
		const inner = orig( opts );
		return new Promise( ( resolve, reject ) => {
			const entry = { ready: false, value: null, settle: null };
			held.push( entry );
			inner.then( ( v ) => {
				entry.ready = true;
				entry.settle = () => resolve( v );
			}, reject );
			if ( opts.signal ) {
				opts.signal.addEventListener( 'abort', () => {
					entry.settle = null;
					reject( opts.signal.reason );
				} );
			}
		} );
	};
	window.__e2eHeldCount = () => held.filter( ( e ) => e.ready && e.settle ).length;
	window.__e2eRelease = () => {
		const e = held.filter( ( x ) => x.ready && x.settle ).pop();
		if ( ! e ) {
			return false;
		}
		const settle = e.settle;
		e.settle = null;
		settle();
		return true;
	};
} )();`;

/** Turn the hold on for this tab (takes effect on the next page load). */
export async function holdConditional( page ) {
	await page.evaluate( () => sessionStorage.setItem( 'e2e:hold', '1' ) );
}

/** "Pick" the passkey offered by the held conditional request. */
export async function pickPasskey( page ) {
	await page.waitForFunction( () => typeof window.__e2eHeldCount === 'function' && window.__e2eHeldCount() > 0 );
	return page.evaluate( () => window.__e2eRelease() );
}

/** Records every magicauth:passkey:error of the tab in sessionStorage (survives navigations). */
export const ERRLOG = `document.addEventListener( 'magicauth:passkey:error', ( e ) => {
	try {
		const list = JSON.parse( sessionStorage.getItem( 'e2e:errors' ) || '[]' );
		list.push( { code: String( e.detail && e.detail.code ), context: String( e.detail && e.detail.context ) } );
		sessionStorage.setItem( 'e2e:errors', JSON.stringify( list ) );
	} catch ( err ) {}
} );`;

export async function errorEvents( page ) {
	return page.evaluate( () => JSON.parse( sessionStorage.getItem( 'e2e:errors' ) || '[]' ) );
}

/**
 * Run `fn` (for example re-enabling presence) when the next request of `action`
 * goes out, before the browser gets its response: the modal get() of the button
 * starts only after that response, so it sees the new authenticator state.
 */
export async function onNextAction( page, action, fn ) {
	let armed = true;
	const handler = async ( route ) => {
		if ( armed && actionOf( route.request() ) === action ) {
			armed = false;
			await fn();
		}
		await route.continue();
	};
	await page.route( AJAX, handler );
	return () => page.unroute( AJAX, handler );
}

/**
 * The next completion POST (a top-level navigation): resolves with its response
 * once the document it leads to has loaded.
 */
export function nextCompletion( page ) {
	const loads = [];
	const onLoad = () => loads.push( Date.now() );
	page.on( 'load', onLoad );
	return page.waitForResponse( isAction( 'magicauth_passkey_complete' ), { timeout: 30000 } ).then( async ( res ) => {
		const at = Date.now();
		await until( () => loads.some( ( t ) => t >= at ), 30000, 100 );
		page.off( 'load', onLoad );
		return res;
	} );
}
