// Passkey sign-in (SPEC 2.2, 6.2, 6.3, 6.13, 7.4, 7.6, 8.4, 8.6): E6 to E12, E17, E27, E28.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import {
	BASE, client, newUser, fixture, go, signInByLink, signOut, loggedIn, ajaxResponse, waitText, text,
	loginStrings, addPasskey, mailMark, mailsTo, waitMail, stopOnExit, sleep, assertMode, countRequests, cookie, isAction, until, HOLD, ERRLOG, holdConditional, pickPasskey, errorEvents, onNextAction, PAGESHOW, pageshows, nextCompletion,
} from '../lib/harness.mjs';

stopOnExit( after );

/**
 * A user with one passkey on this client's authenticator: email sign-in straight
 * onto the management page (no prompt there), Add, sign out. Presence is left off
 * unless asked, so a logged-out page does not sign in by autofill on its own.
 */
async function enrolled( c, prefix, { presence = false } = {} ) {
	const user = await newUser( prefix );
	await signInByLink( c.page, user, { redirectTo: '/account/' } );
	const row = await addPasskey( c.page, user );
	await signOut( c.page );
	await c.auth.presence( presence );
	return { user, row };
}

/** Wait until this context is signed in (the completion navigation ran). */
async function waitSignedIn( c, timeout = 30000 ) {
	const until = Date.now() + timeout;
	while ( Date.now() < until ) {
		if ( await loggedIn( c.context ) ) {
			// The 303 set the cookie; let the landing page finish loading.
			await c.page.waitForURL( ( u ) => ! String( u ).includes( 'admin-ajax.php' ), { waitUntil: 'load' } );
			return true;
		}
		await sleep( 250 );
	}
	return false;
}

/**
 * Open /login/ with presence off; the user picks the passkey from the autofill.
 * Presence comes back while the options request is out, so before get() runs: a
 * conditional request that went pending without presence never resolves. The verify
 * wait starts there too, so a late response of the previous page never counts.
 * Resolves with that pick's verify response.
 */
async function autofillPick( c ) {
	let verify = null;
	const unroute = await onNextAction( c.page, 'magicauth_passkey_signin_options', () => {
		verify = c.page.waitForResponse( isAction( 'magicauth_passkey_signin' ) );
		return c.auth.presence( true );
	} );
	try {
		await go( c.page, '/login/' );
		await until( () => null !== verify, 30000 );
		return await verify;
	} finally {
		await unroute();
	}
}

for ( const mode of [ 'native', 'nojsonapi' ] ) {
	test( `E6 autofill sign-in on the wall lands on the deep link (${ mode })`, async () => {
		const c = await client( { mode } );
		try {
			const { user, row } = await enrolled( c, 'e6', { presence: true } );
			const asserted = c.auth.events.asserted.length;
			await assertMode( c.page, mode );
			const complete = nextCompletion( c.page );
			await go( c.page, '/deep/link/' );
			const res = await complete;
			assert.equal( res.status(), 303, 'completion answers 303' );
			assert.equal( c.page.url(), `${ BASE }/deep/link/` );
			await c.page.waitForSelector( '[data-e2e-private]' );
			assert.ok( await loggedIn( c.context ) );
			assert.equal( c.auth.events.asserted.length, asserted + 1, 'credentialAsserted fired' );
			assert.equal( c.auth.events.asserted.at( -1 ).id, row.credential_id );
			assert.equal( await cookie( c.context, 'magicauth_pk_bind' ), null, 'binding cookie deleted by the completion' );
			assert.ok( await cookie( c.context, 'magicauth_pk_fresh' ), 'passkey sign-in is fresh' );
			const methods = ( await fixture.user( user ) ).sessions.map( ( x ) => x.method );
			assert.deepEqual( methods, [ 'passkey' ], 'one session, stamped passkey' );

			// Fragment variant: the wall has no redirect_to input, so the destination is location.href.
			await signOut( c.page );
			const again = nextCompletion( c.page );
			await go( c.page, '/deep/link/#part-2' );
			assert.equal( ( await again ).status(), 303 );
			assert.equal( c.page.url(), `${ BASE }/deep/link/#part-2` );
			await c.page.waitForSelector( '[data-e2e-private]' );
			assert.ok( await loggedIn( c.context ), 'signed in on the fragment URL' );
			assert.equal( await c.page.evaluate( () => location.hash ), '#part-2' );
		} finally {
			await c.close();
		}
	} );
}

for ( const mode of [ 'native', 'nojsonapi' ] ) {
	test( `E7 button handoff while the conditional request is pending (${ mode })`, async () => {
		const c = await client( { mode } );
		try {
			await enrolled( c, 'e7' );
			const opts = countRequests( c.page, 'magicauth_passkey_signin_options' );
			await go( c.page, '/login/' );
			await assertMode( c.page, mode );
			await c.page.waitForResponse( isAction( 'magicauth_passkey_signin_options' ) );
			await sleep( 500 ); // The conditional get() is now pending (presence off).
			// The user touches the authenticator once the button's own request is under way.
			await onNextAction( c.page, 'magicauth_passkey_signin_options', () => c.auth.presence( true ) );
			const done = nextCompletion( c.page );
			await c.page.click( '[data-magicauth-passkey-signin]' );
			const res = await done;
			assert.equal( opts.n, 2, 'one options call for the button' );
			assert.equal( res.status(), 303 );
			assert.ok( await waitSignedIn( c ), 'signed in by the button' );
			const errors = c.console.filter( ( m ) => /OperationError|already pending/i.test( m.text ) );
			assert.deepEqual( errors, [], 'no OperationError in the console' );
		} finally {
			await c.close();
		}
	} );
}

// AbortError shape (E7b): an engine that rejects an aborted request with a fresh
// DOMException('', 'AbortError') instead of signal.reason (w3c/webauthn 2240).
const ABORT_SHAPE = `( () => {
	const orig = navigator.credentials.get.bind( navigator.credentials );
	navigator.credentials.get = function ( opts ) {
		const p = orig( opts );
		if ( ! opts || ! opts.signal ) {
			return p;
		}
		return new Promise( ( resolve, reject ) => {
			let done = false;
			opts.signal.addEventListener( 'abort', () => {
				if ( ! done ) {
					done = true;
					reject( new DOMException( '', 'AbortError' ) );
				}
			} );
			p.then( ( v ) => {
				if ( ! done ) {
					done = true;
					resolve( v );
				}
			}, ( e ) => {
				if ( ! done ) {
					done = true;
					reject( e );
				}
			} );
		} );
	};
} )();`;

async function silent( c ) {
	assert.deepEqual( await errorEvents( c.page ), [], 'no magicauth:passkey:error' );
	const warns = c.console.filter( ( m ) => /MagicAuth/.test( m.text ) );
	assert.deepEqual( warns, [], 'no MagicAuth console message' );
}

test( 'E7b abort shape: refresh, button handoff and pagehide stay silent; autofill keeps working', async () => {
	// Timer refresh aborts the pending request; the refreshed request signs in.
	let c = await client( { init: [ ABORT_SHAPE, ERRLOG ] } );
	try {
		await enrolled( c, 'e7b' );
		await c.page.clock.install();
		const opts = countRequests( c.page, 'magicauth_passkey_signin_options' );
		const first = c.page.waitForResponse( isAction( 'magicauth_passkey_signin_options' ) );
		await go( c.page, '/login/' );
		await first;
		await sleep( 500 );
		await silent( c );
		await c.auth.presence( true );
		const done = nextCompletion( c.page );
		await c.page.clock.fastForward( 541 * 1000 ); // Past refresh_after: abort, then a new request.
		assert.equal( ( await done ).status(), 303 );
		assert.equal( opts.n, 2 );
		assert.ok( await waitSignedIn( c ), 'autofill signs in after the refresh' );
		await silent( c );
	} finally {
		await c.close();
	}

	// Button handoff.
	c = await client( { init: [ ABORT_SHAPE, ERRLOG ] } );
	try {
		await enrolled( c, 'e7b-btn' );
		await go( c.page, '/login/' );
		await c.page.waitForResponse( isAction( 'magicauth_passkey_signin_options' ) );
		await sleep( 500 );
		await onNextAction( c.page, 'magicauth_passkey_signin_options', () => c.auth.presence( true ) );
		const done = nextCompletion( c.page );
		await c.page.click( '[data-magicauth-passkey-signin]' );
		assert.equal( ( await done ).status(), 303 );
		assert.ok( await waitSignedIn( c ), 'the button signs in' );
		await silent( c );
	} finally {
		await c.close();
	}

	// pagehide aborts the request; back on the page, autofill signs in.
	c = await client( { init: [ ABORT_SHAPE, ERRLOG ] } );
	try {
		await enrolled( c, 'e7b-hide' );
		await go( c.page, '/login/' );
		await c.page.waitForResponse( isAction( 'magicauth_passkey_signin_options' ) );
		await sleep( 500 );
		await go( c.page, '/terms/' );
		await silent( c );
		await c.auth.presence( true );
		const done = nextCompletion( c.page );
		await c.page.goBack( { waitUntil: 'load' } );
		assert.equal( ( await done ).status(), 303 );
		assert.ok( await waitSignedIn( c ), 'autofill works after pagehide' );
		await silent( c );
	} finally {
		await c.close();
	}
} );

test( 'E8 UV failure: L3 and L3b; the email form still works', async () => {
	const c = await client();
	try {
		const { user } = await enrolled( c, 'e8', { presence: true } );
		await c.auth.uv( false );
		const opts = countRequests( c.page, 'magicauth_passkey_signin_options' );
		await go( c.page, '/login/' );
		const i18n = await loginStrings( c.page );
		await until( () => opts.n >= 2 ); // Conditional NotAllowedError: one restart, then autofill stops.
		await sleep( 1000 );
		assert.equal( opts.n, 2, 'one restart only' );
		assert.equal( ( await text( c.page, '[data-magicauth-passkey-error]' ) ).trim(), '', 'conditional failures are silent' );
		await c.page.click( '[data-magicauth-passkey-signin]' );
		assert.equal( await waitText( c.page, '[data-magicauth-passkey-error]' ), `${ i18n.L3 } ${ i18n.L3b }` );
		assert.equal( await loggedIn( c.context ), false );
		assert.ok( c.page.url().startsWith( `${ BASE }/login/` ), 'no navigation on failure' );
		// Email still works from the same form.
		await fixture.reset();
		const mark = await mailMark();
		await c.page.fill( 'input[name="magicauth_email"]', user.email );
		await sleep( 2200 );
		await Promise.all( [ c.page.waitForURL( /magicauth_step=code/ ), c.page.click( '.magicauth-form button[type="submit"]' ) ] );
		await waitMail( user.email, { after: mark, subject: /code|sign/i } );
	} finally {
		await c.close();
	}
} );

test( 'E9 server-side rejections: bogus signature, bad UV, bad UP', async () => {
	for ( const bits of [ { isBogusSignature: true }, { isBadUV: true }, { isBadUP: true } ] ) {
		const c = await client();
		try {
			await enrolled( c, 'e9', { presence: true } );
			await fixture.reset();
			await c.auth.overrides( bits );
			const statuses = [];
			c.page.on( 'response', ( r ) => {
				if ( isAction( 'magicauth_passkey_signin' )( r ) ) {
					statuses.push( r.status() );
				}
			} );
			await go( c.page, '/login/' );
			const i18n = await loginStrings( c.page );
			assert.equal( await waitText( c.page, '[data-magicauth-passkey-error]' ), i18n.L3, JSON.stringify( bits ) );
			await until( () => statuses.length >= 2 ); // Restarted once with fresh options, then stopped.
			await sleep( 1500 );
			assert.deepEqual( statuses, [ 400, 400 ], JSON.stringify( bits ) );
			assert.equal( await loggedIn( c.context ), false );
		} finally {
			await c.close();
		}
	}
} );

test( 'E10 BE flip is rejected', async () => {
	const c = await client();
	try {
		const { row } = await enrolled( c, 'e10' );
		await fixture.reset();
		await c.auth.props( row.credential_id, { backupEligibility: true, backupState: true } );
		await c.auth.presence( true );
		const verify = c.page.waitForResponse( isAction( 'magicauth_passkey_signin' ) );
		await go( c.page, '/login/' );
		const r = await verify;
		assert.equal( r.status(), 400 );
		assert.equal( ( await r.json() ).data.code, 'passkey_failed' );
		const i18n = await loginStrings( c.page );
		assert.equal( await waitText( c.page, '[data-magicauth-passkey-error]' ), i18n.L3 );
		assert.equal( await loggedIn( c.context ), false );
	} finally {
		await c.close();
	}
} );

test( 'E11 counter regression blocks a device-bound passkey for good; blocked mail once', async () => {
	const c = await client();
	try {
		const { user, row } = await enrolled( c, 'e11', { presence: true } );
		// One good sign-in so the stored counter is above 1.
		let done = nextCompletion( c.page );
		await go( c.page, '/login/' );
		assert.equal( ( await done ).status(), 303 );
		assert.ok( await waitSignedIn( c ) );
		const stored = Number( ( await fixture.user( user ) ).passkeys[ 0 ].sign_count );
		assert.ok( stored >= 2, `stored counter ${ stored }` );
		await signOut( c.page );
		await fixture.reset();
		const mark = await mailMark();

		await c.auth.props( row.credential_id, { signCount: 0 } );
		await c.auth.presence( false );
		assert.equal( ( await autofillPick( c ) ).status(), 400, 'lower counter rejected' );
		const blocked = await until( async () => ( await fixture.user( user ) ).passkeys[ 0 ].counter_anomaly_at );
		assert.ok( blocked, 'counter_anomaly_at set' );
		await waitMail( user.email, { after: mark, subject: /blocked/i } );

		// A later, higher counter is still rejected; no second mail.
		await c.auth.presence( false );
		await c.auth.props( row.credential_id, { signCount: 100 } );
		assert.equal( ( await autofillPick( c ) ).status(), 400, 'blocked credential stays rejected' );
		await sleep( 1500 );
		assert.equal( ( await mailsTo( user.email, mark ) ).filter( ( m ) => /blocked/i.test( m.subject ) ).length, 1, 'blocked mail sent once' );
		assert.equal( await loggedIn( c.context ), false );

		// Management: M12 and Blocked, only Remove.
		await c.auth.presence( false );
		await signInByLink( c.page, user, { redirectTo: '/account/' } );
		const item = c.page.locator( '[data-magicauth-pk-item]' );
		const acct = await c.page.evaluate( () => window.magicauthPasskeysConfig.i18n );
		const itemText = await item.textContent();
		assert.ok( itemText.includes( acct.M12 ), 'M12 shown' );
		assert.ok( itemText.includes( acct.M36 ), 'Blocked badge' );
		assert.equal( await item.locator( '[data-magicauth-pk-rename]' ).count(), 0, 'no Rename on a blocked passkey' );
		assert.equal( await item.locator( '[data-magicauth-pk-remove]' ).count(), 1 );
	} finally {
		await c.close();
	}
} );

test( 'E12 unknown credential: signalUnknownCredential deletes it from the authenticator', async () => {
	const c = await client();
	try {
		const { row } = await enrolled( c, 'e12' );
		await fixture.reset();
		await fixture.set( 'passkey_delete', { id: row.id } );
		const verify = c.page.waitForResponse( isAction( 'magicauth_passkey_signin' ) );
		await c.auth.presence( true );
		await go( c.page, '/login/' );
		const r = await verify;
		const body = await r.json();
		assert.equal( r.status(), 400 );
		assert.equal( body.data.code, 'passkey_failed' );
		assert.equal( body.data.unknown_credential, true );
		await until( () => c.auth.events.deleted.length > 0 );
		assert.equal( c.auth.events.deleted[ 0 ].id, row.credential_id, 'credentialDeleted for the used credential' );
		assert.equal( ( await c.auth.credentials() ).length, 0 );
	} finally {
		await c.close();
	}
} );

test( 'E17 already signed in: same account completes without a new session; another account gets L5', async () => {
	const c = await client( { init: [ HOLD ] } );
	try {
		const { user } = await enrolled( c, 'e17' );
		const [ original ] = await c.auth.credentials();
		// Tab A: a logged-out wall with its own authenticator holding the passkey; the
		// autofill offer stays open until the user picks it.
		const a = await c.tab();
		await a.auth.add( original );
		await go( a.page, '/terms/' );
		await holdConditional( a.page );
		await go( a.page, '/wall/' );
		await a.page.waitForResponse( isAction( 'magicauth_passkey_signin_options' ) );
		// Tab B signs in by email.
		await signInByLink( c.page, user );
		const before = ( await fixture.user( user ) ).sessions.length;
		assert.equal( before, 1 );
		const done = nextCompletion( a.page );
		await pickPasskey( a.page );
		const res = await done;
		assert.equal( res.status(), 303 );
		const setCookie = ( await res.allHeaders() )[ 'set-cookie' ] || '';
		assert.ok( ! /wordpress_logged_in_/.test( setCookie ), 'no new auth cookie' );
		await a.page.waitForURL( `${ BASE }/wall/`, { waitUntil: 'load' } );
		const after = await fixture.user( user );
		assert.equal( after.sessions.length, 1, 'no new session' );
		assert.ok( after.passkeys[ 0 ].last_used_at, 'usage recorded' );

		// Another account signed in meanwhile: L5, no swap.
		const other = await newUser( 'e17-other' );
		await signOut( c.page );
		await go( a.page, '/wall/' );
		await a.page.waitForResponse( isAction( 'magicauth_passkey_signin_options' ) );
		await signInByLink( c.page, other );
		const verify = a.page.waitForResponse( isAction( 'magicauth_passkey_signin' ) );
		await pickPasskey( a.page );
		const v = await verify;
		assert.equal( v.status(), 409 );
		assert.equal( ( await v.json() ).data.code, 'other_account' );
		const i18n = await loginStrings( a.page );
		// The wall renders errors itself (it cancels magicauth:passkey:error).
		assert.equal( await waitText( a.page, '[data-e2e-wall-message]' ), `Wall: ${ i18n.L5 }` );
		assert.equal( ( await fixture.user( other ) ).sessions.length, 1, 'still the other account' );
		assert.equal( ( await fixture.user( user ) ).sessions.length, 0, 'no session for the passkey owner' );
	} finally {
		await c.close();
	}
} );

test( 'E27 wp_login interstitial: the passkey sign-in lands on /terms/', async () => {
	const c = await client();
	try {
		await enrolled( c, 'e27', { presence: true } );
		await fixture.flags( { terms: true } );
		const done = nextCompletion( c.page );
		await go( c.page, '/login/' );
		await done;
		await c.page.waitForURL( `${ BASE }/terms/`, { waitUntil: 'load' } );
		await c.page.waitForSelector( '[data-e2e-terms]' );
		assert.ok( await loggedIn( c.context ) );
	} finally {
		await fixture.flags( {} );
		await c.close();
	}
} );

test( 'E28 bfcache restore and the long-lived wall', async () => {
	// Back/forward restore of the wall: autofill works.
	let c = await client( { bfcache: true, init: [ PAGESHOW ] } );
	try {
		await enrolled( c, 'e28-bf' );
		await go( c.page, '/wall/' );
		await c.page.waitForResponse( isAction( 'magicauth_passkey_signin_options' ) );
		await go( c.page, '/terms/' );
		const shown = c.page.waitForEvent( 'framenavigated' );
		await c.auth.presence( true );
		const done = nextCompletion( c.page );
		const restart = c.page.waitForResponse( isAction( 'magicauth_passkey_signin_options' ) );
		await c.page.goBack();
		await shown;
		await restart;
		assert.equal( ( await done ).status(), 303 );
		assert.ok( await waitSignedIn( c ) );
		const shows = await pageshows( c.page );
		const wall = shows.filter( ( x ) => x.path === '/wall/' );
		// Chrome keeps no-store pages out of the back/forward cache, so Back reloads the wall
		// (persisted false); the persisted branch runs where an engine restores it anyway.
		console.log( `  E28 wall pageshow events: ${ JSON.stringify( wall ) }; not restored because: ${ JSON.stringify( c.bfcache ) }` );
	} finally {
		await c.close();
	}

	// Field focused past the TTL: L11 or a sign-in after the automatic refresh, never a dead autofill.
	c = await client();
	try {
		await enrolled( c, 'e28-ttl' );
		await c.page.clock.install();
		const opts = countRequests( c.page, 'magicauth_passkey_signin_options' );
		const first = c.page.waitForResponse( isAction( 'magicauth_passkey_signin_options' ) );
		await go( c.page, '/wall/' );
		await first;
		await sleep( 300 ); // issuedAt is stamped when the options arrive.
		await c.page.focus( '#e2e-wall-email' );
		await c.page.clock.fastForward( 540 * 1000 ); // Focused: no refresh at refresh_after.
		await sleep( 500 );
		assert.equal( opts.n, 1, 'no refresh while the field is focused before ttl - 30 s' );
		await c.auth.presence( true ); // The user picks the passkey from the refreshed request.
		const done = nextCompletion( c.page );
		await c.page.clock.fastForward( 61 * 1000 ); // Past ttl - 30 s and past ttl.
		assert.equal( ( await done ).status(), 303 );
		assert.equal( opts.n, 2, 'refreshed once' );
		assert.ok( await waitSignedIn( c ), 'signed in after the refresh' );
	} finally {
		await c.close();
	}

	// Refresh at t=540 re-sends the binding cookie (Max-Age 720); at t=700 the refreshed challenge signs in.
	c = await client( { init: [ HOLD ] } );
	try {
		await enrolled( c, 'e28-slide', { presence: true } );
		await go( c.page, '/terms/' );
		await holdConditional( c.page );
		await c.page.clock.install();
		const first = c.page.waitForResponse( isAction( 'magicauth_passkey_signin_options' ) );
		await go( c.page, '/wall/' );
		const r1 = await first;
		assert.match( ( await r1.allHeaders() )[ 'set-cookie' ] || '', /magicauth_pk_bind=[0-9a-f]{64}.*Max-Age=720/i );
		// Server half of the time travel: challenge rows age with the client clock.
		await fixture.set( 'shift_challenges', { seconds: 540 } );
		const second = c.page.waitForResponse( isAction( 'magicauth_passkey_signin_options' ) );
		await c.page.clock.fastForward( 540 * 1000 );
		const r2 = await second;
		const sc = ( await r2.allHeaders() )[ 'set-cookie' ] || '';
		assert.match( sc, /magicauth_pk_bind=[0-9a-f]{64}.*Max-Age=720/i, 'refresh re-sends the cookie' );
		await c.page.clock.fastForward( 160 * 1000 );
		await fixture.set( 'shift_challenges', { seconds: 160 } ); // First challenge 700 s old (expired), second 160 s.
		const rows = ( await fixture.get( 'challenges' ) ).rows.filter( ( r ) => r.ceremony === 'signin' && ! r.consumed_at );
		assert.ok( rows.length >= 2, 'both sign-in challenges stored' );
		const verify = c.page.waitForResponse( isAction( 'magicauth_passkey_signin' ) );
		const done = nextCompletion( c.page );
		await pickPasskey( c.page ); // Picked at t=700 from the request refreshed at t=540.
		assert.equal( ( await verify ).status(), 200 );
		assert.equal( ( await done ).status(), 303 );
		assert.ok( await waitSignedIn( c ) );
	} finally {
		await c.close();
	}
} );
