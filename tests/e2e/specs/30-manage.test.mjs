// Management, step-up and account events (SPEC 2.3, 2.4, 3.5, 7.6, 8.7, 8.9): E13 to E16, E18, E21, E22.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import {
	BASE, client, newUser, fixture, go, signInByLink, signInByPassword, signOut, loggedIn, ajaxResponse, waitText,
	text, addPasskey, mailMark, waitMail, mailsTo, mailCode, stopOnExit, sleep, assertMode, countRequests, isAction,
	until, onNextAction, config, actionOf, AJAX, nextCompletion,
} from '../lib/harness.mjs';

stopOnExit( after );

/** Counts signal calls of the tab in sessionStorage, then calls through. */
const SIGCOUNT = `( () => {
	if ( ! window.PublicKeyCredential ) {
		return;
	}
	[ 'signalAllAcceptedCredentials', 'signalCurrentUserDetails', 'signalUnknownCredential' ].forEach( ( name ) => {
		const orig = PublicKeyCredential[ name ];
		if ( typeof orig !== 'function' ) {
			return;
		}
		PublicKeyCredential[ name ] = function ( options ) {
			try {
				const list = JSON.parse( sessionStorage.getItem( 'e2e:signals' ) || '[]' );
				list.push( { name, path: location.pathname, ids: options && options.allAcceptedCredentialIds ? options.allAcceptedCredentialIds.length : null } );
				sessionStorage.setItem( 'e2e:signals', JSON.stringify( list ) );
			} catch ( e ) {}
			return orig.call( PublicKeyCredential, options );
		};
	} );
} )();`;

async function signals( page ) {
	return page.evaluate( () => JSON.parse( sessionStorage.getItem( 'e2e:signals' ) || '[]' ) );
}

/** An administrator session (core password form) in its own context. */
async function adminClient() {
	const a = await client();
	await signInByPassword( a.page, 'admin' );
	return a;
}

async function adminEditUser( a, user ) {
	await go( a.page, `/wp-admin/user-edit.php?user_id=${ user.id }` );
}

async function adminChangeEmail( a, user, email ) {
	await adminEditUser( a, user );
	await a.page.fill( '#email', email );
	await Promise.all( [ a.page.waitForNavigation( { waitUntil: 'load' } ), a.page.click( '#submit' ) ] );
	assert.equal( ( await fixture.user( user ) ).email, email.toLowerCase(), 'email changed' );
}

/** Wait until the step-up view is shown; returns which method buttons are visible. */
async function stepUpShown( page, scope = '' ) {
	const view = page.locator( `${ scope } [data-magicauth-pk-view="reauth"]`.trim() ).first();
	await view.waitFor( { state: 'visible' } );
	const focused = await page.evaluate( () => document.activeElement && document.activeElement.hasAttribute( 'data-magicauth-pk-reauth-title' ) );
	return {
		view,
		focused,
		email: await view.locator( '[data-magicauth-pk-reauth-email]' ).isVisible(),
		passkey: await view.locator( '[data-magicauth-pk-reauth-passkey]' ).isVisible(),
		none: await view.locator( '[data-magicauth-pk-reauth-none]' ).isVisible(),
	};
}

/** Step up by email code: send, read the mail, type it, press Enter. */
async function stepUpByCode( page, view, user ) {
	const mark = await mailMark();
	const sent = await ajaxResponse( page, 'magicauth_passkey_reauth_email', () => view.locator( '[data-magicauth-pk-reauth-email]' ).click() );
	assert.equal( sent.status, 200, JSON.stringify( sent.json ) );
	const mail = await waitMail( user.email, { after: mark, subject: /confirm/i } );
	const input = view.locator( '[data-magicauth-pk-reauth-code]' );
	await input.waitFor( { state: 'visible' } );
	await input.fill( mailCode( mail ) );
	const ok = await ajaxResponse( page, 'magicauth_passkey_reauth_code', () => input.press( 'Enter' ) );
	assert.equal( ok.status, 200, JSON.stringify( ok.json ) );
	return mail;
}

test( 'E13 rename keeps the list; a display name change reaches the authenticator', async () => {
	const user = await newUser( 'e13' );
	const c = await client( { init: [ SIGCOUNT ] } );
	try {
		await signInByLink( c.page, user, { redirectTo: '/account/' } );
		const row = await addPasskey( c.page, user );
		const item = c.page.locator( `[data-magicauth-pk-item][data-id="${ row.id }"]` );
		await item.locator( '[data-magicauth-pk-rename]' ).click();
		const input = item.locator( 'input' );
		await input.fill( 'Work laptop' );
		const r = await ajaxResponse( c.page, 'magicauth_passkey_rename', () => input.press( 'Enter' ) );
		assert.equal( r.status, 200 );
		await c.page.waitForFunction( () => document.querySelector( '[data-magicauth-pk-name]' ).textContent === 'Work laptop' );
		await until( async () => ( await signals( c.page ) ).filter( ( s ) => s.name === 'signalAllAcceptedCredentials' ).length >= 2 );
		await sleep( 500 );
		assert.equal( c.auth.events.deleted.length, 0, 'the accepted list kept the passkey' );
		assert.equal( ( await c.auth.credentials() ).length, 1 );
		assert.equal( c.page.url(), `${ BASE }/account/`, 'no reload' );

		// Display name via the own profile; the next page view tells the authenticator.
		await go( c.page, '/wp-admin/profile.php' );
		await c.page.fill( '#nickname', 'Renamed E13' );
		await c.page.locator( '#display_name' ).evaluate( ( sel ) => {
			const o = document.createElement( 'option' );
			o.value = 'Renamed E13';
			o.textContent = 'Renamed E13';
			sel.appendChild( o );
			sel.value = 'Renamed E13';
		} );
		await Promise.all( [ c.page.waitForNavigation( { waitUntil: 'load' } ), c.page.click( '#submit' ) ] );
		assert.equal( ( await fixture.user( user ) ).display_name, 'Renamed E13' );
		await go( c.page, '/terms/' );
		await until( () => c.auth.events.updated.length > 0 );
		const up = c.auth.events.updated.at( -1 );
		assert.equal( up.id, row.credential_id );
		assert.equal( up.displayName, 'Renamed E13', 'credentialUpdated with the new display name' );
	} finally {
		await c.close();
	}
} );

test( 'E13b email change revokes; seat reassignment cannot add; an in-flight create is signalled away', async () => {
	const admin = await adminClient();
	try {
		// Rule M: passkeys gone, mail to both addresses, the next email sign-in signals [] to the authenticator.
		const s = await newUser( 'e13b' );
		const c = await client();
		try {
			await signInByLink( c.page, s, { redirectTo: '/account/' } );
			const row = await addPasskey( c.page, s );
			await signOut( c.page );
			await c.auth.presence( false );
			const mark = await mailMark();
			const newEmail = `moved-${ s.login }@example.com`;
			await adminChangeEmail( admin, s, newEmail );
			const state = await fixture.user( s );
			assert.equal( state.passkeys.length, 0, 'every passkey removed' );
			assert.ok( state.meta.magicauth_email_changed_at, 'magicauth_email_changed_at set' );
			await waitMail( s.email, { after: mark, subject: /removed/i } );
			await waitMail( newEmail, { after: mark, subject: /removed/i } );
			const moved = Object.assign( {}, s, { email: newEmail } );
			await signInByLink( c.page, moved, { redirectTo: '/terms/' } );
			await until( () => c.auth.events.deleted.length > 0, 15000 );
			assert.equal( c.auth.events.deleted[ 0 ].id, row.credential_id, 'credentialDeleted (empty accepted list)' );
			assert.equal( c.auth.events.asserted.length, 0 );
		} finally {
			await c.close();
		}

		// Seat reassignment: signed in by link, the email changes 2 minutes later: R14 only.
		const t = await newUser( 'e13b-seat' );
		const b = await client();
		try {
			await signInByLink( b.page, t, { redirectTo: '/account/' } );
			await fixture.set( 'shift', { user: t.login, seconds: 120 } );
			await adminChangeEmail( admin, t, `seat-${ t.login }@example.com` );
			await go( b.page, '/account/' );
			const r = await ajaxResponse( b.page, 'magicauth_passkey_register_options', () => b.page.click( '[data-magicauth-pk-add]' ) );
			assert.equal( r.status, 403 );
			assert.deepEqual( r.json.data.methods, [], 'no step-up method after the email change' );
			const shown = await stepUpShown( b.page );
			assert.deepEqual( { email: shown.email, passkey: shown.passkey, none: shown.none }, { email: false, passkey: false, none: true }, 'R14 only' );
			assert.equal( b.auth.events.added.length, 0 );
		} finally {
			await b.close();
		}

		// A create() whose options came before the change and whose result arrives after it.
		const u = await newUser( 'e13b-flight' );
		const d = await client();
		try {
			await signInByLink( d.page, u, { redirectTo: '/account/' } );
			let release;
			const gate = new Promise( ( r ) => {
				release = r;
			} );
			const held = async ( route ) => {
				if ( actionOf( route.request() ) === 'magicauth_passkey_register' ) {
					await gate;
				}
				await route.continue();
			};
			await d.page.route( AJAX, held );
			const reg = d.page.waitForResponse( isAction( 'magicauth_passkey_register' ) );
			await d.page.click( '[data-magicauth-pk-add]' );
			await until( () => d.auth.events.added.length > 0 ); // The authenticator made it.
			await adminChangeEmail( admin, u, `flight-${ u.login }@example.com` );
			release();
			const r = await reg;
			const body = await r.json();
			assert.equal( r.status(), 400 );
			assert.equal( body.data.code, 'registration_failed' );
			assert.equal( body.data.unknown_credential, true );
			const acct = await config( d.page );
			assert.equal( await waitText( d.page, '[data-magicauth-pk-alert]' ), acct.i18n.P15 );
			assert.equal( ( await fixture.user( u ) ).passkeys.length, 0, 'no row stored' );
			await until( () => d.auth.events.deleted.length > 0 );
			assert.equal( d.auth.events.deleted[ 0 ].id, d.auth.events.added[ 0 ].id, 'the flagged credential is signalled away' );
		} finally {
			await d.close();
		}
	} finally {
		await admin.close();
	}
} );

test( 'E14 admin revoke with sign out everywhere; the next email sign-in signals []', async () => {
	const s = await newUser( 'e14' );
	const c = await client();
	const admin = await adminClient();
	try {
		await signInByLink( c.page, s, { redirectTo: '/account/' } );
		const row = await addPasskey( c.page, s );
		await c.auth.presence( false );
		const mark = await mailMark();
		await adminEditUser( admin, s );
		const section = admin.page.locator( '[data-magicauth-pk-manage][data-magicauth-pk-mode="admin"]' );
		await section.locator( '[data-magicauth-pk-remove-all]' ).click();
		const dlg = admin.page.locator( '[data-magicauth-pk-remove-all-dialog]' );
		assert.equal( await dlg.locator( '[data-magicauth-pk-signout]' ).isChecked(), true, 'A9 checked by default' );
		const r = await ajaxResponse( admin.page, 'magicauth_admin_passkey_revoke_all', () => dlg.locator( '[data-magicauth-pk-remove-all-confirm]' ).click() );
		assert.equal( r.status, 200, JSON.stringify( r.json ) );
		assert.equal( r.json.data.count, 1 );
		assert.equal( r.json.data.signed_out, true );
		await waitMail( s.email, { after: mark, subject: /removed/i } );
		const state = await fixture.user( s );
		assert.equal( state.passkeys.length, 0 );
		assert.equal( state.sessions.length, 0, 'every session of the student ended' );
		// The student's browser is signed out (its cookie no longer maps to a session).
		await go( c.page, '/account/' );
		assert.equal( await c.page.locator( '[data-magicauth-pk-manage]' ).count(), 0, 'management not rendered: signed out' );
		// Email sign-in: no assertion; the first signed-in front-end page signals the empty list
		// (the dashboard prompt carries no signals, so the landing page is a front-end one).
		await signInByLink( c.page, s, { redirectTo: '/terms/' } );
		await until( () => c.auth.events.deleted.length > 0, 15000 );
		assert.equal( c.auth.events.deleted[ 0 ].id, row.credential_id );
		assert.equal( c.auth.events.asserted.length, 0, 'no credentialAsserted' );
	} finally {
		await c.close();
		await admin.close();
	}
} );

test( 'E15 stale session step-up by email code (prompt and management)', async () => {
	// Prompt: Enter in the code input confirms (R10) and keeps the dialog open; Create then succeeds.
	const p = await newUser( 'e15-prompt' );
	const c = await client();
	try {
		await signInByLink( c.page, p );
		await c.page.waitForSelector( '[data-magicauth-pk-prompt][open]' );
		await fixture.set( 'shift', { user: p.login, seconds: 660 } );
		const create = c.page.locator( '[data-magicauth-pk-view="offer"] [data-magicauth-pk-create]' );
		const r = await ajaxResponse( c.page, 'magicauth_passkey_register_options', () => create.click() );
		assert.equal( r.status, 403 );
		assert.equal( r.json.data.code, 'reauth_required' );
		const shown = await stepUpShown( c.page, '[data-magicauth-pk-prompt]' );
		assert.ok( shown.email && shown.focused, 'step-up view, focus on R1' );
		await stepUpByCode( c.page, shown.view, p );
		const cfg = await config( c.page );
		assert.equal( await waitText( c.page, '[data-magicauth-pk-prompt] [data-magicauth-pk-status]' ), cfg.i18n.R10 );
		assert.equal( await c.page.locator( '[data-magicauth-pk-prompt]' ).evaluate( ( d ) => d.open ), true, 'dialog still open' );
		const reg = await ajaxResponse( c.page, 'magicauth_passkey_register', () => create.click() );
		assert.equal( reg.status, 200, JSON.stringify( reg.json ) );
		await c.page.waitForSelector( '[data-magicauth-pk-view="success"]:not([hidden])' );
		const state = ( await fixture.user( p ) ).state;
		assert.equal( state[ 0 ].reauth_method, 'email_code' );
	} finally {
		await c.close();
	}

	// Management page: the inline step-up view.
	const m = await newUser( 'e15-manage' );
	const d = await client();
	try {
		await signInByLink( d.page, m, { redirectTo: '/account/' } );
		await fixture.set( 'shift', { user: m.login, seconds: 660 } );
		await d.page.click( '[data-magicauth-pk-add]' );
		const shown = await stepUpShown( d.page, '[data-magicauth-pk-manage]' );
		assert.ok( shown.email && shown.focused );
		await stepUpByCode( d.page, shown.view, m );
		const cfg = await config( d.page );
		assert.equal( await waitText( d.page, '[data-magicauth-pk-manage] [data-magicauth-pk-status]' ), cfg.i18n.R10 );
		assert.equal( await d.page.evaluate( () => document.activeElement.hasAttribute( 'data-magicauth-pk-add' ) ), true, 'focus back on Add' );
		const row = await addPasskey( d.page, m );
		assert.ok( row );
	} finally {
		await d.close();
	}
} );

test( 'E15b admin-created link: no prompt, step-up code goes to the student', async () => {
	const s = await newUser( 'e15b' );
	const admin = await adminClient();
	const c = await client();
	try {
		await adminEditUser( admin, s );
		await admin.page.click( '[data-magicauth-action="create_login_link_for_user"]' );
		const out = admin.page.locator( '#magicauth-user-link-output input' );
		await admin.page.waitForFunction( () => {
			const i = document.querySelector( '#magicauth-user-link-output input' );
			return i && /magicauth=verify/.test( i.value );
		} );
		const link = await out.inputValue();
		await c.page.goto( link, { waitUntil: 'load' } );
		assert.ok( await loggedIn( c.context ), 'signed in by the admin link' );
		const st = await fixture.user( s );
		assert.deepEqual( st.sessions.map( ( x ) => x.method ), [ 'admin_link' ] );
		assert.equal( await c.page.locator( '[data-magicauth-pk-prompt]' ).count(), 0, 'no prompt' );
		await go( c.page, '/account/' );
		const r = await ajaxResponse( c.page, 'magicauth_passkey_register_options', () => c.page.click( '[data-magicauth-pk-add]' ) );
		assert.equal( r.json.data.code, 'reauth_required' );
		const shown = await stepUpShown( c.page );
		assert.equal( shown.email, true );
		const mark = await mailMark();
		await ajaxResponse( c.page, 'magicauth_passkey_reauth_email', () => shown.view.locator( '[data-magicauth-pk-reauth-email]' ).click() );
		await waitMail( s.email, { after: mark, subject: /confirm/i } );
		assert.equal( ( await mailsTo( 'admin@example.com', mark ) ).length, 0, 'nothing to the administrator' );
	} finally {
		await c.close();
		await admin.close();
	}
} );

for ( const mode of [ 'native', 'nojsonapi' ] ) {
	test( `E16 step-up with an existing passkey (${ mode })`, async () => {
		const s = await newUser( 'e16' );
		const c = await client( { mode } );
		try {
			await signInByLink( c.page, s, { redirectTo: '/account/' } );
			await assertMode( c.page, mode );
			const first = await addPasskey( c.page, s );
			await fixture.set( 'shift', { user: s.login, seconds: 660 } );
			await go( c.page, '/account/' );
			await c.page.click( '[data-magicauth-pk-add]' );
			const shown = await stepUpShown( c.page );
			assert.ok( shown.passkey, 'R4 offered' );
			const ok = await ajaxResponse( c.page, 'magicauth_passkey_reauth_passkey', () => shown.view.locator( '[data-magicauth-pk-reauth-passkey]' ).click() );
			assert.equal( ok.status, 200, JSON.stringify( ok.json ) );
			assert.equal( c.auth.events.asserted.at( -1 ).id, first.credential_id );
			const cfg = await config( c.page );
			assert.equal( await waitText( c.page, '[data-magicauth-pk-manage] [data-magicauth-pk-status]' ), cfg.i18n.R10 );
			assert.equal( ( await fixture.user( s ) ).state[ 0 ].reauth_method, 'passkey' );
			// The confirming passkey lives on another device: this authenticator no longer holds it.
			await c.auth.remove( first.credential_id );
			const second = await addPasskey( c.page, s );
			assert.notEqual( second.credential_id, first.credential_id );
		} finally {
			await c.close();
		}
	} );
}

test( 'E18 disabled user: passkey sign-in L3, Add and step-up refused', async () => {
	const s = await newUser( 'e18' );
	const c = await client();
	const admin = await adminClient();
	try {
		await signInByLink( c.page, s, { redirectTo: '/account/' } );
		await addPasskey( c.page, s );
		await adminEditUser( admin, s );
		await admin.page.check( 'input[name="magicauth_disabled"]' );
		await Promise.all( [ admin.page.waitForNavigation( { waitUntil: 'load' } ), admin.page.click( '#submit' ) ] );
		assert.ok( ( await fixture.user( s ) ).meta.magicauth_disabled );

		await go( c.page, '/account/' );
		const r = await ajaxResponse( c.page, 'magicauth_passkey_register_options', () => c.page.click( '[data-magicauth-pk-add]' ) );
		assert.equal( r.status, 403 );
		assert.equal( r.json.data.code, 'disabled_user' );
		const cfg = await config( c.page );
		assert.equal( await waitText( c.page, '[data-magicauth-pk-alert]' ), cfg.i18n.P12 );
		const step = await c.page.evaluate( async ( nonce ) => {
			const res = await fetch( '/wp-admin/admin-ajax.php', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams( { action: 'magicauth_passkey_reauth_email', _ajax_nonce: nonce } ) } );
			return { status: res.status, body: await res.json() };
		}, cfg.nonce );
		assert.equal( step.status, 403 );
		assert.equal( step.body.data.code, 'disabled_user' );

		await signOut( c.page );
		await fixture.reset();
		const verify = c.page.waitForResponse( isAction( 'magicauth_passkey_signin' ) );
		await go( c.page, '/login/' );
		const v = await verify;
		assert.equal( v.status(), 400 );
		assert.equal( ( await v.json() ).data.code, 'passkey_failed' );
		const l = ( await config( c.page ) ).i18n;
		assert.equal( await waitText( c.page, '[data-magicauth-passkey-error]' ), l.L3 );
		await sleep( 1500 );
		assert.equal( await loggedIn( c.context ), false );
	} finally {
		await c.close();
		await admin.close();
	}
} );

for ( const mode of [ 'native', 'nojsonapi' ] ) {
	test( `E21 exclude list: a second passkey on the same authenticator is refused locally (${ mode })`, async () => {
		const s = await newUser( 'e21' );
		const c = await client( { mode } );
		try {
			await signInByLink( c.page, s, { redirectTo: '/account/' } );
			await assertMode( c.page, mode );
			await addPasskey( c.page, s );
			const register = countRequests( c.page, 'magicauth_passkey_register' );
			await c.page.click( '[data-magicauth-pk-add]' );
			const cfg = await config( c.page );
			assert.equal( await waitText( c.page, '[data-magicauth-pk-alert]' ), cfg.i18n.P11 );
			await sleep( 500 );
			assert.equal( register.n, 0, 'no server write' );
			assert.equal( ( await fixture.user( s ) ).passkeys.length, 1 );
			assert.equal( c.auth.events.added.length, 1 );
			const entry = await c.page.evaluate( () => JSON.parse( localStorage.getItem( 'magicauth:pk:acct' ) || '{}' ) );
			assert.ok( Object.values( entry ).some( ( e ) => typeof e.haslocal === 'number' ), 'haslocal stored' );
		} finally {
			await c.close();
		}
	} );
}

test( 'E22 theme contract: the wall signs in, renders errors itself; /account-tpl/ works', async () => {
	const s = await newUser( 'e22' );
	const c = await client( { init: [ SIGCOUNT ] } );
	try {
		await signInByLink( c.page, s, { redirectTo: '/account/' } );
		await addPasskey( c.page, s );
		await signOut( c.page );
		await c.auth.presence( false );

		// Button on the theme markup.
		await go( c.page, '/wall/' );
		await c.page.waitForResponse( isAction( 'magicauth_passkey_signin_options' ) );
		assert.equal( await c.page.locator( '[data-magicauth-passkey-signin]' ).isVisible(), true, 'theme button unhidden' );
		await onNextAction( c.page, 'magicauth_passkey_signin_options', () => c.auth.presence( true ) );
		const done = nextCompletion( c.page );
		await c.page.click( '[data-magicauth-passkey-signin]' );
		assert.equal( ( await done ).status(), 303 );
		assert.equal( c.page.url(), `${ BASE }/wall/` );
		assert.ok( await loggedIn( c.context ) );
		await signOut( c.page );

		// An error: the page cancels magicauth:passkey:error and renders it in place.
		await c.page.unrouteAll( { behavior: 'ignoreErrors' } );
		await c.auth.presence( true );
		await c.auth.uv( false );
		await go( c.page, '/wall/' );
		const l = ( await config( c.page ) ).i18n;
		await sleep( 1500 );
		await c.page.click( '[data-magicauth-passkey-signin]' );
		assert.equal( await waitText( c.page, '[data-e2e-wall-message]' ), `Wall: ${ l.L3 } ${ l.L3b }` );
		assert.equal( ( await text( c.page, '[data-magicauth-passkey-error]' ) ).trim(), '', 'MagicAuth left the region to the theme' );
		await c.auth.uv( true );
		await c.auth.presence( false );

		// /account-tpl/: the shortcode printed by a template (late enqueue), first page of a session.
		await signInByLink( c.page, s, { redirectTo: '/account-tpl/' } );
		assert.equal( c.page.url(), `${ BASE }/account-tpl/` );
		const add = c.page.locator( '[data-magicauth-pk-add]' );
		await add.waitFor( { state: 'visible' } );
		await sleep( 1000 );
		const sent = ( await signals( c.page ) ).filter( ( x ) => x.path === '/account-tpl/' && x.name === 'signalAllAcceptedCredentials' );
		assert.equal( sent.length, 1, 'signals sent once' );
		const item = c.page.locator( '[data-magicauth-pk-item]' ).first();
		await item.locator( '[data-magicauth-pk-rename]' ).click();
		await item.locator( 'input' ).fill( 'Template laptop' );
		const r = await ajaxResponse( c.page, 'magicauth_passkey_rename', () => item.locator( 'input' ).press( 'Enter' ) );
		assert.equal( r.status, 200 );
		assert.equal( ( await fixture.user( s ) ).passkeys[ 0 ].name, 'Template laptop' );
	} finally {
		await c.close();
	}
} );
