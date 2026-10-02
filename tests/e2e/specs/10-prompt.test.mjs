// Post-login prompt (SPEC 2.1): E2, E2b, E3, E4, E5.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import {
	client, newUser, fixture, go, signInByCode, signInByLink, signOut, promptOpened, ajaxResponse, waitMail,
	mailMark, mailText, cookie, config, stopOnExit, assertMode,
} from '../lib/harness.mjs';

stopOnExit( after );

const DAY = 86400;

async function choice( page, run ) {
	const r = await ajaxResponse( page, 'magicauth_passkey_prompt', run );
	assert.equal( r.status, 200, `prompt choice: ${ JSON.stringify( r.json ) }` );
	return r;
}

async function cadence( user ) {
	const meta = ( await fixture.user( user ) ).meta.magicauth_passkey_prompt;
	return meta && typeof meta === 'object' ? meta : { declines: 0, next_at: 0 };
}

for ( const mode of [ 'native', 'nojsonapi' ] ) {
	test( `E2 prompt after email code login, create, list, mail (${ mode })`, async () => {
		const user = await newUser( 'e2' );
		const c = await client( { mode } );
		try {
			const mark = await mailMark();
			await signInByCode( c.page, user );
			// The landing page of the sign-in carries the prompt.
			const dlg = await promptOpened( c.page );
			assert.ok( dlg, 'prompt dialog opened on the landing page' );
			await assertMode( c.page, mode );
			const cfg = await config( c.page );
			assert.equal( await c.page.locator( '[data-magicauth-pk-title]' ).textContent(), cfg.i18n.P1 );
			const reg = await ajaxResponse( c.page, 'magicauth_passkey_register', () => c.page.click( '[data-magicauth-pk-prompt] [data-magicauth-pk-view="offer"] [data-magicauth-pk-create]' ) );
			assert.equal( reg.status, 200, JSON.stringify( reg.json ) );
			await c.page.waitForSelector( '[data-magicauth-pk-view="success"]:not([hidden])' );
			assert.equal( c.auth.events.added.length, 1, 'credentialAdded fired once' );
			assert.equal( c.auth.events.added[ 0 ].rk, true, 'isResidentCredential' );
			assert.equal( c.auth.events.added[ 0 ].loggedIn, true );

			const state = await fixture.user( user );
			assert.equal( state.passkeys.length, 1 );
			const row = state.passkeys[ 0 ];
			assert.equal( row.credential_id, c.auth.events.added[ 0 ].id, 'stored credential is the authenticator one' );
			assert.deepEqual( state.meta.magicauth_passkey_prompt, { declines: 0, next_at: 0 }, 'cadence reset' );

			// Management lists it with the sync label of a device-bound credential (BE=0: M7).
			await go( c.page, '/account/' );
			const item = c.page.locator( '[data-magicauth-pk-list] [data-magicauth-pk-item]' );
			assert.equal( await item.count(), 1 );
			const acct = await config( c.page );
			const label = `Passkey ending in ${ row.credential_hash.slice( -4 ).toUpperCase() }`;
			const itemText = await item.textContent();
			assert.ok( itemText.includes( acct.i18n.M7 ), `sync label M7 in "${ itemText }"` );
			assert.ok( itemText.includes( label ), `M34 label ${ label }` );

			// Passkey-added mail: the M34 label, never the passkey name.
			const mail = await waitMail( user.email, { after: mark, subject: /passkey/i } );
			const body = mailText( mail );
			assert.ok( body.includes( label ), 'mail carries the M34 label' );
			assert.ok( ! body.includes( row.name ), `mail does not carry the name "${ row.name }"` );
		} finally {
			await c.close();
		}
	} );
}

test( 'E2b same device, next email sign-in: no prompt; another account: prompt', async () => {
	const a = await newUser( 'e2b-a' );
	const b = await newUser( 'e2b-b' );
	const c = await client();
	try {
		await signInByLink( c.page, a );
		assert.ok( await promptOpened( c.page ), 'first sign-in: prompt' );
		await ajaxResponse( c.page, 'magicauth_passkey_register', () => c.page.click( '[data-magicauth-pk-view="offer"] [data-magicauth-pk-create]' ) );
		await c.page.waitForSelector( '[data-magicauth-pk-view="success"]:not([hidden])' );
		await signOut( c.page );
		await c.auth.presence( false ); // Logged-out pages must not sign in by autofill here.
		await signInByLink( c.page, a );
		assert.equal( await promptOpened( c.page, 4000 ), false, 'same account, same browser: haslocal keeps the dialog closed' );
		await signOut( c.page );
		await signInByLink( c.page, b );
		assert.ok( await promptOpened( c.page ), 'another account in the same browser: prompt' );
	} finally {
		await c.close();
	}
} );

test( 'E3 prompt cadence: later 30/90/stop, Esc +7 days, failed closes are not declines', async () => {
	const user = await newUser( 'e3' );
	const c = await client();
	const now = async () => ( await fixture.user( user ) ).now;
	const travel = async () => fixture.set( 'meta', { user: user.login, set: { magicauth_passkey_prompt: Object.assign( await cadence( user ), { next_at: ( await now() ) - 1 } ) } } );
	const again = async () => {
		await signOut( c.page );
		await signInByLink( c.page, user );
	};
	try {
		// First Not now: declines 1, next_at +30 days.
		await signInByLink( c.page, user );
		assert.ok( await promptOpened( c.page ) );
		await choice( c.page, () => c.page.click( '[data-magicauth-pk-view="offer"] [data-magicauth-pk-later]' ) );
		let cad = await cadence( user );
		assert.equal( cad.declines, 1 );
		assert.ok( Math.abs( cad.next_at - ( await now() ) - 30 * DAY ) < 120, 'next_at +30 days' );
		// Next email sign-in: no prompt markup at all (server cadence).
		await again();
		assert.equal( await c.page.locator( '[data-magicauth-pk-prompt]' ).count(), 0 );
		// Time travel past next_at: prompt again; second Not now: +90 days.
		await travel();
		await again();
		assert.ok( await promptOpened( c.page ), 'prompt after next_at' );
		await choice( c.page, () => c.page.click( '[data-magicauth-pk-view="offer"] [data-magicauth-pk-later]' ) );
		cad = await cadence( user );
		assert.equal( cad.declines, 2 );
		assert.ok( Math.abs( cad.next_at - ( await now() ) - 90 * DAY ) < 120, 'next_at +90 days' );
		// Third Not now: never again.
		await travel();
		await again();
		assert.ok( await promptOpened( c.page ) );
		await choice( c.page, () => c.page.click( '[data-magicauth-pk-view="offer"] [data-magicauth-pk-later]' ) );
		assert.equal( ( await cadence( user ) ).declines, 3 );
		await travel();
		await again();
		assert.equal( await c.page.locator( '[data-magicauth-pk-prompt]' ).count(), 0, 'stopped after three declines' );
	} finally {
		await c.close();
	}

	// Esc: dismiss, +7 days, no decline; after next_at the prompt returns.
	const esc = await newUser( 'e3-esc' );
	const d = await client();
	try {
		await signInByLink( d.page, esc );
		assert.ok( await promptOpened( d.page ) );
		await choice( d.page, () => d.page.keyboard.press( 'Escape' ) );
		const cad = await cadence( esc );
		assert.equal( cad.declines, 0 );
		const t = ( await fixture.user( esc ) ).now;
		assert.ok( Math.abs( cad.next_at - t - 7 * DAY ) < 120, 'next_at +7 days' );
		await signOut( d.page );
		await signInByLink( d.page, esc );
		assert.equal( await d.page.locator( '[data-magicauth-pk-prompt]' ).count(), 0 );
		await fixture.set( 'meta', { user: esc.login, set: { magicauth_passkey_prompt: { declines: 0, next_at: t - 1 } } } );
		await signOut( d.page );
		await signInByLink( d.page, esc );
		assert.ok( await promptOpened( d.page ), 'prompt again after 7 days' );
	} finally {
		await d.close();
	}

	// Three closes from the error view (failed, +30 days each, never a decline), then Not now: declines 1.
	const fail = await newUser( 'e3-fail' );
	const f = await client();
	try {
		for ( let i = 0; i < 3; i++ ) {
			if ( i > 0 ) {
				await signOut( f.page );
			}
			await signInByLink( f.page, fail );
			assert.ok( await promptOpened( f.page ), `prompt ${ i + 1 }` );
			await f.auth.uv( false ); // create() rejects with NotAllowedError: the error view.
			await f.page.click( '[data-magicauth-pk-view="offer"] [data-magicauth-pk-create]' );
			await f.page.waitForSelector( '[data-magicauth-pk-view="error"]:not([hidden])' );
			await f.auth.uv( true );
			await choice( f.page, () => f.page.click( '[data-magicauth-pk-close]' ) );
			const cad = await cadence( fail );
			assert.equal( cad.declines, 0, 'a failed close is not a decline' );
			const t = ( await fixture.user( fail ) ).now;
			assert.ok( Math.abs( cad.next_at - t - 30 * DAY ) < 120, 'failed: +30 days' );
			await fixture.set( 'meta', { user: fail.login, set: { magicauth_passkey_prompt: { declines: 0, next_at: t - 1 } } } );
			// The browser's own 30-day promptfail gate (2.1) ages out too.
			await f.page.evaluate( () => {
				const map = JSON.parse( localStorage.getItem( 'magicauth:pk:acct' ) || '{}' );
				Object.keys( map ).forEach( ( k ) => {
					map[ k ].promptfail = Date.now() - 31 * 86400000;
				} );
				localStorage.setItem( 'magicauth:pk:acct', JSON.stringify( map ) );
			} );
		}
		await signOut( f.page );
		await signInByLink( f.page, fail );
		assert.ok( await promptOpened( f.page ), 'prompt still offered' );
		await choice( f.page, () => f.page.click( '[data-magicauth-pk-view="offer"] [data-magicauth-pk-later]' ) );
		assert.equal( ( await cadence( fail ) ).declines, 1 );
		const t = ( await fixture.user( fail ) ).now;
		await fixture.set( 'meta', { user: fail.login, set: { magicauth_passkey_prompt: { declines: 1, next_at: t - 1 } } } );
		await signOut( f.page );
		await signInByLink( f.page, fail );
		assert.ok( await promptOpened( f.page ), 'prompt possible after next_at' );
	} finally {
		await f.close();
	}
} );

test( 'E4 shared device: cookie, no prompt for any account on the browser', async () => {
	const a = await newUser( 'e4-a' );
	const b = await newUser( 'e4-b' );
	const c = await client();
	try {
		await signInByLink( c.page, a );
		assert.ok( await promptOpened( c.page ) );
		await choice( c.page, () => c.page.click( '[data-magicauth-pk-shared]' ) );
		const shared = await cookie( c.context, 'magicauth_pk_shared' );
		assert.ok( shared, 'magicauth_pk_shared set' );
		assert.equal( shared.value, '1' );
		assert.equal( shared.httpOnly, true );
		assert.equal( shared.sameSite, 'Lax' );
		assert.equal( shared.path, '/' );
		assert.ok( shared.expires - Date.now() / 1000 > 364 * DAY, 'one year' );
		assert.equal( await c.page.evaluate( () => localStorage.getItem( 'magicauth:pk:noprompt' ) ), '1' );
		assert.equal( ( await cadence( a ) ).declines, 0, 'user meta untouched' );
		for ( const user of [ a, b ] ) {
			await signOut( c.page );
			await signInByLink( c.page, user );
			assert.equal( await c.page.locator( '[data-magicauth-pk-prompt]' ).count(), 0, `no prompt markup for ${ user.login }` );
		}
	} finally {
		await c.close();
	}
} );

const CAPS = {
	allFalse: `( () => {
		PublicKeyCredential.getClientCapabilities = async () => ( { passkeyPlatformAuthenticator: false, userVerifyingPlatformAuthenticator: false, hybridTransport: false } );
		PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => false;
	} )();`,
	empty: `( () => {
		PublicKeyCredential.getClientCapabilities = async () => ( {} );
		PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
	} )();`,
	rejects: `( () => {
		PublicKeyCredential.getClientCapabilities = () => Promise.reject( new Error( 'no' ) );
		PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
	} )();`,
};

test( 'E5 capability gate: all false hides the prompt; {} or a rejection falls back to UVPA', async () => {
	const user = await newUser( 'e5' );
	const off = await client( { init: [ CAPS.allFalse ] } );
	try {
		await signInByLink( off.page, user );
		assert.ok( await off.page.locator( '[data-magicauth-pk-prompt]' ).count(), 'markup printed (server eligible)' );
		assert.equal( await promptOpened( off.page, 4000 ), false, 'client gate keeps it closed' );
		assert.equal( ( await cadence( user ) ).declines, 0, 'nothing sent' );
		await go( off.page, '/account/' );
		assert.ok( await off.page.locator( '[data-magicauth-pk-add]' ).isVisible(), 'management Add still visible' );
	} finally {
		await off.close();
	}
	for ( const variant of [ 'empty', 'rejects' ] ) {
		const u = await newUser( `e5-${ variant }` );
		const c = await client( { init: [ CAPS[ variant ] ] } );
		try {
			await signInByLink( c.page, u );
			assert.ok( await promptOpened( c.page ), `prompt shown (${ variant })` );
		} finally {
			await c.close();
		}
	}
} );
