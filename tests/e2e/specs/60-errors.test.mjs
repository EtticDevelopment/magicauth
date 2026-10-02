// Client error mapping (SPEC 8.4, 8.6): E29.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import {
	client, newUser, fixture, go, signInByLink, waitText, text, stopOnExit, sleep, config, countRequests,
	isAction, until, promptOpened,
} from '../lib/harness.mjs';

stopOnExit( after );

/**
 * WebAuthn stub (per tab, from sessionStorage 'e2e:stub'): { conditional, modal, create },
 * each a DOMException name, 'TypeError', 'pending' (never settles until aborted), or a list
 * (one entry per call, the last repeats); absent means the real call. Calls are counted in
 * sessionStorage 'e2e:calls'. Installed by addInitScript, so no call runs with page.evaluate's
 * user activation.
 */
const STUB = `( () => {
	let plan = {};
	try {
		plan = JSON.parse( sessionStorage.getItem( 'e2e:stub' ) || '{}' );
	} catch ( e ) {}
	const calls = { conditional: 0, modal: 0, create: 0 };
	const save = () => {
		try {
			sessionStorage.setItem( 'e2e:calls', JSON.stringify( calls ) );
		} catch ( e ) {}
	};
	save();
	const step = ( kind ) => {
		const p = plan[ kind ];
		return Array.isArray( p ) ? p[ Math.min( calls[ kind ] - 1, p.length - 1 ) ] : p;
	};
	const answer = ( s, opts, real ) => {
		if ( ! s ) {
			return real();
		}
		if ( s === 'pending' ) {
			return new Promise( ( resolve, reject ) => {
				if ( opts && opts.signal ) {
					opts.signal.addEventListener( 'abort', () => reject( opts.signal.reason ) );
				}
			} );
		}
		return Promise.reject( s === 'TypeError' ? new TypeError( 'stub' ) : new DOMException( 'stub', s ) );
	};
	const get = navigator.credentials.get.bind( navigator.credentials );
	const create = navigator.credentials.create.bind( navigator.credentials );
	navigator.credentials.get = function ( opts ) {
		const kind = opts && opts.mediation === 'conditional' ? 'conditional' : 'modal';
		calls[ kind ]++;
		save();
		return answer( step( kind ), opts, () => get( opts ) );
	};
	navigator.credentials.create = function ( opts ) {
		calls.create++;
		save();
		return answer( step( 'create' ), opts, () => create( opts ) );
	};
} )();`;

async function stubbed( page, path, plan, { options = false } = {} ) {
	await go( page, '/terms/' );
	await page.evaluate( ( p ) => sessionStorage.setItem( 'e2e:stub', JSON.stringify( p ) ), plan );
	const first = options ? page.waitForResponse( isAction( 'magicauth_passkey_signin_options' ) ) : null;
	await go( page, path );
	if ( first ) {
		await first;
		await sleep( 300 );
	}
}

const calls = ( page ) => page.evaluate( () => JSON.parse( sessionStorage.getItem( 'e2e:calls' ) || '{}' ) );

const ERRORS = [ 'NotAllowedError', 'SecurityError', 'NotSupportedError', 'ConstraintError', 'OperationError', 'TypeError', 'EncodingError', 'UnknownError' ];

test( 'E29 error mapping: modal and conditional get(), create(), storage, restart budget', async ( t ) => {
	await t.test( 'modal get() (button): each rejection maps per 8.6', async () => {
		const c = await client( { init: [ STUB ] } );
		try {
			for ( const name of ERRORS ) {
				await stubbed( c.page, '/login/', { conditional: 'pending', modal: name }, { options: true } );
				const l = ( await config( c.page ) ).i18n;
				await c.page.click( '[data-magicauth-passkey-signin]' );
				const shown = await waitText( c.page, '[data-magicauth-passkey-error]' );
				const expected = {
					NotAllowedError: `${ l.L3 } ${ l.L3b }`,
					SecurityError: l.L7,
					NotSupportedError: l.L7,
				}[ name ] || l.L3;
				assert.equal( shown, expected, name );
				const hidden = await c.page.locator( '[data-magicauth-passkey-signin]' ).isHidden();
				assert.equal( hidden, name === 'SecurityError' || name === 'NotSupportedError', `${ name }: button hidden only for L7` );
				const n = await calls( c.page );
				assert.equal( n.modal, name === 'OperationError' ? 2 : 1, `${ name }: modal calls (OperationError retried once, silently)` );
				if ( name === 'NotAllowedError' ) {
					// L3b once per page view.
					await c.page.click( '[data-magicauth-passkey-signin]' );
					await c.page.waitForFunction( ( l3 ) => document.querySelector( '[data-magicauth-passkey-error]' ).textContent === l3, l.L3 );
				}
			}
		} finally {
			await c.close();
		}
	} );

	await t.test( 'conditional get(): NotAllowedError restarts once, anything else stops; all silent', async () => {
		const c = await client( { init: [ STUB ] } );
		try {
			for ( const name of ERRORS ) {
				const opts = countRequests( c.page, 'magicauth_passkey_signin_options' );
				await stubbed( c.page, '/login/', { conditional: name } );
				await sleep( 2500 );
				const n = await calls( c.page );
				assert.equal( n.conditional, name === 'NotAllowedError' ? 2 : 1, `${ name }: conditional calls` );
				assert.equal( opts.n, name === 'NotAllowedError' ? 2 : 1, `${ name }: options calls` );
				assert.equal( ( await text( c.page, '[data-magicauth-passkey-error]' ) ).trim(), '', `${ name }: silent` );
				assert.equal( await c.page.locator( '[data-magicauth-passkey-signin]' ).isVisible(), true, `${ name }: the button still works` );
			}
		} finally {
			await c.close();
		}
	} );

	await t.test( 'create() on the management page: each rejection maps per 8.6, never retried', async () => {
		const user = await newUser( 'e29-create' );
		const c = await client( { init: [ STUB ] } );
		try {
			await signInByLink( c.page, user, { redirectTo: '/account/' } );
			for ( const name of [ 'InvalidStateError', ...ERRORS ] ) {
				const reg = countRequests( c.page, 'magicauth_passkey_register' );
				await stubbed( c.page, '/account/', { create: name } );
				const m = ( await config( c.page ) ).i18n;
				await c.page.click( '[data-magicauth-pk-add]' );
				const shown = await waitText( c.page, '[data-magicauth-pk-manage] [data-magicauth-pk-alert]' );
				const expected = {
					NotAllowedError: m.P10,
					InvalidStateError: m.P11,
					SecurityError: m.P12,
					NotSupportedError: m.P12,
					ConstraintError: m.P13,
				}[ name ] || m.P14;
				assert.equal( shown, expected, name );
				await sleep( 300 );
				assert.equal( ( await calls( c.page ) ).create, 1, `${ name }: one create() call, no automatic retry` );
				assert.equal( reg.n, 0, `${ name }: no register POST` );
				if ( name === 'InvalidStateError' ) {
					const acct = await c.page.evaluate( () => JSON.parse( localStorage.getItem( 'magicauth:pk:acct' ) || '{}' ) );
					assert.ok( Object.values( acct ).some( ( e ) => typeof e.haslocal === 'number' ), 'haslocal set' );
				}
			}
		} finally {
			await c.close();
		}
	} );

	await t.test( 'create() from the prompt: NotAllowedError shows P10 + P10b and stores promptfail', async () => {
		const user = await newUser( 'e29-prompt' );
		const c = await client( { init: [ STUB ] } );
		try {
			await go( c.page, '/terms/' );
			await c.page.evaluate( () => sessionStorage.setItem( 'e2e:stub', JSON.stringify( { create: 'NotAllowedError' } ) ) );
			await signInByLink( c.page, user );
			assert.ok( await promptOpened( c.page ) );
			const p = ( await config( c.page ) ).i18n;
			await c.page.click( '[data-magicauth-pk-view="offer"] [data-magicauth-pk-create]' );
			await c.page.waitForSelector( '[data-magicauth-pk-view="error"]:not([hidden])' );
			assert.equal( ( await text( c.page, '[data-magicauth-pk-error-text]' ) ).trim(), `${ p.P10 } ${ p.P10b }` );
			const acct = await c.page.evaluate( () => JSON.parse( localStorage.getItem( 'magicauth:pk:acct' ) || '{}' ) );
			assert.ok( Object.values( acct ).some( ( e ) => typeof e.promptfail === 'number' ), 'promptfail stored' );
			// Try again (P18) is a new click: create() runs once more, never on its own.
			assert.equal( ( await calls( c.page ) ).create, 1 );
		} finally {
			await c.close();
		}
	} );

	await t.test( 'localStorage throwing: the prompt still shows', async () => {
		const THROWING = `( () => {
			const boom = () => {
				throw new DOMException( 'blocked', 'SecurityError' );
			};
			Storage.prototype.getItem = boom;
			Storage.prototype.setItem = boom;
		} )();`;
		const user = await newUser( 'e29-storage' );
		const c = await client( { init: [ THROWING ] } );
		try {
			await signInByLink( c.page, user );
			assert.ok( await promptOpened( c.page ), 'prompt shown when storage throws' );
		} finally {
			await c.close();
		}
	} );

	await t.test( 'restart budget: a timer refresh restores it; a failed button attempt does not spend it', async () => {
		// After a timer refresh, a NotAllowedError restarts once again.
		let c = await client( { init: [ STUB ] } );
		try {
			await go( c.page, '/terms/' );
			await c.page.evaluate( () => sessionStorage.setItem( 'e2e:stub', JSON.stringify( { conditional: [ 'pending', 'NotAllowedError' ] } ) ) );
			await c.page.clock.install();
			const first = c.page.waitForResponse( isAction( 'magicauth_passkey_signin_options' ) );
			await go( c.page, '/login/' );
			await first;
			await sleep( 500 );
			await c.page.clock.fastForward( 541 * 1000 );
			await until( async () => ( await calls( c.page ) ).conditional >= 3 );
			await sleep( 2000 );
			assert.equal( ( await calls( c.page ) ).conditional, 3, 'refresh, then one restart, then stop' );
		} finally {
			await c.close();
		}

		// A failed button attempt restarts autofill even with the budget spent.
		c = await client( { init: [ STUB ] } );
		try {
			await stubbed( c.page, '/login/', { conditional: [ 'NotAllowedError', 'pending' ], modal: 'NotAllowedError' } );
			await until( async () => ( await calls( c.page ) ).conditional >= 2 ); // Initial, then the one restart.
			await sleep( 500 );
			await c.page.click( '[data-magicauth-passkey-signin]' );
			await waitText( c.page, '[data-magicauth-passkey-error]' );
			await until( async () => ( await calls( c.page ) ).conditional >= 3 );
			const n = await calls( c.page );
			assert.equal( n.conditional, 3, 'autofill restarted after the button' );
			assert.equal( n.modal, 1 );
		} finally {
			await c.close();
		}
	} );
} );
