// Accessibility (SPEC 8.12): E24 axe-core on every passkey surface in en_US and nl_NL, E24b focus.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import {
	BASE, client, newUser, fixture, go, signInByLink, signOut, ajaxResponse, waitText, addPasskey, mailMark,
	waitMail, mailCode, stopOnExit, sleep, config,
} from '../lib/harness.mjs';

stopOnExit( after );

const require = createRequire( import.meta.url );
const AXE = require.resolve( 'axe-core/axe.min.js' );
const TAGS = [ 'wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa' ];

/** axe-core on one surface; returns the violations (id, impact, targets). */
async function axe( page, include ) {
	if ( ! ( await page.evaluate( () => typeof window.axe === 'object' ) ) ) {
		await page.addScriptTag( { path: AXE } );
	}
	return page.evaluate( async ( { inc, tags } ) => {
		const res = await window.axe.run( { include: inc }, { runOnly: { type: 'tag', values: tags }, resultTypes: [ 'violations' ] } );
		return res.violations.map( ( v ) => ( { id: v.id, impact: v.impact, nodes: v.nodes.map( ( n ) => n.target.join( ' ' ) ) } ) );
	}, { inc: include, tags: TAGS } );
}

async function noViolations( page, include, label ) {
	const v = await axe( page, include );
	assert.deepEqual( v, [], `${ label }: ${ JSON.stringify( v, null, 1 ) }` );
}

/** Accessible names of the per-item buttons start with their visible text (WCAG 2.5.3). */
async function namesStartWithVisibleText( page ) {
	const buttons = page.locator( '[data-magicauth-pk-item] button' );
	const n = await buttons.count();
	assert.ok( n > 0 );
	for ( let i = 0; i < n; i++ ) {
		const b = buttons.nth( i );
		const visible = ( await b.evaluate( ( el ) => Array.from( el.childNodes ).filter( ( c ) => c.nodeType === 3 ).map( ( c ) => c.textContent ).join( '' ).trim() ) );
		const snap = await b.ariaSnapshot();
		const m = snap.match( /button "([^"]*)"/ );
		assert.ok( m, snap );
		assert.ok( visible !== '' && m[ 1 ].startsWith( visible ), `"${ m[ 1 ] }" starts with "${ visible }"` );
		assert.equal( await b.getAttribute( 'aria-label' ), null, 'no aria-label on per-item buttons' );
	}
}

/**
 * Esc on an open dialog, then wait for its close event: Chrome delivers it a few
 * milliseconds later, and a person never reopens the dialog inside that gap.
 */
async function escape( page, selector ) {
	await page.evaluate( ( sel ) => {
		window.__e2eClosed = false;
		document.querySelector( sel ).addEventListener( 'close', () => {
			window.__e2eClosed = true;
		}, { once: true } );
	}, selector );
	await page.keyboard.press( 'Escape' );
	await page.waitForFunction( () => window.__e2eClosed === true );
}

async function locale( value ) {
	await fixture.flags( value ? { locale: value } : {} );
}

for ( const lang of [ 'en_US', 'nl_NL' ] ) {
	test( `E24 axe-core: zero WCAG 2.2 A/AA violations on every passkey surface (${ lang })`, async () => {
		await locale( lang === 'en_US' ? '' : lang );
		try {
			// Login state A: the shortcode and the wp-login.php replacement.
			const c = await client();
			try {
				await c.auth.presence( false );
				for ( const path of [ '/login/', '/wp-login.php?action=magicauth' ] ) {
					await go( c.page, path );
					await c.page.waitForSelector( '[data-magicauth-passkey-signin]:not([hidden])' );
					const l = ( await config( c.page ) ).i18n;
					if ( lang === 'nl_NL' ) {
						assert.equal( l.L1, 'Inloggen met een passkey', 'Dutch strings' );
					}
					await noViolations( c.page, [ path.startsWith( '/login/' ) ? '.magicauth-shell' : '.magicauth-card' ], `login ${ path }` );
				}
			} finally {
				await c.close();
			}

			// Prompt open, then its step-up view.
			const p = await newUser( `e24-p-${ lang }` );
			const d = await client();
			try {
				await signInByLink( d.page, p );
				await d.page.waitForSelector( '[data-magicauth-pk-prompt][open]' );
				await noViolations( d.page, [ '[data-magicauth-pk-prompt]' ], 'prompt' );
				const dialog = d.page.locator( '[data-magicauth-pk-prompt]' );
				const bg = await dialog.evaluate( ( el ) => getComputedStyle( el ).backgroundColor );
				assert.ok( bg !== 'transparent' && bg !== 'rgba(0, 0, 0, 0)', `dialog background ${ bg }` );
				const status = await d.page.locator( '[data-magicauth-pk-prompt] [data-magicauth-pk-status]' ).evaluate( ( el ) => {
					const s = getComputedStyle( el );
					return { w: s.width, h: s.height, overflow: s.overflow, clip: s.clip, clipPath: s.clipPath };
				} );
				assert.equal( status.w, '1px' );
				assert.equal( status.h, '1px' );
				assert.equal( status.overflow, 'hidden' );
				await fixture.set( 'shift', { user: p.login, seconds: 660 } );
				await d.page.click( '[data-magicauth-pk-view="offer"] [data-magicauth-pk-create]' );
				await d.page.waitForSelector( '[data-magicauth-pk-prompt] [data-magicauth-pk-view="reauth"]:not([hidden])' );
				await noViolations( d.page, [ '[data-magicauth-pk-prompt]' ], 'prompt step-up' );
			} finally {
				await d.close();
			}

			// Management with items, rename, remove dialog, step-up view.
			const m = await newUser( `e24-m-${ lang }` );
			const e = await client();
			try {
				await signInByLink( e.page, m, { redirectTo: '/account/' } );
				await addPasskey( e.page, m );
				await go( e.page, '/account/' );
				await e.page.waitForSelector( '[data-magicauth-pk-item] [data-magicauth-pk-rename]:not([hidden])' );
				await noViolations( e.page, [ '[data-magicauth-pk-manage]' ], 'management' );
				await namesStartWithVisibleText( e.page );
				await e.page.click( '[data-magicauth-pk-item] [data-magicauth-pk-rename]' );
				await e.page.waitForSelector( '.magicauth-pk-rename input' );
				await noViolations( e.page, [ '[data-magicauth-pk-manage]' ], 'rename' );
				await e.page.keyboard.press( 'Escape' );
				await e.page.click( '[data-magicauth-pk-item] [data-magicauth-pk-remove]' );
				await e.page.waitForSelector( '[data-magicauth-pk-remove-dialog][open]' );
				await noViolations( e.page, [ '[data-magicauth-pk-remove-dialog]' ], 'remove dialog' );
				await escape( e.page, '[data-magicauth-pk-remove-dialog]' );
				await fixture.set( 'shift', { user: m.login, seconds: 660 } );
				await e.page.click( '[data-magicauth-pk-add]' );
				await e.page.waitForSelector( '[data-magicauth-pk-manage] [data-magicauth-pk-view="reauth"]:not([hidden])' );
				await noViolations( e.page, [ '[data-magicauth-pk-manage]' ], 'management step-up' );
			} finally {
				await e.close();
			}
		} finally {
			await locale( '' );
		}
	} );
}

test( 'E24b focus after every transition, keyboard only', async ( t ) => {
	await fixture.flags( { focus_css: true } );
	try {
		const active = ( page ) => page.evaluate( () => {
			const a = document.activeElement;
			return a ? Array.from( a.attributes ).map( ( x ) => x.name ).filter( ( n ) => n.startsWith( 'data-magicauth' ) ).join( ',' ) || a.tagName : null;
		} );

		// Prompt: heading on open, Tab reaches P4, success text.
		await t.test( 'prompt: heading, P4, success', async () => {
			const a = await newUser( 'e24b-ok' );
			const c = await client();
			try {
				await signInByLink( c.page, a );
				await c.page.waitForSelector( '[data-magicauth-pk-prompt][open]' );
				assert.match( await active( c.page ), /data-magicauth-pk-title/, 'focus on the heading' );
				await c.page.keyboard.press( 'Tab' );
				assert.match( await active( c.page ), /data-magicauth-pk-create/, 'Tab reaches P4 first' );
				await ajaxResponse( c.page, 'magicauth_passkey_register', () => c.page.keyboard.press( 'Enter' ) );
				await c.page.waitForSelector( '[data-magicauth-pk-view="success"]:not([hidden])' );
				assert.match( await active( c.page ), /data-magicauth-pk-success/, 'focus on the success text' );
			} finally {
				await c.close();
			}
		} );

		// Prompt: error text.
		await t.test( 'prompt: error text', async () => {
			const b = await newUser( 'e24b-err' );
			const c = await client();
			try {
				await signInByLink( c.page, b );
				await c.page.waitForSelector( '[data-magicauth-pk-prompt][open]' );
				await c.auth.uv( false );
				await c.page.keyboard.press( 'Tab' );
				await c.page.keyboard.press( 'Enter' );
				await c.page.waitForSelector( '[data-magicauth-pk-view="error"]:not([hidden])' );
				assert.match( await active( c.page ), /data-magicauth-pk-error-text/, 'focus on the error text' );
			} finally {
				await c.close();
			}
		} );

		// Prompt: step-up view (R1), then P4 after R10.
		await t.test( 'prompt: step-up R1, then P4', async () => {
			const s = await newUser( 'e24b-step' );
			const c = await client();
			try {
				await signInByLink( c.page, s );
				await c.page.waitForSelector( '[data-magicauth-pk-prompt][open]' );
				await fixture.set( 'shift', { user: s.login, seconds: 660 } );
				await c.page.keyboard.press( 'Tab' );
				await c.page.keyboard.press( 'Enter' );
				await c.page.waitForSelector( '[data-magicauth-pk-prompt] [data-magicauth-pk-view="reauth"]:not([hidden])' );
				assert.match( await active( c.page ), /data-magicauth-pk-reauth-title/, 'focus on R1' );
				const mark = await mailMark();
				await c.page.keyboard.press( 'Tab' );
				await c.page.waitForFunction( () => document.activeElement && document.activeElement.hasAttribute( 'data-magicauth-pk-reauth-email' ) );
				await ajaxResponse( c.page, 'magicauth_passkey_reauth_email', () => c.page.keyboard.press( 'Enter' ) );
				const mail = await waitMail( s.email, { after: mark, subject: /confirm/i } );
				await c.page.waitForFunction( () => document.activeElement && document.activeElement.hasAttribute( 'data-magicauth-pk-reauth-code' ) );
				await c.page.keyboard.type( mailCode( mail ) );
				await ajaxResponse( c.page, 'magicauth_passkey_reauth_code', () => c.page.keyboard.press( 'Enter' ) );
				await c.page.waitForSelector( '[data-magicauth-pk-view="offer"]:not([hidden])' );
				assert.match( await active( c.page ), /data-magicauth-pk-create/, 'focus back on P4' );
				assert.equal( await c.page.locator( '[data-magicauth-pk-prompt]' ).evaluate( ( d ) => d.open ), true );
			} finally {
				await c.close();
			}
		} );

		// Management: rename save and cancel, remove, remove dialog close; focus ring under hostile theme CSS.
		await t.test( 'management: rename, remove, dialog, focus ring', async () => {
			const m = await newUser( 'e24b-manage' );
			const c = await client();
			try {
				await signInByLink( c.page, m, { redirectTo: '/account/' } );
				await addPasskey( c.page, m );
				// Two passkeys: the second from another authenticator (another tab).
				const other = await c.tab();
				await go( other.page, '/account/' );
				await addPasskey( other.page, m );
				await other.page.close();
				await c.page.bringToFront();
				await go( c.page, '/account/' );
				assert.ok( await c.page.locator( '#magicauth-e2e-theme' ).count(), 'hostile theme CSS present' );
				const items = c.page.locator( '[data-magicauth-pk-item]' );
				assert.equal( await items.count(), 2 );

				// Rename by Enter: no reload, focus on that item's Rename.
				const firstId = await items.nth( 0 ).getAttribute( 'data-id' );
				await items.nth( 0 ).locator( '[data-magicauth-pk-rename]' ).focus();
				await c.page.keyboard.press( 'Enter' );
				await c.page.waitForSelector( '.magicauth-pk-rename input' );
				await c.page.keyboard.press( 'ControlOrMeta+a' );
				await c.page.keyboard.type( 'Keyboard laptop' );
				const navs = [];
				c.page.on( 'framenavigated', ( f ) => navs.push( f.url() ) );
				await ajaxResponse( c.page, 'magicauth_passkey_rename', () => c.page.keyboard.press( 'Enter' ) );
				await c.page.waitForFunction( ( id ) => document.activeElement && document.activeElement.hasAttribute( 'data-magicauth-pk-rename' ) && document.activeElement.closest( `[data-id="${ id }"]` ), firstId );
				assert.deepEqual( navs, [], 'no page reload' );
				// The focus indicator survives .entry-content button{all:unset} and :focus{outline:none}.
				const ring = await c.page.evaluate( () => {
					const s = getComputedStyle( document.activeElement );
					return { outline: s.outlineStyle, width: s.outlineWidth, shadow: s.boxShadow, visible: document.activeElement.matches( ':focus-visible' ) };
				} );
				assert.ok( ring.visible, 'keyboard focus is :focus-visible' );
				assert.ok( ( ring.outline !== 'none' && ring.width !== '0px' ) || ring.shadow !== 'none', `focus indicator visible: ${ JSON.stringify( ring ) }` );

				// Cancel (Escape): focus back on Rename.
				await c.page.keyboard.press( 'Enter' );
				await c.page.waitForSelector( '.magicauth-pk-rename input' );
				await c.page.keyboard.press( 'Escape' );
				assert.match( await active( c.page ), /data-magicauth-pk-rename/, 'cancel returns focus to Rename' );

				// Remove dialog: Esc returns focus to its Remove button.
				await items.nth( 0 ).locator( '[data-magicauth-pk-remove]' ).focus();
				await c.page.keyboard.press( 'Enter' );
				await c.page.waitForSelector( '[data-magicauth-pk-remove-dialog][open]' );
				await escape( c.page, '[data-magicauth-pk-remove-dialog]' );
				assert.match( await active( c.page ), /data-magicauth-pk-remove/, 'dialog close returns focus to Remove' );
				assert.equal( await c.page.evaluate( () => document.activeElement.closest( '[data-id]' ).getAttribute( 'data-id' ) ), firstId );

				// Remove the first: focus on the next item's Remove; remove the last: heading M1.
				await c.page.keyboard.press( 'Enter' );
				await c.page.waitForSelector( '[data-magicauth-pk-remove-dialog][open]' );
				await c.page.locator( '[data-magicauth-pk-remove-dialog] [data-magicauth-pk-signout]' ).uncheck();
				await c.page.locator( '[data-magicauth-pk-remove-confirm]' ).focus();
				await ajaxResponse( c.page, 'magicauth_passkey_delete', () => c.page.keyboard.press( 'Enter' ) );
				await c.page.waitForFunction( () => document.querySelectorAll( '[data-magicauth-pk-item]' ).length === 1 );
				assert.match( await active( c.page ), /data-magicauth-pk-remove/, 'focus on the next Remove' );
				await c.page.keyboard.press( 'Enter' );
				await c.page.waitForSelector( '[data-magicauth-pk-remove-dialog][open]' );
				await c.page.locator( '[data-magicauth-pk-remove-confirm]' ).focus();
				await ajaxResponse( c.page, 'magicauth_passkey_delete', () => c.page.keyboard.press( 'Enter' ) );
				await c.page.waitForFunction( () => document.querySelectorAll( '[data-magicauth-pk-item]' ).length === 0 );
				assert.match( await active( c.page ), /data-magicauth-pk-title/, 'focus on M1' );
			} finally {
				await c.close();
			}
		} );

		// Own profile: Enter in the rename input renames without submitting the profile form.
		await t.test( 'profile.php: Enter renames in place', async () => {
			const pr = await newUser( 'e24b-profile' );
			const c = await client();
			try {
				await signInByLink( c.page, pr, { redirectTo: '/account/' } );
				await addPasskey( c.page, pr );
				await go( c.page, '/wp-admin/profile.php' );
				const rename = c.page.locator( '#magicauth-passkeys [data-magicauth-pk-rename], [data-magicauth-pk-manage] [data-magicauth-pk-rename]' ).first();
				await rename.waitFor( { state: 'visible' } );
				await rename.focus();
				await c.page.keyboard.press( 'Enter' );
				await c.page.waitForSelector( '.magicauth-pk-rename input' );
				await c.page.keyboard.press( 'ControlOrMeta+a' );
				await c.page.keyboard.type( 'Profile laptop' );
				const navs = [];
				c.page.on( 'framenavigated', ( f ) => navs.push( f.url() ) );
				const r = await ajaxResponse( c.page, 'magicauth_passkey_rename', () => c.page.keyboard.press( 'Enter' ) );
				assert.equal( r.status, 200 );
				await sleep( 800 );
				assert.deepEqual( navs, [], 'profile form not submitted' );
				assert.equal( ( await fixture.user( pr ) ).passkeys[ 0 ].name, 'Profile laptop' );
			} finally {
				await c.close();
			}
		} );

		// Throttled button: aria-disabled, clicks suppressed, focus stays on it.
		await t.test( 'login: throttled button keeps focus', async () => {
			const t = await newUser( 'e24b-throttle' );
			const NO_AUTOFILL = `( () => {
				PublicKeyCredential.isConditionalMediationAvailable = async () => false;
				const caps = PublicKeyCredential.getClientCapabilities;
				PublicKeyCredential.getClientCapabilities = async () => Object.assign( {}, caps ? await caps.call( PublicKeyCredential ) : {}, { conditionalGet: false } );
			} )();`;
			const c = await client( { init: [ NO_AUTOFILL ] } );
			try {
				await signInByLink( c.page, t, { redirectTo: '/account/' } );
				await addPasskey( c.page, t );
				await signOut( c.page );
				await fixture.reset();
				await fixture.settings( { throttle: { per_ip_passkey_max: 1 } } );
				await c.auth.overrides( { isBogusSignature: true } );
				await go( c.page, '/login/' );
				const l = ( await config( c.page ) ).i18n;
				const button = c.page.locator( '[data-magicauth-passkey-signin]' );
				await button.focus();
				const first = await ajaxResponse( c.page, 'magicauth_passkey_signin', () => c.page.keyboard.press( 'Enter' ) );
				assert.equal( first.status, 400 );
				assert.equal( await waitText( c.page, '[data-magicauth-passkey-error]' ), l.L3 );
				await c.page.waitForFunction( () => ! document.querySelector( '[data-magicauth-passkey-signin]' ).hasAttribute( 'aria-busy' ) );
				const second = await ajaxResponse( c.page, 'magicauth_passkey_signin', () => c.page.keyboard.press( 'Enter' ) );
				assert.equal( second.status, 429 );
				await c.page.waitForFunction( () => document.querySelector( '[data-magicauth-passkey-signin]' ).getAttribute( 'aria-disabled' ) === 'true' );
				assert.match( await active( c.page ), /data-magicauth-passkey-signin/, 'focus stays on the throttled button' );
				const msg = await waitText( c.page, '[data-magicauth-passkey-error]' );
				assert.ok( msg === l.L4 || msg === second.json.data.message, `throttled message: ${ msg }` );
				const before = await c.page.evaluate( () => performance.getEntriesByType( 'resource' ).filter( ( r ) => r.name.includes( 'admin-ajax' ) ).length );
				await c.page.keyboard.press( 'Enter' );
				await sleep( 1000 );
				const afterCount = await c.page.evaluate( () => performance.getEntriesByType( 'resource' ).filter( ( r ) => r.name.includes( 'admin-ajax' ) ).length );
				assert.equal( afterCount, before, 'clicks suppressed while throttled' );
				assert.equal( await button.evaluate( ( el ) => el.hasAttribute( 'disabled' ) ), false, 'never the disabled attribute' );
			} finally {
				await fixture.settings( { throttle: { per_ip_passkey_max: 30 } } );
				await fixture.reset();
				await c.close();
			}
		} );
	} finally {
		await fixture.flags( {} );
	}
} );
