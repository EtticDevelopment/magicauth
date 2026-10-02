// Runs assets/js/magicauth-passkeys-core.js and -login.js against a fake DOM, a fake fetch, a fake
// navigator.credentials and virtual timers, then checks one scenario of SPEC 8.4 / 8.6 / 2.2.
// Usage: node login-lifecycle.js <plugin dir> <scenario>. Prints "ok" or the failure; exit 0 / 1.
'use strict';

const fs = require( 'fs' );
const path = require( 'path' );
const vm = require( 'vm' );
const assert = require( 'assert' );

const dir = process.argv[ 2 ];
const scenario = process.argv[ 3 ];

const L = {
	L1: 'Sign in with a passkey', L2: 'Waiting', L3: 'Did not work', L3b: 'Open in browser', L4: 'Too many',
	L5: 'Other account', L6: 'Did not finish', L7: 'Not available', L8: 'Use email', L9: 'or', L10: 'Signed in', L11: 'Too long',
};

function flush() {
	let p = Promise.resolve();
	for ( let i = 0; i < 30; i++ ) {
		p = p.then( () => new Promise( ( r ) => setImmediate( r ) ) );
	}
	return p;
}

function deferred() {
	let resolve;
	let reject;
	const promise = new Promise( ( res, rej ) => {
		resolve = res;
		reject = rej;
	} );
	return { promise, resolve, reject };
}

function domError( name ) {
	const e = new Error( name );
	e.name = name;
	return e;
}

class El {
	constructor( tag, attrs ) {
		this.tagName = tag.toUpperCase();
		this.attrs = Object.assign( {}, attrs || {} );
		this.listeners = {};
		this.children = [];
		this.textContent = '';
		this.form = null;
		this.value = '';
		const self = this;
		this.classList = {
			set: new Set(),
			add( c ) { this.set.add( c ); },
			remove( c ) { this.set.delete( c ); },
			toggle( c, on ) { if ( on ) { this.set.add( c ); } else { this.set.delete( c ); } },
			contains( c ) { return this.set.has( c ); },
		};
		this.submitted = null;
		this.submit = function () {
			self.submitted = {};
			self.children.forEach( ( c ) => { self.submitted[ c.name ] = c.value; } );
		};
	}
	get hidden() { return 'hidden' in this.attrs; }
	set hidden( v ) { if ( v ) { this.attrs.hidden = ''; } else { delete this.attrs.hidden; } }
	setAttribute( k, v ) { this.attrs[ k ] = String( v ); }
	getAttribute( k ) { return k in this.attrs ? this.attrs[ k ] : null; }
	removeAttribute( k ) { delete this.attrs[ k ]; }
	hasAttribute( k ) { return k in this.attrs; }
	addEventListener( t, f ) { ( this.listeners[ t ] = this.listeners[ t ] || [] ).push( f ); }
	fire( t, ev ) { ( this.listeners[ t ] || [] ).forEach( ( f ) => f( ev || { type: t, preventDefault() {} } ) ); }
	appendChild( c ) { this.children.push( c ); return c; }
	querySelector( sel ) {
		if ( sel === 'input[name="redirect_to"]' ) {
			return this.children.find( ( c ) => c.name === 'redirect_to' ) || null;
		}
		return this.lookup ? this.lookup( sel ) : null;
	}
	focus() {
		if ( this.doc ) {
			this.doc.activeElement = this;
		}
	}
}

function setup( opts ) {
	opts = opts || {};
	let now = 1000000;
	let seq = 0;
	const timers = [];
	const log = [];
	const fetches = [];
	const gets = [];
	const events = [];
	const signals = [];
	const replaced = [];
	const warns = [];

	const form = new El( 'form' );
	const redirectField = new El( 'input', { name: 'redirect_to' } );
	redirectField.name = 'redirect_to';
	redirectField.value = opts.formRedirect === undefined ? 'https://academy.test/lesson/3/' : opts.formRedirect;
	form.appendChild( redirectField );
	const input = new El( 'input', { autocomplete: 'username webauthn' } );
	input.form = form;
	const root = new El( 'div', Object.assign( { hidden: '' }, opts.rootAttrs || {} ) );
	const button = new El( 'button', { type: 'button', hidden: '' } );
	button.form = form;
	const status = new El( 'p' );
	const error = new El( 'p' );
	const body = new El( 'body' );
	const docListeners = {};
	// The default block sits inside the email form (login-form.php); opts.planted adds look-alike markup
	// elsewhere on the page that document.querySelector finds first.
	const block = {
		'[data-magicauth-passkey-root]': root,
		'[data-magicauth-passkey-signin]': button,
		'[data-magicauth-passkey-status]': status,
		'[data-magicauth-passkey-error]': error,
	};
	form.lookup = ( sel ) => ( opts.noBlock || opts.blockOutsideForm ? null : block[ sel ] || null );
	const plantedRoot = new El( 'div', { hidden: '', 'data-magicauth-redirect-to': 'https://academy.test/planted/' } );
	const plantedButton = new El( 'button', { type: 'button', hidden: '' } );
	const planted = {
		'[data-magicauth-passkey-root]': plantedRoot,
		'[data-magicauth-passkey-signin]': plantedButton,
		'[data-magicauth-passkey-status]': new El( 'p' ),
		'[data-magicauth-passkey-error]': new El( 'p' ),
	};

	const document = {
		readyState: 'complete',
		visibilityState: 'visible',
		activeElement: body,
		body,
		querySelector( sel ) {
			if ( opts.planted ) {
				return planted[ sel ] || null;
			}
			return ( opts.noBlock ? {} : block )[ sel ] || null;
		},
		querySelectorAll( sel ) {
			if ( sel === 'input[autocomplete~="webauthn"]' ) {
				return opts.inputs === undefined ? [ input ] : opts.inputs.map( () => input );
			}
			return [];
		},
		getElementById() { return null; },
		createElement( tag ) { return new El( tag ); },
		addEventListener( t, f ) { ( docListeners[ t ] = docListeners[ t ] || [] ).push( f ); },
		dispatchEvent( ev ) {
			events.push( ev );
			( docListeners[ ev.type ] || [] ).forEach( ( f ) => f( ev ) );
			return ! ev.defaultPrevented;
		},
		fire( t ) { ( docListeners[ t ] || [] ).forEach( ( f ) => f( { type: t } ) ); },
	};

	[ form, input, root, button, status, error, body, plantedButton ].forEach( ( el ) => {
		el.doc = document;
	} );

	Object.keys( opts.listen || {} ).forEach( ( type ) => document.addEventListener( type, opts.listen[ type ] ) );

	function later( fn, ms ) {
		timers.push( { fn, due: now + ms, id: timers.length + 1, live: true } );
	}

	const winListeners = {};
	const credentials = {
		get( options ) {
			const d = deferred();
			const call = { options, d, mediation: options.mediation };
			gets.push( call );
			log.push( 'get:' + ( options.mediation || 'modal' ) );
			if ( options.signal ) {
				// A real browser settles an aborted request later, not in the same task.
				const abort = () => later( () => {
					log.push( 'settled:' + ( options.mediation || 'modal' ) );
					d.reject( domError( 'AbortError' ) );
				}, ABORT_SETTLE_MS );
				if ( options.signal.aborted ) {
					abort();
				} else {
					options.signal.addEventListener( 'abort', abort );
				}
			}
			return d.promise;
		},
	};
	const PKC = {
		isConditionalMediationAvailable: async () => opts.conditional !== false,
		parseRequestOptionsFromJSON: ( json ) => Object.assign( { parsed: true }, json ),
		signalUnknownCredential: async ( o ) => { signals.push( o ); },
	};

	let responder = opts.responder || ( ( action ) => {
		if ( action === 'magicauth_passkey_signin_options' ) {
			return { status: 200, body: { success: true, data: { publicKey: { challenge: 'c' + ( ++seq ) }, refresh_after: 540, ttl: 600 } } };
		}
		return { status: 200, body: { success: true, data: { complete: 'TOKEN', redirect: 'https://academy.test/lesson/3/' } } };
	} );

	function fetch( url, init ) {
		const params = new URLSearchParams( String( init.body ) );
		const action = params.get( 'action' );
		const entry = { url, init, action, params };
		fetches.push( entry );
		log.push( 'fetch:' + action );
		const out = responder( action, entry );
		const answer = ( r ) => ( {
			status: r.status,
			headers: { get: () => ( r.type || 'application/json; charset=UTF-8' ) },
			json: async () => {
				if ( typeof r.body === 'string' ) {
					throw new SyntaxError( 'not json' );
				}
				return r.body;
			},
		} );
		if ( out && typeof out.then === 'function' ) {
			return out.then( answer );
		}
		return Promise.resolve( answer( out ) );
	}

	function FakeDate() {}
	FakeDate.now = () => now;

	class CustomEvent {
		constructor( type, init ) {
			this.type = type;
			this.detail = init && init.detail;
			this.cancelable = !! ( init && init.cancelable );
			this.defaultPrevented = false;
		}
		preventDefault() {
			if ( this.cancelable ) {
				this.defaultPrevented = true;
			}
		}
	}

	const location = { href: opts.href || 'https://academy.test/login/' };
	const sandbox = {
		document,
		navigator: { credentials },
		PublicKeyCredential: PKC,
		isSecureContext: opts.secure !== false,
		location,
		history: {
			state: null,
			replaceState( s, t, url ) { replaced.push( url ); location.href = url; },
		},
		console: { warn: ( ...a ) => warns.push( a ), error: ( ...a ) => warns.push( a ), log() {} },
		fetch,
		Date: FakeDate,
		setTimeout( fn, ms ) {
			const t = { fn, due: now + ( ms || 0 ), id: timers.length + 1, live: true };
			timers.push( t );
			return t.id;
		},
		clearTimeout( id ) { const t = timers[ id - 1 ]; if ( t ) { t.live = false; } },
		requestAnimationFrame( fn ) { Promise.resolve().then( fn ); },
		addEventListener( t, f ) { ( winListeners[ t ] = winListeners[ t ] || [] ).push( f ); },
		CustomEvent,
		AbortController,
		URL,
		URLSearchParams,
		DOMException,
		btoa,
		atob,
		Uint8Array,
		ArrayBuffer,
		JSON,
		Object,
		String,
		Math,
		Promise,
		Error,
		Set,
	};
	sandbox.window = sandbox;
	sandbox.magicauthPasskeysConfig = {
		ajaxUrl: 'https://academy.test/wp-admin/admin-ajax.php',
		rpId: 'academy.test',
		homeUrl: 'https://academy.test/',
		actions: { signinOptions: 'magicauth_passkey_signin_options', signin: 'magicauth_passkey_signin', complete: 'magicauth_passkey_complete' },
		i18n: L,
	};
	if ( opts.secure === false ) {
		sandbox.isSecureContext = false;
	}

	vm.createContext( sandbox );
	vm.runInContext( fs.readFileSync( path.join( dir, 'assets/js/magicauth-passkeys-core.js' ), 'utf8' ), sandbox );
	vm.runInContext( fs.readFileSync( path.join( dir, 'assets/js/magicauth-passkeys-login.js' ), 'utf8' ), sandbox );

	async function advance( ms ) {
		const end = now + ms;
		for ( ;; ) {
			await flush();
			const next = timers.filter( ( t ) => t.live && t.due <= end ).sort( ( a, b ) => a.due - b.due )[ 0 ];
			if ( ! next ) {
				break;
			}
			now = next.due;
			next.live = false;
			next.fn();
		}
		now = end;
		await flush();
	}

	const cred = ( id ) => ( { toJSON: () => ( { id: id || 'CRED', rawId: id || 'CRED', type: 'public-key', response: {} } ) } );

	return {
		input, root, button, status, error, body, form, document, plantedRoot, plantedButton, gets, fetches, events, signals, replaced, warns, log,
		advance, flush, cred,
		setNow( t ) { now = t; },
		now: () => now,
		setResponder( fn ) { responder = fn; },
		fireWindow( t, ev ) { ( winListeners[ t ] || [] ).forEach( ( f ) => f( ev || { type: t } ) ); },
		count( action ) { return fetches.filter( ( f ) => f.action === action ).length; },
		completion() { return body.children.find( ( c ) => c.tagName === 'FORM' ) || null; },
		async click() {
			button.fire( 'click', { type: 'click', preventDefault() {} } );
			await advance( ABORT_SETTLE_MS );
		},
	};
}

const ABORT_SETTLE_MS = 50;
const OPTIONS = 'magicauth_passkey_signin_options';
const SIGNIN = 'magicauth_passkey_signin';

const failed = ( code, extra ) => ( { status: code === 'retry' ? 503 : 400, body: { success: false, data: Object.assign( { code, message: 'server ' + code }, extra || {} ) } } );

const scenarios = {
	async init_shows_the_block_and_starts_autofill() {
		const t = setup();
		await t.flush();
		assert.strictEqual( t.root.hidden, false );
		assert.strictEqual( t.button.hidden, false );
		assert.strictEqual( t.count( OPTIONS ), 1 );
		assert.strictEqual( t.gets.length, 1 );
		assert.strictEqual( t.gets[ 0 ].mediation, 'conditional' );
		assert.strictEqual( t.gets[ 0 ].options.publicKey.challenge, 'c1' );
		const init = t.fetches[ 0 ].init;
		assert.strictEqual( init.method, 'POST' );
		assert.strictEqual( init.credentials, 'same-origin' );
		assert.strictEqual( init.cache, 'no-store' );
		assert.strictEqual( init.headers[ 'Content-Type' ], 'application/x-www-form-urlencoded' );
	},

	async no_g1_no_ui() {
		const t = setup( { secure: false } );
		await t.flush();
		assert.strictEqual( t.button.hidden, true );
		assert.strictEqual( t.root.hidden, true );
		assert.strictEqual( t.fetches.length, 0 );
	},

	async no_g4_no_autofill_but_the_button_works() {
		const t = setup( { conditional: false } );
		await t.flush();
		assert.strictEqual( t.button.hidden, false );
		assert.strictEqual( t.fetches.length, 0 );
		await t.click();
		assert.strictEqual( t.gets.length, 1 );
		assert.strictEqual( t.gets[ 0 ].mediation, undefined );
	},

	async several_webauthn_inputs_no_autofill() {
		const t = setup( { inputs: [ 1, 2 ] } );
		await t.flush();
		assert.strictEqual( t.fetches.length, 0 );
		assert.strictEqual( t.button.hidden, false );
	},

	async conditional_not_allowed_restarts_once_then_stops() {
		const t = setup();
		await t.flush();
		t.gets[ 0 ].d.reject( domError( 'NotAllowedError' ) );
		await t.flush();
		assert.strictEqual( t.count( OPTIONS ), 2, 'restarted once' );
		t.gets[ 1 ].d.reject( domError( 'NotAllowedError' ) );
		await t.flush();
		assert.strictEqual( t.count( OPTIONS ), 2, 'second failure stops autofill' );
		assert.strictEqual( t.gets.length, 2 );
		await t.advance( 3600 * 1000 );
		assert.strictEqual( t.count( OPTIONS ), 2, 'no refresh once stopped' );
		assert.strictEqual( t.error.textContent, '', 'nothing shown' );
	},

	async server_failure_restarts_once_then_stops() {
		const t = setup();
		t.setResponder( ( action ) => ( action === OPTIONS
			? { status: 200, body: { success: true, data: { publicKey: { challenge: 'x' }, refresh_after: 540, ttl: 600 } } }
			: failed( 'passkey_failed' ) ) );
		await t.flush();
		t.gets[ 0 ].d.resolve( t.cred() );
		await t.flush();
		assert.strictEqual( t.error.textContent, L.L3 );
		assert.strictEqual( t.count( OPTIONS ), 2 );
		t.gets[ 1 ].d.resolve( t.cred() );
		await t.flush();
		assert.strictEqual( t.count( SIGNIN ), 2 );
		assert.strictEqual( t.count( OPTIONS ), 2, 'stopped after the second server failure' );
	},

	async retry_restarts_once() {
		const t = setup();
		t.setResponder( ( action ) => ( action === OPTIONS
			? { status: 200, body: { success: true, data: { publicKey: { challenge: 'x' }, refresh_after: 540, ttl: 600 } } }
			: failed( 'retry' ) ) );
		await t.flush();
		t.gets[ 0 ].d.resolve( t.cred() );
		await t.flush();
		assert.strictEqual( t.error.textContent, L.L6 );
		assert.strictEqual( t.count( OPTIONS ), 2 );
	},

	async other_errors_stop_autofill() {
		const t = setup();
		await t.flush();
		t.gets[ 0 ].d.reject( domError( 'SecurityError' ) );
		await t.flush();
		assert.strictEqual( t.count( OPTIONS ), 1 );
		assert.strictEqual( t.warns.length, 1 );
		assert.strictEqual( t.button.hidden, false, 'the button still works' );
	},

	async a_planned_refresh_resets_the_budget() {
		const t = setup();
		await t.flush();
		t.gets[ 0 ].d.reject( domError( 'NotAllowedError' ) );
		await t.flush();
		assert.strictEqual( t.count( OPTIONS ), 2, 'budget spent' );
		await t.advance( 540 * 1000 );
		assert.strictEqual( t.count( OPTIONS ), 3, 'timer refresh' );
		t.gets[ 2 ].d.reject( domError( 'NotAllowedError' ) );
		await t.flush();
		assert.strictEqual( t.count( OPTIONS ), 4, 'fresh budget after a planned start' );
	},

	async expired_challenge_shows_l11_and_restarts_without_spending_the_budget() {
		const t = setup();
		await t.flush();
		t.setNow( t.now() + 595 * 1000 );
		t.gets[ 0 ].d.resolve( t.cred() );
		await t.flush();
		assert.strictEqual( t.count( SIGNIN ), 0, 'not posted' );
		assert.strictEqual( t.error.textContent, L.L11 );
		assert.strictEqual( t.count( OPTIONS ), 2, 'restarted' );
		t.gets[ 1 ].d.reject( domError( 'NotAllowedError' ) );
		await t.flush();
		assert.strictEqual( t.count( OPTIONS ), 3, 'the budget was still there' );
	},

	async just_inside_the_ttl_is_posted() {
		const t = setup();
		await t.flush();
		t.setNow( t.now() + 594 * 1000 );
		t.gets[ 0 ].d.resolve( t.cred() );
		await t.flush();
		assert.strictEqual( t.count( SIGNIN ), 1 );
	},

	async our_abort_is_silent() {
		const t = setup();
		await t.flush();
		t.fireWindow( 'pagehide' );
		await t.flush();
		assert.strictEqual( t.count( OPTIONS ), 1, 'no restart after our own abort' );
		assert.strictEqual( t.warns.length, 0 );
		assert.strictEqual( t.error.textContent, '' );
	},

	async bfcache_restore_restarts_autofill() {
		const t = setup();
		await t.flush();
		t.fireWindow( 'pagehide' );
		await t.flush();
		t.fireWindow( 'pageshow', { type: 'pageshow', persisted: true } );
		await t.flush();
		assert.strictEqual( t.count( OPTIONS ), 2 );
		assert.strictEqual( t.gets[ 1 ].mediation, 'conditional' );
	},

	async email_form_submit_stops_autofill() {
		const t = setup();
		await t.flush();
		t.form.fire( 'submit' );
		await t.flush();
		await t.advance( 3600 * 1000 );
		assert.strictEqual( t.count( OPTIONS ), 1 );
	},

	async idle_refreshes_stop_after_six_until_activity() {
		const t = setup();
		await t.flush();
		for ( let i = 0; i < 10; i++ ) {
			await t.advance( 540 * 1000 );
		}
		assert.strictEqual( t.count( OPTIONS ), 7, 'init plus six timer refreshes' );
		t.document.fire( 'visibilitychange' );
		await t.flush();
		assert.strictEqual( t.count( OPTIONS ), 8, 'visibility resets the cap and refreshes the stale challenge' );
	},

	async hidden_page_does_not_refresh() {
		const t = setup();
		await t.flush();
		t.document.visibilityState = 'hidden';
		await t.advance( 540 * 1000 );
		assert.strictEqual( t.count( OPTIONS ), 1 );
		t.document.visibilityState = 'visible';
		t.document.fire( 'visibilitychange' );
		await t.flush();
		assert.strictEqual( t.count( OPTIONS ), 2 );
	},

	async focused_input_refreshes_only_near_expiry() {
		const t = setup();
		await t.flush();
		t.document.activeElement = t.input;
		await t.advance( 540 * 1000 );
		assert.strictEqual( t.count( OPTIONS ), 1, 'the open autofill list is left alone' );
		await t.advance( 30 * 1000 );
		assert.strictEqual( t.count( OPTIONS ), 2, 'ttl - 30 s' );
	},

	async button_fetches_inside_the_gesture_and_settles_before_get() {
		const t = setup();
		await t.flush();
		t.log.length = 0;
		t.button.fire( 'click', { type: 'click', preventDefault() {} } );
		assert.deepStrictEqual( t.log, [ 'fetch:' + OPTIONS ], 'options fetch started synchronously in the click' );
		assert.strictEqual( t.button.getAttribute( 'aria-busy' ), 'true' );
		assert.strictEqual( t.button.getAttribute( 'aria-disabled' ), 'true' );
		await t.flush();
		assert.strictEqual( t.gets.filter( ( g ) => g.mediation === undefined ).length, 0, 'options are in, the conditional request is still settling' );
		await t.advance( ABORT_SETTLE_MS );
		const modal = t.gets.filter( ( g ) => g.mediation === undefined );
		assert.strictEqual( modal.length, 1, 'modal get after the conditional one settled' );
		assert.strictEqual( modal[ 0 ].options.signal, undefined );
		assert.strictEqual( modal[ 0 ].options.publicKey.challenge, 'c2' );
		assert.deepStrictEqual( t.log, [ 'fetch:' + OPTIONS, 'settled:conditional', 'get:modal' ] );
	},

	async button_success_submits_the_completion_form() {
		const t = setup();
		await t.flush();
		await t.click();
		const modal = t.gets.find( ( g ) => g.mediation === undefined );
		modal.d.resolve( t.cred( 'MINE' ) );
		await t.flush();
		const verify = t.fetches.find( ( f ) => f.action === SIGNIN );
		assert.strictEqual( JSON.parse( verify.params.get( 'credential' ) ).id, 'MINE' );
		assert.strictEqual( verify.params.get( 'redirect_to' ), 'https://academy.test/lesson/3/' );
		const form = t.completion();
		assert.ok( form, 'completion form appended' );
		assert.strictEqual( form.method, 'post' );
		assert.strictEqual( form.action, 'https://academy.test/wp-admin/admin-ajax.php' );
		assert.deepStrictEqual( form.submitted, {
			action: 'magicauth_passkey_complete',
			token: 'TOKEN',
			redirect_to: 'https://academy.test/lesson/3/',
			return_to: 'https://academy.test/login/',
		} );
		const success = t.events.find( ( e ) => e.type === 'magicauth:passkey:success' );
		assert.strictEqual( success.detail.redirect, 'https://academy.test/lesson/3/' );
		assert.strictEqual( success.cancelable, false );
		assert.strictEqual( t.status.textContent, L.L10 );
		await t.advance( 3600 * 1000 );
		assert.strictEqual( t.count( OPTIONS ), 2, 'no autofill restart while navigating' );
	},

	async conditional_success_submits_the_completion_form() {
		const t = setup();
		await t.flush();
		t.gets[ 0 ].d.resolve( t.cred() );
		await t.flush();
		assert.strictEqual( t.completion().submitted.token, 'TOKEN' );
	},

	async modal_not_allowed_shows_l3b_once() {
		const t = setup( { conditional: false } );
		await t.flush();
		await t.click();
		t.gets[ 0 ].d.reject( domError( 'NotAllowedError' ) );
		await t.flush();
		assert.strictEqual( t.error.textContent, L.L3 + ' ' + L.L3b );
		assert.strictEqual( t.button.hasAttribute( 'aria-disabled' ), false );
		await t.click();
		t.gets[ 1 ].d.reject( domError( 'NotAllowedError' ) );
		await t.flush();
		assert.strictEqual( t.error.textContent, L.L3 );
	},

	async modal_failure_restarts_autofill_without_spending_the_budget() {
		const t = setup();
		await t.flush();
		await t.click();
		const modal = t.gets.find( ( g ) => g.mediation === undefined );
		modal.d.reject( domError( 'NotAllowedError' ) );
		await t.flush();
		const conditional = t.gets.filter( ( g ) => g.mediation === 'conditional' );
		assert.strictEqual( conditional.length, 2, 'restarted after the button' );
		conditional[ 1 ].d.reject( domError( 'NotAllowedError' ) );
		await t.flush();
		assert.strictEqual( t.gets.filter( ( g ) => g.mediation === 'conditional' ).length, 3, 'budget still there' );
	},

	async operation_error_retries_once_silently() {
		const t = setup( { conditional: false } );
		await t.flush();
		await t.click();
		t.gets[ 0 ].d.reject( domError( 'OperationError' ) );
		await t.flush();
		assert.strictEqual( t.gets.length, 2, 'retried once' );
		assert.strictEqual( t.error.textContent, '' );
		t.gets[ 1 ].d.reject( domError( 'OperationError' ) );
		await t.flush();
		assert.strictEqual( t.gets.length, 2, 'only once' );
		assert.strictEqual( t.error.textContent, L.L3 );
	},

	async security_error_hides_the_button() {
		const t = setup( { conditional: false } );
		await t.flush();
		await t.click();
		t.gets[ 0 ].d.reject( domError( 'SecurityError' ) );
		await t.flush();
		assert.strictEqual( t.error.textContent, L.L7 );
		assert.strictEqual( t.button.hidden, true );
	},

	async unavailable_hides_the_button() {
		const t = setup( { conditional: false } );
		t.setResponder( () => ( { status: 404, body: { success: false, data: { code: 'unavailable', message: 'x' } } } ) );
		await t.flush();
		await t.click();
		assert.strictEqual( t.error.textContent, L.L7 );
		assert.strictEqual( t.button.hidden, true );
	},

	async throttled_button_is_suppressed_for_60_seconds() {
		const t = setup( { conditional: false } );
		t.setResponder( () => ( { status: 429, body: { success: false, data: { code: 'throttled', message: 'server' } } } ) );
		await t.flush();
		await t.click();
		assert.strictEqual( t.error.textContent, L.L4 );
		assert.strictEqual( t.button.getAttribute( 'aria-disabled' ), 'true' );
		assert.strictEqual( t.button.hasAttribute( 'disabled' ), false, 'focus stays on the button' );
		await t.click();
		assert.strictEqual( t.fetches.length, 1, 'clicks suppressed' );
		await t.advance( 59 * 1000 );
		assert.strictEqual( t.button.getAttribute( 'aria-disabled' ), 'true', 'still suppressed at 59 s' );
		await t.click();
		assert.strictEqual( t.fetches.length, 1, 'clicks still suppressed' );
		await t.advance( 1000 );
		assert.strictEqual( t.button.hasAttribute( 'aria-disabled' ), false );
		assert.strictEqual( t.status.textContent, L.L1, 're-enable announced' );
		await t.click();
		assert.strictEqual( t.fetches.length, 2 );
	},

	async throttled_with_retry_after_shows_the_server_message() {
		const t = setup( { conditional: false } );
		t.setResponder( () => ( { status: 429, body: { success: false, data: { code: 'throttled', message: 'Wait 3 minutes.', retry_after: 180 } } } ) );
		await t.flush();
		await t.click();
		assert.strictEqual( t.error.textContent, 'Wait 3 minutes.' );
	},

	async unexpected_response_is_l3_and_stops_autofill() {
		const t = setup();
		await t.flush();
		t.setResponder( ( action ) => ( action === OPTIONS
			? { status: 200, body: { success: true, data: { publicKey: { challenge: 'x' }, refresh_after: 540, ttl: 600 } } }
			: { status: 400, type: 'text/html', body: '0' } ) );
		await t.click();
		t.gets.find( ( g ) => g.mediation === undefined ).d.resolve( t.cred() );
		await t.flush();
		assert.strictEqual( t.error.textContent, L.L3 );
		assert.strictEqual( t.gets.filter( ( g ) => g.mediation === 'conditional' ).length, 1, 'autofill stopped' );
	},

	async network_error_is_l3() {
		const t = setup( { conditional: false } );
		t.setResponder( () => Promise.reject( new TypeError( 'offline' ) ) );
		await t.flush();
		await t.click();
		assert.strictEqual( t.error.textContent, L.L3 );
	},

	async unknown_credential_is_signalled() {
		const t = setup( { conditional: false } );
		t.setResponder( ( action ) => ( action === OPTIONS
			? { status: 200, body: { success: true, data: { publicKey: { challenge: 'x' }, refresh_after: 540, ttl: 600 } } }
			: failed( 'passkey_failed', { unknown_credential: true } ) ) );
		await t.flush();
		await t.click();
		t.gets[ 0 ].d.resolve( t.cred( 'GONE' ) );
		await t.flush();
		assert.deepStrictEqual( JSON.parse( JSON.stringify( t.signals ) ), [ { rpId: 'academy.test', credentialId: 'GONE' } ] );
		assert.strictEqual( t.error.textContent, L.L3 );
	},

	async no_signal_without_the_flag() {
		const t = setup( { conditional: false } );
		t.setResponder( ( action ) => ( action === OPTIONS
			? { status: 200, body: { success: true, data: { publicKey: { challenge: 'x' }, refresh_after: 540, ttl: 600 } } }
			: failed( 'passkey_failed' ) ) );
		await t.flush();
		await t.click();
		t.gets[ 0 ].d.resolve( t.cred() );
		await t.flush();
		assert.deepStrictEqual( t.signals, [] );
	},

	async other_account_and_reverify_messages() {
		for ( const [ code, text ] of [ [ 'other_account', L.L5 ], [ 'reverify_required', L.L8 ] ] ) {
			const t = setup( { conditional: false } );
			t.setResponder( ( action ) => ( action === OPTIONS
				? { status: 200, body: { success: true, data: { publicKey: { challenge: 'x' }, refresh_after: 540, ttl: 600 } } }
				: failed( code ) ) );
			await t.flush();
			await t.click();
			t.gets[ 0 ].d.resolve( t.cred() );
			await t.flush();
			assert.strictEqual( t.error.textContent, text, code );
		}
	},

	async return_error_is_shown_and_removed_from_the_url() {
		const t = setup( { href: 'https://academy.test/login/?x=1&magicauth_passkey_error=other_account#top' } );
		await t.flush();
		assert.strictEqual( t.error.textContent, L.L5 );
		assert.deepStrictEqual( t.replaced, [ 'https://academy.test/login/?x=1#top' ] );
	},

	async unknown_return_error_code_shows_l3() {
		const t = setup( { href: 'https://academy.test/login/?magicauth_passkey_error=%3Cb%3E' } );
		await t.flush();
		assert.strictEqual( t.error.textContent, L.L3 );
	},

	async theme_can_cancel_the_error_event() {
		const t = setup( {
			href: 'https://academy.test/login/?magicauth_passkey_error=retry',
			listen: { 'magicauth:passkey:error': ( e ) => e.preventDefault() },
		} );
		await t.flush();
		const ev = t.events.find( ( e ) => e.type === 'magicauth:passkey:error' );
		assert.strictEqual( ev.detail.code, 'retry' );
		assert.strictEqual( ev.detail.message, L.L6 );
		assert.strictEqual( t.error.textContent, '', 'the theme renders it' );
	},

	async redirect_to_prefers_the_data_attribute() {
		const t = setup( { conditional: false, rootAttrs: { 'data-magicauth-redirect-to': 'https://academy.test/wall-target/' } } );
		await t.flush();
		await t.click();
		t.gets[ 0 ].d.resolve( t.cred() );
		await t.flush();
		assert.strictEqual( t.fetches.find( ( f ) => f.action === SIGNIN ).params.get( 'redirect_to' ), 'https://academy.test/wall-target/' );
	},

	async redirect_to_falls_back_to_the_current_url() {
		const t = setup( { conditional: false, formRedirect: '', href: 'https://academy.test/courses/x/#part' } );
		await t.flush();
		await t.click();
		t.gets[ 0 ].d.resolve( t.cred() );
		await t.flush();
		assert.strictEqual( t.fetches.find( ( f ) => f.action === SIGNIN ).params.get( 'redirect_to' ), 'https://academy.test/courses/x/#part' );
	},

	async options_refused_at_load_stops_autofill_silently() {
		const t = setup();
		t.setResponder( () => ( { status: 429, body: { success: false, data: { code: 'throttled', message: 'x' } } } ) );
		await t.flush();
		assert.strictEqual( t.error.textContent, '', 'silent' );
		assert.strictEqual( t.gets.length, 0 );
		assert.strictEqual( t.button.hasAttribute( 'aria-disabled' ), false, 'the button still works' );
	},

	// r1-frontend-01: look-alike markup outside the form (post content above a shortcode form) is found first
	// by document.querySelector; the block inside the form of the webauthn input wins.
	async lookalike_block_outside_the_form_is_ignored() {
		const t = setup( { conditional: false, planted: true } );
		await t.flush();
		assert.strictEqual( t.button.hidden, false, 'the real button is shown' );
		assert.strictEqual( t.root.hidden, false );
		assert.strictEqual( t.plantedButton.hidden, true, 'the planted button stays hidden' );
		assert.strictEqual( t.plantedRoot.hidden, true );
		t.plantedButton.fire( 'click', { type: 'click', preventDefault() {} } );
		await t.flush();
		assert.strictEqual( t.fetches.length, 0, 'the planted button is not bound' );
		await t.click();
		t.gets[ 0 ].d.resolve( t.cred() );
		await t.flush();
		assert.strictEqual( t.fetches.find( ( f ) => f.action === SIGNIN ).params.get( 'redirect_to' ), 'https://academy.test/lesson/3/', 'no planted redirect target' );
		assert.strictEqual( t.completion().submitted.redirect_to, 'https://academy.test/lesson/3/' );
	},

	// r1-frontend-02: Back after the completion form (a wp_login interstitial) restores the page from the
	// back/forward cache: the button and autofill work again and the stale status goes.
	async bfcache_restore_after_completion_revives_the_button_and_autofill() {
		const t = setup();
		await t.flush();
		await t.click();
		t.gets.find( ( g ) => g.mediation === undefined ).d.resolve( t.cred() );
		await t.flush();
		assert.ok( t.completion(), 'completion submitted' );
		assert.strictEqual( t.status.textContent, L.L10 );
		t.fireWindow( 'pagehide' );
		t.fireWindow( 'pageshow', { type: 'pageshow', persisted: true } );
		await t.flush();
		assert.strictEqual( t.status.textContent, '', 'stale "Signed in" status cleared' );
		assert.strictEqual( t.button.hasAttribute( 'aria-disabled' ), false );
		assert.strictEqual( t.gets.filter( ( g ) => g.mediation === 'conditional' ).length, 2, 'autofill restarted' );
		const before = t.count( OPTIONS );
		await t.click();
		assert.strictEqual( t.count( OPTIONS ), before + 1, 'the button works again' );
		assert.strictEqual( t.gets.filter( ( g ) => g.mediation === undefined ).length, 2, 'a new modal ceremony' );
	},

	async bfcache_restore_after_an_email_submit_restarts_autofill() {
		const t = setup();
		await t.flush();
		t.form.fire( 'submit' );
		t.fireWindow( 'pagehide' );
		t.fireWindow( 'pageshow', { type: 'pageshow', persisted: true } );
		await t.flush();
		assert.strictEqual( t.count( OPTIONS ), 2 );
		assert.strictEqual( t.gets[ 1 ].mediation, 'conditional' );
	},

	async bfcache_restore_without_an_autofill_input_revives_the_button() {
		const t = setup( { inputs: [] } );
		await t.flush();
		await t.click();
		t.gets[ 0 ].d.resolve( t.cred() );
		await t.flush();
		assert.ok( t.completion() );
		t.fireWindow( 'pageshow', { type: 'pageshow', persisted: true } );
		await t.flush();
		await t.click();
		assert.strictEqual( t.gets.length, 2, 'the button starts a new ceremony' );
	},

	// r1-frontend-03: a click while an autofill pick is being verified opens no second ceremony.
	async click_during_a_conditional_verify_is_ignored() {
		const t = setup();
		const verify = deferred();
		t.setResponder( ( action ) => {
			if ( action === SIGNIN ) {
				return verify.promise;
			}
			return { status: 200, body: { success: true, data: { publicKey: { challenge: 'c' }, refresh_after: 540, ttl: 600 } } };
		} );
		await t.flush();
		t.gets[ 0 ].d.resolve( t.cred() );
		await t.flush();
		assert.strictEqual( t.count( SIGNIN ), 1, 'verifying the pick' );
		assert.strictEqual( t.button.getAttribute( 'aria-busy' ), 'true' );
		await t.click();
		verify.resolve( { status: 200, body: { success: true, data: { complete: 'TOKEN', redirect: 'https://academy.test/' } } } );
		await t.advance( 1000 );
		assert.strictEqual( t.gets.filter( ( g ) => g.mediation === undefined ).length, 0, 'no modal ceremony' );
		assert.strictEqual( t.count( SIGNIN ), 1 );
		assert.strictEqual( t.body.children.filter( ( c ) => c.tagName === 'FORM' ).length, 1, 'one completion' );
	},

	// The pick lands after the click started (the click's abort comes too late): the click stops after
	// the conditional request settled instead of opening a modal ceremony during the navigation.
	async click_racing_a_conditional_pick_stops_after_it_settled() {
		const t = setup();
		await t.flush();
		t.button.fire( 'click', { type: 'click', preventDefault() {} } );
		t.gets[ 0 ].d.resolve( t.cred() );
		await t.advance( 1000 );
		assert.strictEqual( t.count( SIGNIN ), 1 );
		assert.strictEqual( t.gets.filter( ( g ) => g.mediation === undefined ).length, 0, 'no modal ceremony' );
		assert.strictEqual( t.body.children.filter( ( c ) => c.tagName === 'FORM' ).length, 1, 'one completion' );
	},

	// r1-frontend-06: hiding the focused button hands focus to the email input, not the body.
	async hiding_the_focused_button_moves_focus_to_the_email_input() {
		const t = setup( { conditional: false } );
		await t.flush();
		t.button.focus();
		await t.click();
		t.gets[ 0 ].d.reject( domError( 'SecurityError' ) );
		await t.flush();
		assert.strictEqual( t.button.hidden, true );
		assert.strictEqual( t.document.activeElement, t.input );

		const u = setup( { conditional: false, inputs: [] } );
		u.setResponder( () => ( { status: 404, body: { success: false, data: { code: 'unavailable', message: 'x' } } } ) );
		await u.flush();
		u.button.focus();
		await u.click();
		assert.strictEqual( u.button.hidden, true );
		assert.strictEqual( u.document.activeElement, u.error, 'no input: the error region' );
		assert.strictEqual( u.error.getAttribute( 'tabindex' ), '-1' );
	},
};

( async () => {
	if ( scenario === '--list' ) {
		process.stdout.write( Object.keys( scenarios ).join( '\n' ) + '\n' );
		return;
	}
	const run = scenarios[ scenario ];
	if ( ! run ) {
		process.stdout.write( 'unknown scenario: ' + scenario + '\n' );
		process.exit( 1 );
	}
	try {
		await run();
		process.stdout.write( 'ok\n' );
	} catch ( e ) {
		process.stdout.write( ( e && e.stack ) || String( e ) );
		process.exit( 1 );
	}
} )();
