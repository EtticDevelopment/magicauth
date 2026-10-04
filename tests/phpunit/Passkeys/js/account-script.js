// Runs assets/js/magicauth-passkeys-core.js and -account.js against a small DOM built from the markup the
// PHP templates rendered (prompt dialog, management section), a fake fetch, navigator.credentials and
// localStorage, then checks one scenario of SPEC 2.1 / 2.3 / 3.5 / 8.6 / 8.7 / 8.11 / 8.12.
// Usage: node account-script.js <plugin dir> <scenario> <fixture.json | inline script>. Prints "ok" or the
// failure; exit 0 / 1. "--list" prints the scenario names.
'use strict';

const fs = require( 'fs' );
const path = require( 'path' );
const vm = require( 'vm' );
const assert = require( 'assert' );

const dir = process.argv[ 2 ];
const scenario = process.argv[ 3 ];
const fixturePath = process.argv[ 4 ];

const DAY = 86400000;

function flush() {
	let p = Promise.resolve();
	for ( let i = 0; i < 40; i++ ) {
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

/* ------------------------------------------------------------------ a small DOM */

const VOID = new Set( [ 'input', 'br', 'img', 'meta', 'link', 'hr' ] );
const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", times: '×', nbsp: ' ' };

function decode( s ) {
	return s.replace( /&(#x?[0-9a-f]+|[a-z]+);/gi, ( m, e ) => {
		if ( e[ 0 ] === '#' ) {
			return String.fromCodePoint( e[ 1 ] === 'x' || e[ 1 ] === 'X' ? parseInt( e.slice( 2 ), 16 ) : parseInt( e.slice( 1 ), 10 ) );
		}
		return e in ENTITIES ? ENTITIES[ e ] : m;
	} );
}

// Compound selector: tag, #id, .class, [attr], [attr="v"]; groups by comma; descendants by space.
function parseSelector( sel ) {
	return sel.split( ',' ).map( ( group ) => group.trim().split( /\s+(?![^[]*\])/ ).map( ( part ) => {
		const c = { tag: null, attrs: [], classes: [] };
		const re = /^([a-zA-Z][a-zA-Z0-9-]*)|\.([\w-]+)|#([\w-]+)|\[([\w-]+)(?:="([^"]*)")?\]/g;
		let m;
		let consumed = 0;
		while ( ( m = re.exec( part ) ) !== null ) {
			if ( m.index !== consumed ) {
				break;
			}
			consumed = re.lastIndex;
			if ( m[ 1 ] ) {
				c.tag = m[ 1 ].toUpperCase();
			} else if ( m[ 2 ] ) {
				c.classes.push( m[ 2 ] );
			} else if ( m[ 3 ] ) {
				c.attrs.push( [ 'id', m[ 3 ] ] );
			} else {
				c.attrs.push( [ m[ 4 ], m[ 5 ] === undefined ? null : m[ 5 ] ] );
			}
		}
		if ( consumed !== part.length ) {
			throw new Error( 'selector not supported: ' + sel );
		}
		return c;
	} ) );
}

function matchCompound( el, c ) {
	if ( ! el || el.nodeType !== 1 ) {
		return false;
	}
	if ( c.tag && el.tagName !== c.tag ) {
		return false;
	}
	for ( const cls of c.classes ) {
		if ( ( ' ' + ( el.getAttribute( 'class' ) || '' ) + ' ' ).indexOf( ' ' + cls + ' ' ) < 0 ) {
			return false;
		}
	}
	for ( const [ name, value ] of c.attrs ) {
		if ( ! el.hasAttribute( name ) ) {
			return false;
		}
		if ( value !== null && el.getAttribute( name ) !== value ) {
			return false;
		}
	}
	return true;
}

function matches( el, groups ) {
	return groups.some( ( chain ) => {
		if ( ! matchCompound( el, chain[ chain.length - 1 ] ) ) {
			return false;
		}
		let i = chain.length - 2;
		let node = el.parentNode;
		while ( i >= 0 && node ) {
			if ( matchCompound( node, chain[ i ] ) ) {
				i--;
			}
			node = node.parentNode;
		}
		return i < 0;
	} );
}

class Text {
	constructor( text ) {
		this.nodeType = 3;
		this.data = text;
		this.parentNode = null;
	}
	get textContent() { return this.data; }
}

class El {
	constructor( doc, tag, attrs ) {
		this.nodeType = 1;
		this.ownerDocument = doc;
		this.tagName = tag.toUpperCase();
		this.attrs = Object.assign( {}, attrs || {} );
		this.childNodes = [];
		this.parentNode = null;
		this.listeners = {};
		this.value = 'value' in this.attrs ? this.attrs.value : '';
		this.checked = 'checked' in this.attrs;
		this.maxLength = -1;
		this.focusCount = 0;
	}
	get children() { return this.childNodes.filter( ( n ) => n.nodeType === 1 ); }
	get hidden() { return 'hidden' in this.attrs; }
	set hidden( v ) { if ( v ) { this.attrs.hidden = ''; } else { delete this.attrs.hidden; } }
	get open() { return 'open' in this.attrs; }
	get type() { return this.attrs.type || ( this.tagName === 'BUTTON' ? 'submit' : '' ); }
	set type( v ) { this.attrs.type = String( v ); }
	get id() { return this.attrs.id || ''; }
	set id( v ) { this.attrs.id = String( v ); }
	get className() { return this.attrs.class || ''; }
	set className( v ) { this.attrs.class = String( v ); }
	get textContent() { return this.childNodes.map( ( n ) => n.textContent ).join( '' ); }
	set textContent( v ) {
		this.childNodes.forEach( ( n ) => { n.parentNode = null; } );
		this.childNodes = [];
		if ( v !== '' && v !== null && v !== undefined ) {
			this.appendChild( new Text( String( v ) ) );
		}
	}
	setAttribute( k, v ) { this.attrs[ k ] = String( v ); }
	getAttribute( k ) { return k in this.attrs ? this.attrs[ k ] : null; }
	hasAttribute( k ) { return k in this.attrs; }
	removeAttribute( k ) { delete this.attrs[ k ]; }
	appendChild( c ) {
		if ( c.parentNode ) {
			c.parentNode.childNodes = c.parentNode.childNodes.filter( ( n ) => n !== c );
		}
		c.parentNode = this;
		this.childNodes.push( c );
		return c;
	}
	remove() {
		if ( this.parentNode ) {
			this.parentNode.childNodes = this.parentNode.childNodes.filter( ( n ) => n !== this );
			this.parentNode = null;
		}
	}
	contains( other ) {
		for ( let n = other; n; n = n.parentNode ) {
			if ( n === this ) {
				return true;
			}
		}
		return false;
	}
	descendants() {
		const out = [];
		const walk = ( node ) => node.children.forEach( ( c ) => { out.push( c ); walk( c ); } );
		walk( this );
		return out;
	}
	querySelectorAll( sel ) {
		const groups = parseSelector( sel );
		return this.descendants().filter( ( el ) => matches( el, groups ) );
	}
	querySelector( sel ) { return this.querySelectorAll( sel )[ 0 ] || null; }
	matches( sel ) { return matches( this, parseSelector( sel ) ); }
	closest( sel ) {
		const groups = parseSelector( sel );
		for ( let n = this; n && n.nodeType === 1; n = n.parentNode ) {
			if ( matches( n, groups ) ) {
				return n;
			}
		}
		return null;
	}
	addEventListener( t, f ) { ( this.listeners[ t ] = this.listeners[ t ] || [] ).push( f ); }
	removeEventListener( t, f ) { this.listeners[ t ] = ( this.listeners[ t ] || [] ).filter( ( g ) => g !== f ); }
	// Dispatches on this element and, when bubbles, on its ancestors and the document.
	dispatch( type, extra, bubbles ) {
		const ev = Object.assign( {
			type,
			target: this,
			defaultPrevented: false,
			preventDefault() { this.defaultPrevented = true; },
		}, extra || {} );
		for ( let n = this; n; n = bubbles ? n.parentNode : null ) {
			ev.currentTarget = n;
			( n.listeners[ type ] || [] ).slice().forEach( ( f ) => f( ev ) );
			if ( ! bubbles ) {
				break;
			}
		}
		if ( bubbles ) {
			this.ownerDocument.fireDoc( ev );
		}
		return ev;
	}
	click() {
		if ( this.tagName === 'BUTTON' && this.type === 'submit' ) {
			const form = this.closest( 'form' );
			const ev = this.dispatch( 'click', {}, true );
			if ( form && ! ev.defaultPrevented ) {
				form.dispatch( 'submit', {}, true );
			}
			return;
		}
		this.dispatch( 'click', {}, true );
	}
	key( k ) { return this.dispatch( 'keydown', { key: k }, true ); }
	focus() {
		this.focusCount++;
		this.ownerDocument.activeElement = this;
	}
	showModal() {
		if ( this.open ) {
			throw domError( 'InvalidStateError' );
		}
		this.attrs.open = '';
		this.ownerDocument.log.push( 'showModal:' + ( this.getAttribute( 'data-magicauth-pk-prompt' ) !== null ? 'prompt' : 'dialog' ) );
	}
	close() {
		if ( ! this.open ) {
			return;
		}
		delete this.attrs.open;
		// The close event is queued as a task, as in browsers.
		setImmediate( () => this.dispatch( 'close', {}, false ) );
	}
}

function parseInto( doc, parent, html ) {
	const re = /<!--[\s\S]*?-->|<\/([a-zA-Z][\w-]*)\s*>|<([a-zA-Z][\w-]*)((?:\s+[^\s=>/]+(?:\s*=\s*"[^"]*")?)*)\s*(\/?)>|([^<]+)/g;
	const stack = [ parent ];
	let m;
	while ( ( m = re.exec( html ) ) !== null ) {
		const top = stack[ stack.length - 1 ];
		if ( m[ 1 ] ) {
			const tag = m[ 1 ].toUpperCase();
			while ( stack.length > 1 && stack[ stack.length - 1 ].tagName !== tag ) {
				stack.pop();
			}
			if ( stack.length > 1 ) {
				stack.pop();
			}
		} else if ( m[ 2 ] ) {
			const attrs = {};
			const are = /([^\s=/]+)(?:\s*=\s*"([^"]*)")?/g;
			let a;
			while ( ( a = are.exec( m[ 3 ] || '' ) ) !== null ) {
				attrs[ a[ 1 ] ] = a[ 2 ] === undefined ? '' : decode( a[ 2 ] );
			}
			const el = new El( doc, m[ 2 ], attrs );
			top.appendChild( el );
			if ( ! VOID.has( m[ 2 ].toLowerCase() ) && ! m[ 4 ] ) {
				stack.push( el );
			}
		} else if ( m[ 5 ] ) {
			if ( m[ 5 ].trim() !== '' ) {
				top.appendChild( new Text( decode( m[ 5 ] ) ) );
			}
		}
	}
}

/* ------------------------------------------------------------------ one page */

const fixture = fixturePath && /\.json$/.test( fixturePath ) ? JSON.parse( fs.readFileSync( fixturePath, 'utf8' ) ) : null;

// opts: { page: 'prompt' | 'manage' | 'profile' | 'none', before: html, config: overrides, caps, uvpa, secure, storage, storageThrows, responder }
function setup( opts ) {
	opts = opts || {};
	const page = opts.page || 'prompt';
	const fetches = [];
	const creates = [];
	const gets = [];
	const signals = [];
	const warns = [];
	const reloads = [];
	const docListeners = {};
	const winListeners = {};

	const document = {
		readyState: 'complete',
		activeElement: null,
		log: [],
		events: [],
		addEventListener( t, f ) { ( docListeners[ t ] = docListeners[ t ] || [] ).push( f ); },
		fireDoc( ev ) { ( docListeners[ ev.type ] || [] ).slice().forEach( ( f ) => f( ev ) ); },
		dispatchEvent( ev ) {
			this.events.push( ev );
			this.fireDoc( ev );
			return ! ev.defaultPrevented;
		},
		createElement( tag ) { return new El( document, tag ); },
		createTextNode( text ) { return new Text( text ); },
		querySelector( sel ) { return document.body.querySelector( sel ); },
		querySelectorAll( sel ) { return document.body.querySelectorAll( sel ); },
	};
	document.body = new El( document, 'body' );
	const opener = new El( document, 'a', { href: '/lesson/' } );
	document.body.appendChild( opener );
	opener.focus();
	if ( opts.before ) {
		parseInto( document, document.body, opts.before ); // Look-alike markup earlier on the page (post content).
	}
	if ( page !== 'none' ) {
		parseInto( document, document.body, fixture[ page ].html );
	}

	const store = new Map( Object.entries( opts.storage || {} ) );
	const localStorage = {
		getItem( k ) {
			if ( opts.storageThrows ) {
				throw domError( 'SecurityError' );
			}
			return store.has( k ) ? store.get( k ) : null;
		},
		setItem( k, v ) {
			if ( opts.storageThrows ) {
				throw domError( 'SecurityError' );
			}
			store.set( k, String( v ) );
		},
	};

	let createImpl = opts.create || ( () => Promise.resolve( cred( 'NEWCRED' ) ) );
	const credentials = {
		create( options ) {
			creates.push( options );
			return createImpl( options );
		},
		get( options ) {
			gets.push( options );
			return Promise.resolve( cred( 'OLDCRED' ) );
		},
	};
	const PKC = {
		parseCreationOptionsFromJSON: ( json ) => Object.assign( { parsed: true }, json ),
		parseRequestOptionsFromJSON: ( json ) => Object.assign( { parsed: true }, json ),
	};
	[ 'signalAllAcceptedCredentials', 'signalCurrentUserDetails', 'signalUnknownCredential' ].forEach( ( name ) => {
		PKC[ name ] = async ( o ) => { signals.push( [ name, o ] ); };
	} );
	if ( opts.caps !== undefined ) {
		PKC.getClientCapabilities = opts.caps === 'reject' ? async () => { throw domError( 'NotSupportedError' ); } : async () => opts.caps;
	}
	if ( opts.uvpa !== undefined ) {
		PKC.isUserVerifyingPlatformAuthenticatorAvailable = async () => opts.uvpa;
	}

	const ok = ( data ) => ( { status: 200, body: { success: true, data: data || {} } } );
	const passkeys = [ { id: 5, name: 'Laptop', label: 'Passkey ending in ABCD', provider: null, synced: true, sync_possible: true, device_bound: false, created: '2026-10-02T10:00:00Z', created_label: 'Added today', last_used: null, last_used_label: null, usable_here: true, blocked: false, is_new: true, credential_id: 'NEWCRED' } ];
	const signal = { rpId: 'academy.example.com', userId: 'HANDLE', allAccepted: [ 'NEWCRED' ], name: 'learner7@example.test', displayName: 'Learner 7', details: false };
	let responder = opts.responder || ( ( action ) => {
		switch ( action ) {
			case 'magicauth_passkey_register_options':
				return ok( { publicKey: { challenge: 'Y2hhbGxlbmdl', user: { id: 'SEFORExF', name: 'x', displayName: 'x' } } } );
			case 'magicauth_passkey_register':
				return ok( { passkey: passkeys[ 0 ], passkeys, signal } );
			default:
				return ok( {} );
		}
	} );
	function fetch( url, init ) {
		const params = new URLSearchParams( String( init.body ) );
		const entry = { url, init, action: params.get( 'action' ), params };
		fetches.push( entry );
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
		const out = responder( entry.action, entry );
		return out && typeof out.then === 'function' ? out.then( answer ) : Promise.resolve( answer( out ) );
	}

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

	const config = JSON.parse( JSON.stringify( page === 'none' ? ( fixture ? fixture.prompt.config : {} ) : fixture[ page ].config ) );
	Object.assign( config, opts.config || {} );

	const sandbox = {
		document,
		navigator: { credentials, platform: 'MacIntel', maxTouchPoints: 0 },
		PublicKeyCredential: PKC,
		isSecureContext: opts.secure !== false,
		location: { reload() { reloads.push( 1 ); } },
		localStorage,
		console: { warn: ( ...a ) => warns.push( a ), error: ( ...a ) => warns.push( a ), log() {} },
		fetch,
		setTimeout,
		clearTimeout,
		addEventListener( t, f ) { ( winListeners[ t ] = winListeners[ t ] || [] ).push( f ); },
		CustomEvent,
		URLSearchParams,
		DOMException,
		btoa,
		atob,
		Uint8Array,
		ArrayBuffer,
		JSON,
		Object,
		Array,
		String,
		Math,
		Promise,
		Error,
		Date,
		Set,
		Map,
		TextEncoder,
		crypto: globalThis.crypto || require( 'crypto' ).webcrypto, // Node 18 has no global.
		magicauthPasskeysConfig: config,
	};
	sandbox.window = sandbox;
	vm.createContext( sandbox );
	vm.runInContext( fs.readFileSync( path.join( dir, 'assets/js/magicauth-passkeys-core.js' ), 'utf8' ), sandbox );
	if ( opts.inline ) {
		vm.runInContext( opts.inline, sandbox );
	} else {
		vm.runInContext( fs.readFileSync( path.join( dir, 'assets/js/magicauth-passkeys-account.js' ), 'utf8' ), sandbox );
	}

	const q = ( sel ) => document.querySelector( sel );
	const t = {
		document, fetches, creates, gets, signals, warns, reloads, store, opener, passkeys, signal,
		q,
		// The config the scripts saw (an inline script sets its own).
		get config() { return sandbox.magicauthPasskeysConfig; },
		dlg: q( '[data-magicauth-pk-prompt]' ),
		view( name ) { return q( '[data-magicauth-pk-prompt] [data-magicauth-pk-view="' + name + '"]' ); },
		visibleViews() {
			return [ 'offer', 'reauth', 'success', 'error' ].filter( ( v ) => t.view( v ) && ! t.view( v ).hidden );
		},
		p4() { return t.view( 'offer' ).querySelector( '[data-magicauth-pk-create]' ); },
		actions() { return fetches.map( ( f ) => f.action ); },
		choices() { return fetches.filter( ( f ) => f.action === 'magicauth_passkey_prompt' ).map( ( f ) => f.params.get( 'choice' ) ); },
		entry() {
			const map = JSON.parse( store.get( 'magicauth:pk:acct' ) || '{}' );
			return map[ config.account.key ] || null;
		},
		setResponder( fn ) { responder = fn; },
		setCreate( fn ) { createImpl = fn; },
		fireWindow( type, ev ) { ( winListeners[ type ] || [] ).forEach( ( f ) => f( ev ) ); },
		flush,
	};
	return t;
}

// Objects made inside the vm context have its prototypes: compare as JSON.
function plain( v ) {
	return JSON.parse( JSON.stringify( v ) );
}

function cred( id ) {
	return { id, toJSON: () => ( { id, rawId: id, type: 'public-key', response: {}, clientExtensionResults: {} } ) };
}

const fail = ( code, status, extra ) => ( { status: status || 400, body: { success: false, data: Object.assign( { code, message: 'server ' + code }, extra || {} ) } } );
const SHOW = { caps: { passkeyPlatformAuthenticator: true } };

async function opened( opts ) {
	const t = setup( Object.assign( {}, SHOW, opts || {} ) );
	await flush();
	assert.ok( t.dlg.open, 'the prompt is open' );
	return t;
}

/* ------------------------------------------------------------------ scenarios */

const scenarios = {
	async gate_opens_the_closed_dialog_and_focuses_the_heading() {
		const t = setup( SHOW );
		assert.strictEqual( t.dlg.open, false, 'closed until the gate passed' );
		await flush();
		assert.strictEqual( t.dlg.open, true );
		assert.deepStrictEqual( t.document.log, [ 'showModal:prompt' ] );
		assert.strictEqual( t.document.activeElement, t.q( '[data-magicauth-pk-title]' ) );
		assert.deepStrictEqual( t.visibleViews(), [ 'offer' ] );
		assert.deepStrictEqual( t.fetches, [], 'nothing sent on open' );
	},

	async gate_fails_without_g1_create_or_prompt_show() {
		for ( const opts of [ { secure: false }, { config: { prompt: { show: false, hasPasskeys: false } } } ] ) {
			const t = setup( Object.assign( {}, SHOW, opts ) );
			await flush();
			assert.strictEqual( t.dlg.open, false, JSON.stringify( opts ) );
			assert.deepStrictEqual( t.fetches, [], 'nothing sent, cadence untouched' );
		}
		const t = setup( SHOW );
		await flush();
		assert.strictEqual( t.dlg.open, true, 'control' );
	},

	async gate_shared_device_flag_suppresses() {
		const t = setup( Object.assign( { storage: { 'magicauth:pk:noprompt': '1' } }, SHOW ) );
		await flush();
		assert.strictEqual( t.dlg.open, false );
		assert.deepStrictEqual( t.fetches, [] );
	},

	async gate_throwing_storage_counts_as_absent() {
		const t = setup( Object.assign( { storageThrows: true }, SHOW ) );
		await flush();
		assert.strictEqual( t.dlg.open, true );
	},

	async gate_promptfail_30_days_and_haslocal_90_days() {
		const key = fixture.prompt.config.account.key;
		const cases = [
			[ { promptfail: Date.now() - 29 * DAY }, false ],
			[ { promptfail: Date.now() - 31 * DAY }, true ],
			[ { haslocal: Date.now() - 89 * DAY }, false ],
			[ { haslocal: Date.now() - 91 * DAY }, true ],
			[ { haslocal: 'yesterday' }, true ],
		];
		for ( const [ mine, shown ] of cases ) {
			const map = { [ key ]: mine, otheraccountkey0: { haslocal: Date.now() } };
			const t = setup( Object.assign( { storage: { 'magicauth:pk:acct': JSON.stringify( map ) } }, SHOW ) );
			await flush();
			assert.strictEqual( t.dlg.open, shown, JSON.stringify( mine ) );
		}
	},

	async gate_g3_capabilities_then_uvpa() {
		const cases = [
			[ { caps: { hybridTransport: true }, uvpa: false }, true ],
			[ { caps: { passkeyPlatformAuthenticator: false, userVerifyingPlatformAuthenticator: false, hybridTransport: false }, uvpa: true }, false ],
			[ { caps: {}, uvpa: true }, true ],
			[ { caps: {}, uvpa: false }, false ],
			[ { caps: 'reject', uvpa: true }, true ],
			[ { caps: { passkeyPlatformAuthenticator: false }, uvpa: true }, true ],
			[ { uvpa: true }, true ],
			[ {}, false ],
		];
		for ( const [ opts, shown ] of cases ) {
			const t = setup( opts );
			await flush();
			assert.strictEqual( t.dlg.open, shown, JSON.stringify( opts ) );
		}
	},

	async not_now_records_later_once_and_returns_focus() {
		const t = await opened();
		t.view( 'offer' ).querySelector( '[data-magicauth-pk-later]' ).click();
		await flush();
		assert.strictEqual( t.dlg.open, false );
		assert.deepStrictEqual( t.choices(), [ 'later' ], 'the close event adds no dismiss' );
		const post = t.fetches[ 0 ];
		assert.strictEqual( post.params.get( '_ajax_nonce' ), t.config.nonce );
		assert.strictEqual( post.init.credentials, 'same-origin' );
		assert.strictEqual( t.document.activeElement, t.opener, 'focus back where it was' );
	},

	async close_button_and_escape_dismiss() {
		let t = await opened();
		t.q( '[data-magicauth-pk-close]' ).click();
		await flush();
		assert.deepStrictEqual( t.choices(), [ 'dismiss' ] );

		t = await opened();
		t.dlg.close(); // Esc and the back gesture close the dialog.
		await flush();
		assert.deepStrictEqual( t.choices(), [ 'dismiss' ] );
		assert.strictEqual( t.q( '[data-magicauth-pk-close]' ).getAttribute( 'type' ), 'button' );
	},

	async shared_device_marks_the_browser_and_sends_device() {
		const t = await opened();
		t.q( '[data-magicauth-pk-shared]' ).click();
		await flush();
		assert.strictEqual( t.store.get( 'magicauth:pk:noprompt' ), '1' );
		assert.deepStrictEqual( t.choices(), [ 'device' ] );
		assert.strictEqual( t.dlg.open, false );
	},

	async create_success_shows_success_stamps_haslocal_and_signals() {
		const t = await opened( { config: { signals: null } } );
		t.p4().click();
		await flush();
		assert.deepStrictEqual( t.actions(), [ 'magicauth_passkey_register_options', 'magicauth_passkey_register' ] );
		assert.strictEqual( t.creates.length, 1 );
		assert.strictEqual( t.creates[ 0 ].publicKey.parsed, true, 'parseCreationOptionsFromJSON' );
		assert.strictEqual( t.creates[ 0 ].mediation, undefined, 'never conditional' );
		const reg = t.fetches[ 1 ].params;
		assert.strictEqual( JSON.parse( reg.get( 'credential' ) ).id, 'NEWCRED' );
		assert.strictEqual( reg.get( 'platform' ), 'Mac' );
		assert.deepStrictEqual( t.visibleViews(), [ 'success' ] );
		const success = t.q( '[data-magicauth-pk-success]' );
		assert.strictEqual( t.document.activeElement, success );
		await new Promise( ( r ) => setTimeout( r, 5 ) ); // Live regions are written on the next frame.
		assert.strictEqual( t.q( '[data-magicauth-pk-prompt] [data-magicauth-pk-status]' ).textContent, success.textContent );
		assert.ok( typeof t.entry().haslocal === 'number', 'haslocal for this account' );
		assert.deepStrictEqual( plain( t.signals ), [ [ 'signalAllAcceptedCredentials', { rpId: t.signal.rpId, userId: 'HANDLE', allAcceptedCredentialIds: [ 'NEWCRED' ] } ] ], 'the returned list only' );
		assert.strictEqual( t.p4().hasAttribute( 'aria-busy' ), false );
		t.q( '[data-magicauth-pk-done]' ).click();
		await flush();
		assert.strictEqual( t.dlg.open, false );
		assert.deepStrictEqual( t.choices(), [], 'a created passkey is the choice' );
	},

	async create_busy_label_and_ignored_second_click() {
		const t = await opened();
		const gate = deferred();
		t.setResponder( ( action ) => ( action === 'magicauth_passkey_register_options' ? gate.promise.then( () => ( { status: 200, body: { success: true, data: { publicKey: { challenge: 'Yw', user: { id: 'SA' } } } } } ) ) : { status: 200, body: { success: true, data: { passkeys: [], signal: null } } } ) );
		const p4 = t.p4();
		const label = p4.textContent;
		p4.click();
		await flush();
		assert.strictEqual( p4.textContent, t.config.i18n.P7, 'label P7 while running' );
		assert.strictEqual( p4.getAttribute( 'aria-disabled' ), 'true' );
		assert.strictEqual( p4.getAttribute( 'aria-busy' ), 'true' );
		assert.strictEqual( t.document.activeElement, t.q( '[data-magicauth-pk-title]' ), 'focus not moved' );
		p4.click();
		await flush();
		assert.strictEqual( t.actions().length, 1, 'one register_options' );
		gate.resolve();
		await flush();
		assert.strictEqual( p4.textContent, label );
		assert.strictEqual( p4.hasAttribute( 'aria-disabled' ), false );
		assert.strictEqual( t.creates.length, 1 );
	},

	async not_allowed_shows_p10_p10b_sets_promptfail_and_not_now_sends_failed() {
		const t = await opened( { create: () => Promise.reject( domError( 'NotAllowedError' ) ) } );
		t.p4().click();
		await flush();
		assert.deepStrictEqual( t.actions(), [ 'magicauth_passkey_register_options' ], 'no register' );
		assert.deepStrictEqual( t.visibleViews(), [ 'error' ] );
		const text = t.q( '[data-magicauth-pk-error-text]' );
		assert.strictEqual( text.textContent, t.config.i18n.P10 + ' ' + t.config.i18n.P10b );
		assert.strictEqual( t.document.activeElement, text );
		await new Promise( ( r ) => setTimeout( r, 5 ) );
		assert.strictEqual( t.q( '[data-magicauth-pk-prompt] [data-magicauth-pk-alert]' ).textContent, text.textContent );
		assert.ok( typeof t.entry().promptfail === 'number' );
		t.view( 'error' ).querySelector( '[data-magicauth-pk-later]' ).click();
		await flush();
		assert.deepStrictEqual( t.choices(), [ 'failed' ] );
	},

	async closing_the_error_view_sends_failed() {
		const t = await opened( { create: () => Promise.reject( domError( 'ConstraintError' ) ) } );
		t.p4().click();
		await flush();
		assert.strictEqual( t.q( '[data-magicauth-pk-error-text]' ).textContent, t.config.i18n.P13 );
		t.dlg.close();
		await flush();
		assert.deepStrictEqual( t.choices(), [ 'failed' ] );
	},

	async invalid_state_sets_haslocal_without_a_server_write() {
		const t = await opened( { create: () => Promise.reject( domError( 'InvalidStateError' ) ) } );
		t.p4().click();
		await flush();
		assert.deepStrictEqual( t.actions(), [ 'magicauth_passkey_register_options' ] );
		assert.strictEqual( t.q( '[data-magicauth-pk-error-text]' ).textContent, t.config.i18n.P11 );
		assert.ok( typeof t.entry().haslocal === 'number' );
		assert.strictEqual( t.entry().promptfail, undefined );
	},

	async error_map_for_create() {
		const cases = [
			[ 'SecurityError', 'P12' ], [ 'NotSupportedError', 'P12' ], [ 'OperationError', 'P14' ], [ 'TypeError', 'P14' ], [ 'UnknownError', 'P14' ],
		];
		for ( const [ name, id ] of cases ) {
			const t = await opened( { create: () => Promise.reject( domError( name ) ) } );
			t.p4().click();
			await flush();
			assert.strictEqual( t.q( '[data-magicauth-pk-error-text]' ).textContent, t.config.i18n[ id ], name );
			assert.strictEqual( t.creates.length, 1, name + ': never retried' );
		}
	},

	async try_again_creates_from_the_new_click() {
		let calls = 0;
		const t = await opened( { create: () => ( ++calls === 1 ? Promise.reject( domError( 'NotAllowedError' ) ) : Promise.resolve( cred( 'NEWCRED' ) ) ) } );
		t.p4().click();
		await flush();
		assert.strictEqual( t.creates.length, 1 );
		t.view( 'error' ).querySelector( '[data-magicauth-pk-create]' ).click();
		await flush();
		assert.strictEqual( t.creates.length, 2 );
		assert.deepStrictEqual( t.visibleViews(), [ 'success' ] );
		t.dlg.close();
		await flush();
		assert.deepStrictEqual( t.choices(), [] );
	},

	async server_rejection_signals_only_this_browsers_new_credential() {
		const t = await opened( { config: { signals: null } } );
		t.setResponder( ( action ) => ( action === 'magicauth_passkey_register'
			? fail( 'registration_failed', 400, { unknown_credential: true } )
			: { status: 200, body: { success: true, data: { publicKey: { challenge: 'Yw', user: { id: 'SA' } } } } } ) );
		t.p4().click();
		await flush();
		assert.deepStrictEqual( plain( t.signals ), [ [ 'signalUnknownCredential', { rpId: t.config.rpId, credentialId: 'NEWCRED' } ] ] );
		assert.strictEqual( t.q( '[data-magicauth-pk-error-text]' ).textContent, t.config.i18n.P15 );
		assert.strictEqual( ( t.entry() || {} ).haslocal, undefined, 'not stamped on failure' );
	},

	async server_messages_for_numbers_and_session_end() {
		let t = await opened( { responder: () => fail( 'limit_reached', 409, { message: 'You have 10 passkeys, which is the maximum.' } ) } );
		t.p4().click();
		await flush();
		assert.strictEqual( t.q( '[data-magicauth-pk-error-text]' ).textContent, 'You have 10 passkeys, which is the maximum.' );

		t = await opened( { responder: () => ( { status: 400, type: 'text/html', body: '0' } ) } );
		t.p4().click();
		await flush();
		assert.strictEqual( t.q( '[data-magicauth-pk-error-text]' ).textContent, t.config.i18n.X1, 'admin-ajax 0: X1, no creation wording' );
	},

	async step_up_inside_the_prompt_then_create_again() {
		const t = await opened();
		let fresh = false;
		t.setResponder( ( action ) => {
			if ( action === 'magicauth_passkey_register_options' ) {
				return fresh ? { status: 200, body: { success: true, data: { publicKey: { challenge: 'Yw', user: { id: 'SA' } } } } } : fail( 'reauth_required', 403, { methods: [ 'email_code' ] } );
			}
			if ( action === 'magicauth_passkey_reauth_email' ) {
				return { status: 200, body: { success: true, data: { reauth_id: 'AAAAAAAAAAAAAAAAAAAAAA', expires_in: 600, sent_to: 'l***@example.test' } } };
			}
			if ( action === 'magicauth_passkey_reauth_code' ) {
				fresh = true;
				return { status: 200, body: { success: true, data: { fresh_until: 1 } } };
			}
			return { status: 200, body: { success: true, data: { passkeys: [], signal: null } } };
		} );
		t.p4().click();
		await flush();
		assert.deepStrictEqual( t.visibleViews(), [ 'reauth' ] );
		assert.strictEqual( t.creates.length, 0 );
		const reauth = t.view( 'reauth' );
		assert.strictEqual( t.document.activeElement, reauth.querySelector( '[data-magicauth-pk-reauth-title]' ) );
		assert.strictEqual( reauth.querySelector( '[data-magicauth-pk-reauth-email]' ).hidden, false );
		assert.strictEqual( reauth.querySelector( '[data-magicauth-pk-reauth-passkey]' ).hidden, true );
		assert.strictEqual( t.dlg.open, true, 'still the same dialog' );

		reauth.querySelector( '[data-magicauth-pk-reauth-email]' ).click();
		await flush();
		const form = reauth.querySelector( '[data-magicauth-pk-reauth-form]' );
		assert.strictEqual( form.tagName, 'FORM' );
		assert.strictEqual( form.hidden, false );
		const input = reauth.querySelector( '[data-magicauth-pk-reauth-code]' );
		assert.strictEqual( t.document.activeElement, input );
		input.value = 'ABC123';
		reauth.querySelector( '[data-magicauth-pk-reauth-confirm]' ).click(); // R7 submits its own form.
		await flush();
		assert.strictEqual( t.fetches.find( ( f ) => f.action === 'magicauth_passkey_reauth_code' ).params.get( 'code' ), 'ABC123' );
		assert.strictEqual( t.dlg.open, true, 'Enter or R7 never closes the prompt' );
		assert.deepStrictEqual( t.visibleViews(), [ 'offer' ] );
		assert.strictEqual( t.document.activeElement, t.p4() );
		await new Promise( ( r ) => setTimeout( r, 5 ) );
		assert.strictEqual( t.q( '[data-magicauth-pk-prompt] [data-magicauth-pk-status]' ).textContent, t.config.i18n.R10 );
		assert.strictEqual( t.creates.length, 0, 'P4 again is a new gesture' );

		t.p4().click();
		await flush();
		assert.strictEqual( t.creates.length, 1 );
		assert.deepStrictEqual( t.visibleViews(), [ 'success' ] );
	},

	async step_up_cancel_and_escape() {
		let t = await opened( { responder: () => fail( 'reauth_required', 403, { methods: [] } ) } );
		t.p4().click();
		await flush();
		const reauth = t.view( 'reauth' );
		assert.strictEqual( reauth.querySelector( '[data-magicauth-pk-reauth-none]' ).hidden, false, 'R14 without a method' );
		reauth.querySelector( '[data-magicauth-pk-reauth-cancel]' ).click();
		await flush();
		assert.deepStrictEqual( t.visibleViews(), [ 'offer' ] );
		assert.strictEqual( t.document.activeElement, t.p4() );
		assert.deepStrictEqual( t.choices(), [] );

		t = await opened( { responder: () => fail( 'reauth_required', 403, { methods: [ 'email_code' ] } ) } );
		t.p4().click();
		await flush();
		t.dlg.close();
		await flush();
		assert.deepStrictEqual( t.choices(), [ 'dismiss' ] );
	},

	async bfcache_restore_closes_without_a_choice_hides_creation_and_reloads() {
		const t = await opened();
		t.fireWindow( 'pageshow', { persisted: false } );
		assert.strictEqual( t.reloads.length, 0 );
		t.fireWindow( 'pageshow', { persisted: true } );
		await flush();
		assert.strictEqual( t.dlg.open, false );
		t.document.querySelectorAll( '[data-magicauth-pk-create]' ).forEach( ( b ) => assert.strictEqual( b.hidden, true ) );
		assert.deepStrictEqual( t.choices(), [], 'no dismiss from a restored page' );
		assert.strictEqual( t.reloads.length, 1 );
	},

	async session_signals_on_a_prompt_page() {
		const key = fixture.prompt.config.account.key;
		const s = { rpId: 'academy.example.com', userId: 'HANDLE', allAccepted: [], name: 'n', displayName: 'd', details: false };
		const t = setup( { caps: {}, uvpa: false, config: { signals: s }, storage: { 'magicauth:pk:acct': JSON.stringify( { [ key ]: { haslocal: 1 } } ) } } );
		await flush();
		assert.deepStrictEqual( t.signals.map( ( x ) => x[ 0 ] ), [ 'signalAllAcceptedCredentials' ], 'details not flagged: the list only' );
		assert.deepStrictEqual( plain( t.signals[ 0 ][ 1 ] ), { rpId: s.rpId, userId: 'HANDLE', allAcceptedCredentialIds: [] } );
		assert.strictEqual( t.entry(), null, 'an empty list forgets this account' );

		// 8.7: the details only when the payload says so, after the list.
		const d = Object.assign( {}, s, { allAccepted: [ 'C1' ], details: true } );
		const changed = setup( { caps: {}, uvpa: false, config: { signals: d } } );
		await flush();
		assert.deepStrictEqual( plain( changed.signals ), [
			[ 'signalAllAcceptedCredentials', { rpId: d.rpId, userId: 'HANDLE', allAcceptedCredentialIds: [ 'C1' ] } ],
			[ 'signalCurrentUserDetails', { rpId: d.rpId, userId: 'HANDLE', name: 'n', displayName: 'd' } ],
		] );
		for ( const flag of [ undefined, 1, 'true', null ] ) {
			const odd = setup( { caps: {}, uvpa: false, config: { signals: Object.assign( {}, d, { details: flag } ) } } );
			await flush();
			assert.deepStrictEqual( odd.signals.map( ( x ) => x[ 0 ] ), [ 'signalAllAcceptedCredentials' ], 'only details === true: ' + String( flag ) );
		}

		const quiet = setup( { caps: {}, uvpa: false, config: { signals: null } } );
		await flush();
		assert.deepStrictEqual( quiet.signals, [], 'not due: nothing' );
		const broken = setup( { caps: {}, uvpa: false, config: { signals: { rpId: 'x', userId: 'y' } } } );
		await flush();
		assert.deepStrictEqual( broken.signals, [], 'never with an incomplete list' );
	},

	async no_usable_passkey_forgets_the_entry_before_the_gate() {
		const key = fixture.prompt.config.account.key;
		const t = setup( Object.assign( { storage: { 'magicauth:pk:acct': JSON.stringify( { [ key ]: { haslocal: Date.now() } } ) }, config: { passkeys: [ { id: 1, usable_here: false } ] } }, SHOW ) );
		await flush();
		assert.strictEqual( t.entry(), null );
		assert.strictEqual( t.dlg.open, true, 'the stale entry no longer suppresses it' );

		const old = Date.now() - 31 * DAY;
		const kept = setup( Object.assign( { storage: { 'magicauth:pk:acct': JSON.stringify( { [ key ]: { haslocal: Date.now(), promptfail: old } } ) } }, SHOW, { config: { passkeys: [] } } ) );
		await flush();
		assert.deepStrictEqual( kept.entry(), { promptfail: old }, 'haslocal goes, promptfail stays' );
		assert.strictEqual( kept.dlg.open, true, 'an old promptfail does not suppress it' );
	},

	async recent_promptfail_without_passkeys_keeps_the_dialog_closed() {
		// The in-app browser case (2.1, P10b): create() failed and the user left without a choice.
		const key = fixture.prompt.config.account.key;
		const recent = Date.now() - DAY;
		for ( const passkeys of [ [], [ { id: 1, usable_here: false } ] ] ) {
			const t = setup( Object.assign( { storage: { 'magicauth:pk:acct': JSON.stringify( { [ key ]: { promptfail: recent } } ) } }, SHOW, { config: { passkeys: passkeys } } ) );
			await flush();
			assert.strictEqual( t.dlg.open, false, JSON.stringify( passkeys ) );
			assert.deepStrictEqual( t.entry(), { promptfail: recent } );
			assert.deepStrictEqual( t.fetches, [], 'nothing sent' );
		}
		const s = { rpId: 'academy.example.com', userId: 'HANDLE', allAccepted: [], name: 'n', displayName: 'd' };
		const t = setup( Object.assign( { storage: { 'magicauth:pk:acct': JSON.stringify( { [ key ]: { promptfail: recent, haslocal: 1 } } ) } }, SHOW, { config: { passkeys: [], signals: s } } ) );
		await flush();
		assert.strictEqual( t.signals.length, 1 );
		assert.deepStrictEqual( t.entry(), { promptfail: recent }, 'the empty signals list keeps promptfail too' );
		assert.strictEqual( t.dlg.open, false );
	},

	async first_passkey_learns_the_account_key_from_the_creation_options() {
		const handle = 'q3N0dWRlbnQtaGFuZGxlLWZvci10aGUta2V5LXRlc3Q';
		const expected = require( 'crypto' ).createHash( 'sha256' ).update( handle ).digest( 'hex' ).slice( 0, 16 );
		const options = { status: 200, body: { success: true, data: { publicKey: { challenge: 'Yw', user: { id: handle, name: 'n', displayName: 'd' } } } } };
		let t = await opened( {
			config: { account: { key: '' }, signals: null },
			responder: ( action ) => ( action === 'magicauth_passkey_register_options' ? options : { status: 200, body: { success: true, data: { passkeys: [], signal: null } } } ),
		} );
		t.p4().click();
		await flush();
		assert.deepStrictEqual( t.visibleViews(), [ 'success' ] );
		assert.ok( typeof JSON.parse( t.store.get( 'magicauth:pk:acct' ) )[ expected ].haslocal === 'number', 'haslocal under the server-side key' );

		t = await opened( { config: { account: { key: '' }, signals: null }, responder: () => options, create: () => Promise.reject( domError( 'NotAllowedError' ) ) } );
		t.p4().click();
		await flush();
		assert.ok( typeof JSON.parse( t.store.get( 'magicauth:pk:acct' ) )[ expected ].promptfail === 'number', 'promptfail under the server-side key' );
		assert.strictEqual( t.creates.length, 1 );
	},

	async management_page_and_profile_send_details_only_when_flagged() {
		for ( const page of [ 'manage', 'profile' ] ) {
			const base = fixture[ page ].config.signals;
			assert.ok( base && Array.isArray( base.allAccepted ) && base.allAccepted.length === 1, page + ': a payload with the list' );
			assert.strictEqual( base.details, false, page + ': the prompt page before it delivered the details' );
			const t = setup( { page } );
			await flush();
			assert.deepStrictEqual( t.signals.map( ( x ) => x[ 0 ] ), [ 'signalAllAcceptedCredentials' ], page + ': unchanged details are not signalled' );

			const changed = setup( { page, config: { signals: Object.assign( {}, base, { displayName: 'Renamed', details: true } ) } } );
			await flush();
			assert.deepStrictEqual( plain( changed.signals ), [
				[ 'signalAllAcceptedCredentials', { rpId: base.rpId, userId: base.userId, allAcceptedCredentialIds: base.allAccepted } ],
				[ 'signalCurrentUserDetails', { rpId: base.rpId, userId: base.userId, name: base.name, displayName: 'Renamed' } ],
			], page );
		}
	},

	async endpoint_responses_send_the_list_only() {
		const t = setup( { page: 'manage', responder: ( action ) => ( action === 'magicauth_passkey_rename'
			? { status: 200, body: { success: true, data: { passkey: null, passkeys: [], signal: { rpId: 'r', userId: 'u', allAccepted: [], name: 'n', displayName: 'd', details: false } } } }
			: { status: 200, body: { success: true, data: {} } } ) } );
		await flush();
		t.signals.length = 0;
		const li = t.q( '[data-magicauth-pk-item]' );
		li.querySelector( '[data-magicauth-pk-rename]' ).click();
		await flush();
		const input = li.querySelector( '[data-magicauth-pk-rename-box] input' );
		input.value = 'Work laptop';
		input.key( 'Enter' );
		await flush();
		assert.deepStrictEqual( t.actions().filter( ( a ) => a === 'magicauth_passkey_rename' ), [ 'magicauth_passkey_rename' ] );
		assert.deepStrictEqual( t.signals.map( ( x ) => x[ 0 ] ), [ 'signalAllAcceptedCredentials' ] );
	},

	async management_add_with_inline_step_up() {
		let fresh = false;
		const t = setup( { page: 'manage', responder: ( action ) => {
			if ( action === 'magicauth_passkey_register_options' ) {
				return fresh ? { status: 200, body: { success: true, data: { publicKey: { challenge: 'Yw', user: { id: 'SA' } } } } } : fail( 'reauth_required', 403, { methods: [ 'email_code', 'passkey' ] } );
			}
			if ( action === 'magicauth_passkey_reauth_email' ) {
				return { status: 200, body: { success: true, data: { reauth_id: 'AAAAAAAAAAAAAAAAAAAAAA', expires_in: 600, sent_to: 'l***@example.test' } } };
			}
			if ( action === 'magicauth_passkey_reauth_code' ) {
				fresh = true;
				return { status: 200, body: { success: true, data: { fresh_until: 1 } } };
			}
			if ( action === 'magicauth_passkey_register' ) {
				return { status: 200, body: { success: true, data: { passkey: t.passkeys[ 0 ], passkeys: t.passkeys, signal: t.signal } } };
			}
			return { status: 200, body: { success: true, data: {} } };
		} } );
		await flush();
		const add = t.q( '[data-magicauth-pk-add]' );
		assert.strictEqual( add.hidden, false );
		const label = add.textContent;
		add.click();
		await flush();
		assert.strictEqual( add.textContent, label, 'Add keeps its label' );
		const reauth = t.q( '[data-magicauth-pk-view="reauth"]' );
		assert.strictEqual( reauth.hidden, false );
		assert.strictEqual( reauth.querySelector( 'form' ), null, 'inline view: no form' );
		assert.strictEqual( t.document.activeElement, reauth.querySelector( '[data-magicauth-pk-reauth-title]' ) );
		reauth.querySelector( '[data-magicauth-pk-reauth-email]' ).click();
		await flush();
		const input = reauth.querySelector( '[data-magicauth-pk-reauth-code]' );
		input.value = 'ABC123';
		input.key( 'Enter' );
		await flush();
		assert.strictEqual( reauth.hidden, true );
		assert.strictEqual( t.document.activeElement, add );
		add.click();
		await flush();
		assert.strictEqual( t.creates.length, 1 );
		assert.strictEqual( t.q( '[data-magicauth-pk-list]' ).querySelectorAll( '[data-magicauth-pk-item]' ).length, 1 );
		await new Promise( ( r ) => setTimeout( r, 5 ) );
		assert.strictEqual( t.q( '[data-magicauth-pk-manage] [data-magicauth-pk-status]' ).textContent, t.config.i18n.M24 );
		assert.ok( typeof t.entry().haslocal === 'number' );
		assert.deepStrictEqual( t.choices(), [] );
	},

	async management_create_error_stays_in_the_page() {
		const t = setup( { page: 'manage', create: () => Promise.reject( domError( 'NotAllowedError' ) ), responder: () => ( { status: 200, body: { success: true, data: { publicKey: { challenge: 'Yw', user: { id: 'SA' } } } } } ) } );
		await flush();
		t.q( '[data-magicauth-pk-add]' ).click();
		await flush();
		await new Promise( ( r ) => setTimeout( r, 5 ) );
		assert.strictEqual( t.q( '[data-magicauth-pk-manage] [data-magicauth-pk-alert]' ).textContent, t.config.i18n.P10, 'P10 without the prompt-only P10b' );
		assert.strictEqual( ( t.entry() || {} ).promptfail, undefined, 'promptfail is the prompt\'s' );
	},

	// r1-frontend-04: a list that could not be read is no empty list.
	async list_error_keeps_the_list_and_shows_mx() {
		const t = setup( { page: 'manage', responder: ( action ) => {
			if ( action === 'magicauth_passkey_register_options' ) {
				return { status: 200, body: { success: true, data: { publicKey: { challenge: 'Yw', user: { id: 'SA' } } } } };
			}
			return { status: 200, body: { success: true, data: { passkey: t.passkeys[ 0 ], passkeys: null, list_error: true, signal: null } } };
		} } );
		await flush();
		const list = t.q( '[data-magicauth-pk-list]' );
		const before = list.querySelectorAll( '[data-magicauth-pk-item]' ).length;
		assert.ok( before > 0, 'the fixture lists a passkey' );
		t.q( '[data-magicauth-pk-add]' ).click();
		await flush();
		await new Promise( ( r ) => setTimeout( r, 5 ) );
		assert.strictEqual( t.creates.length, 1 );
		assert.strictEqual( list.querySelectorAll( '[data-magicauth-pk-item]' ).length, before, 'the shown list is kept' );
		assert.strictEqual( t.q( '[data-magicauth-pk-manage] [data-magicauth-pk-alert]' ).textContent, t.config.i18n.MX );
		const empty = t.q( '[data-magicauth-pk-manage] [data-magicauth-pk-empty]' );
		assert.ok( ! empty || empty.hidden, 'no M3' );
		const removeAll = t.q( '[data-magicauth-pk-manage] [data-magicauth-pk-remove-all]' );
		assert.ok( ! removeAll || removeAll.hidden === false, 'Remove all, when present, stays' );
	},

	async unreadable_list_in_the_config_never_forgets_haslocal() {
		const key = fixture.prompt.config.account.key;
		const now = Date.now();
		const t = setup( { storage: { 'magicauth:pk:acct': JSON.stringify( { [ key ]: { haslocal: now } } ) }, config: { passkeys: null } } );
		await flush();
		assert.deepStrictEqual( t.entry(), { haslocal: now } );
	},

	async inline_signals() {
		const inline = fs.readFileSync( fixturePath, 'utf8' );
		const m = /^window\.magicauthPasskeysConfig = (\{.*?\});(\(function\(c\)[\s\S]*)$/.exec( inline );
		assert.ok( m, 'config, then the call' );
		const t = setup( { page: 'none', inline } );
		await flush();
		const s = plain( t.config.signals );
		assert.strictEqual( s.allAccepted.length, 1 );
		assert.deepStrictEqual( plain( t.signals ), [
			[ 'signalAllAcceptedCredentials', { rpId: s.rpId, userId: s.userId, allAcceptedCredentialIds: s.allAccepted } ],
			[ 'signalCurrentUserDetails', { rpId: s.rpId, userId: s.userId, name: s.name, displayName: s.displayName } ],
		] );
		assert.deepStrictEqual( t.fetches, [], 'no request' );
		assert.strictEqual( s.details, true, 'the fixture account has no details record yet' );

		// Details not flagged (8.7): the list only, so Safari has nothing to announce.
		const same = JSON.parse( m[ 1 ] );
		same.signals.details = false;
		const quiet = setup( { page: 'none', inline: 'window.magicauthPasskeysConfig = ' + JSON.stringify( same ) + ';' + m[ 2 ] } );
		await flush();
		assert.deepStrictEqual( plain( quiet.signals ), [
			[ 'signalAllAcceptedCredentials', { rpId: s.rpId, userId: s.userId, allAcceptedCredentialIds: s.allAccepted } ],
		] );

		// After revoke-all the empty list is sent and this account's browser entry goes.
		const config = JSON.parse( m[ 1 ] );
		config.signals.allAccepted = [];
		const key = config.account.key;
		const empty = setup( {
			page: 'none',
			inline: 'window.magicauthPasskeysConfig = ' + JSON.stringify( config ) + ';' + m[ 2 ],
			storage: { 'magicauth:pk:acct': JSON.stringify( { [ key ]: { haslocal: 1 }, other: { haslocal: 2 } } ) },
		} );
		await flush();
		assert.deepStrictEqual( plain( empty.signals[ 0 ][ 1 ].allAcceptedCredentialIds ), [] );
		assert.deepStrictEqual( JSON.parse( empty.store.get( 'magicauth:pk:acct' ) ), { other: { haslocal: 2 } } );

		// The empty list drops haslocal only; promptfail keeps gating the prompt (2.1).
		const failed = setup( {
			page: 'none',
			inline: 'window.magicauthPasskeysConfig = ' + JSON.stringify( config ) + ';' + m[ 2 ],
			storage: { 'magicauth:pk:acct': JSON.stringify( { [ key ]: { haslocal: 1, promptfail: 5 }, other: { haslocal: 2 } } ) },
		} );
		await flush();
		assert.deepStrictEqual( JSON.parse( failed.store.get( 'magicauth:pk:acct' ) ), { [ key ]: { promptfail: 5 }, other: { haslocal: 2 } } );

		// A list that is not empty leaves the entry alone.
		const listed = setup( {
			page: 'none',
			inline,
			storage: { 'magicauth:pk:acct': JSON.stringify( { [ key ]: { haslocal: 1, promptfail: 5 } } ) },
		} );
		await flush();
		assert.strictEqual( listed.signals.length, 2 );
		assert.deepStrictEqual( JSON.parse( listed.store.get( 'magicauth:pk:acct' ) ), { [ key ]: { haslocal: 1, promptfail: 5 } } );

		// A malformed list sends nothing.
		const broken = JSON.parse( m[ 1 ] );
		broken.signals.allAccepted = 'x';
		const bad = setup( { page: 'none', inline: 'window.magicauthPasskeysConfig = ' + JSON.stringify( broken ) + ';' + m[ 2 ] } );
		await flush();
		assert.deepStrictEqual( bad.signals, [], 'never an incomplete list' );
	},

	// r1-frontend-01: post content (kses keeps data-*, section, dialog, button) above the shortcode plants
	// look-alike sections. Only the section with this request's render key is bound.
	async lookalike_sections_in_post_content_are_never_bound() {
		const planted = '<section data-magicauth-pk-manage data-magicauth-pk-mode="manage" data-magicauth-pk-user="7">' +
			'<ul data-magicauth-pk-list><li data-magicauth-pk-item data-id="5"><bdi data-magicauth-pk-name>x</bdi>' +
			'<button type="button" data-magicauth-pk-remove hidden>Remove</button></li></ul>' +
			'<button type="button" data-magicauth-pk-signout-others hidden>Read more</button></section>' +
			'<section data-magicauth-pk-manage data-magicauth-pk-render="0123456789abcdef0123456789abcdef">' +
			'<ul data-magicauth-pk-list></ul><button type="button" data-magicauth-pk-signout-others hidden>Guess</button></section>';
		const t = setup( { page: 'manage', before: planted, responder: () => ( { status: 200, body: { success: true, data: { passkeys: [] } } } ) } );
		await flush();
		const sections = t.document.querySelectorAll( '[data-magicauth-pk-manage]' );
		assert.strictEqual( sections.length, 3 );
		const real = sections[ 2 ];
		assert.strictEqual( real.getAttribute( 'data-magicauth-pk-render' ), t.config.render, 'the real section carries the key' );
		[ sections[ 0 ], sections[ 1 ] ].forEach( ( fake ) => {
			fake.querySelectorAll( 'button' ).forEach( ( b ) => {
				assert.strictEqual( b.hidden, true, 'planted controls stay hidden' );
				b.click();
			} );
		} );
		await flush();
		assert.deepStrictEqual( t.actions(), [], 'planted buttons post nothing' );
		const dlg = real.querySelector( '[data-magicauth-pk-remove-dialog]' );
		assert.strictEqual( dlg.open, false, 'the planted Remove does not open the real dialog' );

		// The real section still works: Remove then Confirm, and sign out elsewhere.
		const realId = real.querySelector( '[data-magicauth-pk-item]' ).getAttribute( 'data-id' );
		real.querySelector( '[data-magicauth-pk-remove]' ).click();
		assert.ok( dlg.open );
		dlg.querySelector( '[data-magicauth-pk-remove-confirm]' ).click();
		await flush();
		const del = t.fetches.find( ( f ) => f.action === 'magicauth_passkey_delete' );
		assert.ok( del, 'Confirm on the real dialog sends the removal' );
		assert.strictEqual( del.params.get( 'id' ), realId );
		const out = real.querySelector( '[data-magicauth-pk-signout-others]' );
		assert.strictEqual( out.hidden, false );
		out.click();
		await flush();
		assert.strictEqual( t.fetches.filter( ( f ) => f.action === 'magicauth_passkey_signout_others' ).length, 1 );
	},

	async lookalike_prompt_is_never_opened() {
		const planted = '<dialog data-magicauth-pk-prompt><h2 data-magicauth-pk-title tabindex="-1">x</h2>' +
			'<div data-magicauth-pk-view="offer"><button type="button" data-magicauth-pk-create>Go</button></div></dialog>';
		const t = setup( Object.assign( { before: planted }, SHOW ) );
		await flush();
		const dialogs = t.document.querySelectorAll( '[data-magicauth-pk-prompt]' );
		assert.strictEqual( dialogs.length, 2 );
		assert.strictEqual( dialogs[ 0 ].open, false, 'the planted prompt stays closed' );
		assert.strictEqual( dialogs[ 1 ].open, true, 'the real prompt opens' );
		assert.deepStrictEqual( t.document.log, [ 'showModal:prompt' ] );
	},

	// wp-admin: the dialogs print in the footer, outside the section. A look-alike with the same id earlier
	// on the page is skipped: only the dialog with the render key and a named id is bound.
	async profile_dialogs_are_found_by_named_id_and_render_key() {
		const ids = /data-magicauth-pk-dialogs="([^"]+)"/.exec( fixture.profile.html )[ 1 ].split( ' ' );
		assert.deepStrictEqual( ids.map( ( id ) => id.replace( /-\d+$/, '' ) ), [ 'magicauth-pk-remove-dialog', 'magicauth-pk-reauth-dialog' ] );
		const planted = '<dialog id="' + ids[ 0 ] + '" data-magicauth-pk-remove-dialog><h2 tabindex="-1">x</h2>' +
			'<input type="checkbox" data-magicauth-pk-signout checked>' +
			'<button type="button" data-magicauth-pk-remove-cancel>c</button><button type="button" data-magicauth-pk-remove-confirm>y</button></dialog>';
		const t = setup( { page: 'profile', before: planted, responder: () => ( { status: 200, body: { success: true, data: { passkeys: [] } } } ) } );
		await flush();
		const both = t.document.querySelectorAll( '[data-magicauth-pk-remove-dialog]' );
		assert.strictEqual( both.length, 2 );
		const sec = t.q( '[data-magicauth-pk-manage]' );
		assert.ok( ! sec.querySelector( '[data-magicauth-pk-remove-dialog]' ), 'no dialog inside the profile section' );
		sec.querySelector( '[data-magicauth-pk-remove]' ).click();
		assert.strictEqual( both[ 0 ].open, false, 'the planted dialog is not used' );
		assert.strictEqual( both[ 1 ].open, true, 'the footer dialog opens' );
		both[ 0 ].querySelector( '[data-magicauth-pk-remove-confirm]' ).click();
		await flush();
		assert.deepStrictEqual( t.actions().filter( ( a ) => a === 'magicauth_passkey_delete' ), [], 'the planted Confirm is not bound' );
		both[ 1 ].querySelector( '[data-magicauth-pk-remove-confirm]' ).click();
		await flush();
		assert.strictEqual( t.fetches.filter( ( f ) => f.action === 'magicauth_passkey_delete' ).length, 1 );
	},

	// r1-frontend-05: x and Esc wait while the passkey is being saved; its outcome shows in the open dialog.
	async prompt_close_and_escape_wait_for_a_pending_creation() {
		const t = await opened();
		const register = deferred();
		t.setResponder( ( action ) => {
			if ( action === 'magicauth_passkey_register' ) {
				return register.promise;
			}
			if ( action === 'magicauth_passkey_register_options' ) {
				return { status: 200, body: { success: true, data: { publicKey: { challenge: 'Y2hhbGxlbmdl', user: { id: 'SEFORExF', name: 'x', displayName: 'x' } } } } };
			}
			return { status: 200, body: { success: true, data: {} } };
		} );
		t.p4().click();
		await flush();
		assert.ok( t.fetches.some( ( f ) => f.action === 'magicauth_passkey_register' ), 'register pending' );
		t.dlg.querySelector( '[data-magicauth-pk-close]' ).click();
		assert.strictEqual( t.dlg.open, true, 'x ignored while pending' );
		const esc = t.dlg.dispatch( 'cancel', {}, false );
		assert.strictEqual( esc.defaultPrevented, true, 'Esc cancelled while pending' );
		register.resolve( { status: 200, body: { success: true, data: { passkeys: t.passkeys, signal: t.signal } } } );
		await flush();
		assert.strictEqual( t.dlg.open, true );
		assert.deepStrictEqual( t.visibleViews(), [ 'success' ] );
		const idle = t.dlg.dispatch( 'cancel', {}, false );
		assert.strictEqual( idle.defaultPrevented, false, 'Esc works again after the outcome' );
		t.dlg.querySelector( '[data-magicauth-pk-done]' ).click();
		await flush();
		assert.strictEqual( t.dlg.open, false );
	},

	// A close that still got through (Chrome lets a repeated Esc past cancel) is followed by the outcome.
	async prompt_closed_during_a_pending_creation_reopens_with_the_success() {
		const t = await opened();
		const register = deferred();
		t.setResponder( ( action ) => {
			if ( action === 'magicauth_passkey_register' ) {
				return register.promise;
			}
			if ( action === 'magicauth_passkey_register_options' ) {
				return { status: 200, body: { success: true, data: { publicKey: { challenge: 'Y2hhbGxlbmdl', user: { id: 'SEFORExF', name: 'x', displayName: 'x' } } } } };
			}
			return { status: 200, body: { success: true, data: {} } };
		} );
		t.p4().click();
		await flush();
		t.dlg.close();
		await flush();
		assert.strictEqual( t.dlg.open, false );
		register.resolve( { status: 200, body: { success: true, data: { passkeys: t.passkeys, signal: t.signal } } } );
		await flush();
		assert.strictEqual( t.dlg.open, true, 'reopened for the outcome' );
		assert.deepStrictEqual( t.visibleViews(), [ 'success' ] );
		assert.strictEqual( t.document.activeElement, t.q( '[data-magicauth-pk-success]' ) );
		assert.ok( t.choices().length <= 1, 'one choice per dialog' );
	},

	// r1-frontend-07: rename binds to data-magicauth-pk-actions, not to a class a theme override may rename.
	async rename_works_without_the_plugin_classes() {
		const t = setup( { page: 'manage' } );
		await flush();
		const li = t.q( '[data-magicauth-pk-item]' );
		const actions = li.querySelector( '[data-magicauth-pk-actions]' );
		assert.ok( actions, 'the template marks the actions' );
		actions.setAttribute( 'class', 'theme-actions' );
		li.querySelector( '[data-magicauth-pk-rename]' ).click();
		const input = li.querySelector( 'input' );
		assert.ok( input, 'the rename field opened' );
		assert.strictEqual( actions.hidden, true );
		input.key( 'Escape' );
		assert.strictEqual( actions.hidden, false );
		assert.strictEqual( li.querySelector( 'input' ), null );
		// The script's own items carry the attribute as well.
		li.querySelector( '[data-magicauth-pk-rename]' ).click();
		li.querySelector( 'input' ).value = 'Phone';
		li.querySelector( 'input' ).key( 'Enter' );
		await flush();
		const again = t.q( '[data-magicauth-pk-item]' );
		assert.ok( again.querySelector( '[data-magicauth-pk-actions]' ), 'rebuilt items keep data-magicauth-pk-actions' );
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
