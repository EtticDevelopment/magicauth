// MagicAuth passkeys: account script (SPEC 2.1, 2.3, 3.5, 8.1, 8.5 to 8.7, 8.11, 8.12). Signed-in pages only.
// Post-login prompt, management list (add, rename, remove, sign out elsewhere, admin removal), step-up,
// signals. ES2017, vanilla. DOM writes through textContent and setAttribute only; no HTML is parsed.
( function () {
	'use strict';

	const P = window.MagicAuthPasskeys;
	const cfg = window.magicauthPasskeysConfig || {};
	if ( ! P ) {
		return;
	}
	const S = cfg.i18n || {};
	const A = cfg.actions || {};
	const STORE = 'magicauth:pk:acct';
	const NOPROMPT = 'magicauth:pk:noprompt';
	const DAY = 86400000;
	const RENDER = typeof cfg.render === 'string' ? cfg.render : '';

	// The open prompt's state, so a back/forward cache restore can close it without a choice.
	let prompting = null;

	// A page restored from the back/forward cache (perhaps after sign-out) never offers creation (8.11).
	window.addEventListener( 'pageshow', function ( e ) {
		if ( ! e.persisted ) {
			return;
		}
		if ( prompting ) {
			prompting.restoring = true;
		}
		document.querySelectorAll( '[data-magicauth-pk-create],[data-magicauth-pk-add]' ).forEach( function ( el ) {
			el.hidden = true;
		} );
		document.querySelectorAll( '[data-magicauth-pk-prompt][open],[data-magicauth-pk-remove-dialog][open],' +
			'[data-magicauth-pk-remove-all-dialog][open],[data-magicauth-pk-reauth-dialog][open]' ).forEach( function ( d ) {
			d.close();
		} );
		window.location.reload();
	} );

	/* ------------------------------------------------------------ helpers */

	// A section, dialog or prompt the plugin printed on this request: it carries the request's random key.
	// Look-alike markup in post content (kses keeps data-*) cannot know it and is never bound.
	function ours( el ) {
		return !! el && RENDER !== '' && el.getAttribute( 'data-magicauth-pk-render' ) === RENDER;
	}

	function ownRoots( sel ) {
		return Array.prototype.filter.call( document.querySelectorAll( sel ), ours );
	}

	function make( tag, cls, text ) {
		const el = document.createElement( tag );
		if ( cls ) {
			el.className = cls;
		}
		if ( typeof text === 'string' ) {
			el.textContent = text;
		}
		return el;
	}

	// "... %s ..." with the value in a <bdi> (names, 8.8).
	function bdiText( el, pattern, value ) {
		const parts = String( pattern || '%s' ).split( '%s' );
		el.textContent = '';
		el.appendChild( document.createTextNode( parts[ 0 ] ) );
		const b = make( 'bdi', '', value );
		el.appendChild( b );
		el.appendChild( document.createTextNode( parts.slice( 1 ).join( '%s' ) ) );
	}

	function focus( el ) {
		if ( el && typeof el.focus === 'function' ) {
			el.focus();
		}
	}

	function busy( btn, on ) {
		if ( ! btn ) {
			return;
		}
		if ( on ) {
			btn.setAttribute( 'aria-disabled', 'true' );
			btn.setAttribute( 'aria-busy', 'true' );
		} else {
			btn.removeAttribute( 'aria-disabled' );
			btn.removeAttribute( 'aria-busy' );
		}
	}

	// Busy state for a running ceremony: aria-disabled and aria-busy, the label swapped when given
	// (P7 on P4, 8.5); focus stays on the button. Returns the undo.
	function pending( btn, label ) {
		if ( ! btn ) {
			return function () {};
		}
		const text = btn.textContent;
		busy( btn, true );
		if ( label ) {
			btn.textContent = label;
		}
		return function () {
			busy( btn, false );
			if ( label ) {
				btn.textContent = text;
			}
		};
	}

	// G2 (8.3): G1 plus create().
	function canCreate() {
		const c = navigator.credentials;
		return P.g1() && typeof c.create === 'function';
	}

	function descs( list ) {
		return ( list || [] ).map( function ( d ) {
			const out = { type: d.type, id: P.b64u.decode( d.id ) };
			if ( d.transports ) {
				out.transports = d.transports;
			}
			return out;
		} );
	}

	// Native parseCreationOptionsFromJSON, else the 03 section 3 fallback.
	function parseCreation( json ) {
		if ( typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function' ) {
			return PublicKeyCredential.parseCreationOptionsFromJSON( json );
		}
		return Object.assign( {}, json, {
			challenge: P.b64u.decode( json.challenge ),
			user: Object.assign( {}, json.user, { id: P.b64u.decode( json.user.id ) } ),
			excludeCredentials: descs( json.excludeCredentials ),
		} );
	}

	// Platform hint for the default name only (4.8); iPadOS Safari reports MacIntel.
	function platform() {
		const nav = navigator;
		const p = String( ( nav.userAgentData && nav.userAgentData.platform ) || nav.platform || '' );
		if ( p === 'MacIntel' && nav.maxTouchPoints > 1 ) {
			return 'iPad';
		}
		const map = [ [ /iPhone/i, 'iPhone' ], [ /iPad/i, 'iPad' ], [ /Android/i, 'Android' ], [ /^(Chrome ?OS|CrOS)/i, 'ChromeOS' ],
			[ /^Win/i, 'Windows' ], [ /^(macOS|Mac)/i, 'Mac' ], [ /Linux/i, 'Linux' ] ];
		for ( let i = 0; i < map.length; i++ ) {
			if ( map[ i ][ 0 ].test( p ) ) {
				return map[ i ][ 1 ];
			}
		}
		return '';
	}

	// Per-account browser entries (5.3); storage that throws counts as absent.
	function account( fn ) {
		const key = cfg.account && cfg.account.key;
		if ( ! key ) {
			return;
		}
		try {
			const map = JSON.parse( window.localStorage.getItem( STORE ) || '{}' ) || {};
			fn( map, key );
			window.localStorage.setItem( STORE, JSON.stringify( map ) );
		} catch ( e ) {
			// Private mode or blocked storage.
		}
	}

	// This account's entry, read only; {} when absent or unreadable.
	function entry() {
		const key = cfg.account && cfg.account.key;
		try {
			const map = JSON.parse( window.localStorage.getItem( STORE ) || '{}' ) || {};
			return key && map[ key ] && typeof map[ key ] === 'object' ? map[ key ] : {};
		} catch ( e ) {
			return {};
		}
	}

	function stamp( name ) {
		account( function ( map, key ) {
			const next = Object.assign( {}, map[ key ] );
			next[ name ] = Date.now();
			map[ key ] = next;
		} );
	}

	// A first passkey: the config had no key, the account had no user handle yet (5.3). The creation
	// options carry the handle as user.id; the key is the same first 16 hex of its SHA-256 the server
	// computes. Run only after create() settled (no await may come between the click and create()).
	async function learnKey( publicKey ) {
		if ( ( cfg.account && cfg.account.key ) || ! publicKey || ! publicKey.user || typeof publicKey.user.id !== 'string' ) {
			return;
		}
		try {
			const digest = await window.crypto.subtle.digest( 'SHA-256', new TextEncoder().encode( publicKey.user.id ) );
			const hex = Array.prototype.map.call( new Uint8Array( digest ), function ( b ) {
				return ( '0' + b.toString( 16 ) ).slice( -2 );
			} ).join( '' );
			cfg.account = Object.assign( {}, cfg.account, { key: hex.slice( 0, 16 ) } );
		} catch ( e ) {
			// No SubtleCrypto: the entries are skipped, as with blocked storage.
		}
	}

	// Zero credentials for this RP ID (5.3): no local passkey can exist, so haslocal goes. promptfail stays:
	// those accounts are the prompt's audience and the 30-day gate (2.1) must hold for them.
	function forget() {
		account( function ( map, key ) {
			const mine = map[ key ];
			if ( mine && typeof mine === 'object' && typeof mine.promptfail === 'number' ) {
				map[ key ] = { promptfail: mine.promptfail };
			} else {
				delete map[ key ];
			}
		} );
	}

	// The details only when the server says the authenticators lack them (8.7): Safari 26 tells the user about
	// every signalCurrentUserDetails, changed or not. Endpoint responses never carry details.
	async function signals( s ) {
		if ( ! s || ! s.rpId || ! s.userId || ! Array.isArray( s.allAccepted ) ) {
			return; // Never with an incomplete list (invariant 7).
		}
		await P.signal( 'signalAllAcceptedCredentials', { rpId: s.rpId, userId: s.userId, allAcceptedCredentialIds: s.allAccepted } );
		if ( s.details === true ) {
			await P.signal( 'signalCurrentUserDetails', { rpId: s.rpId, userId: s.userId, name: s.name, displayName: s.displayName } );
		}
		if ( s.allAccepted.length === 0 ) {
			forget();
		}
	}

	function owner( fields ) {
		return Object.assign( { _ajax_nonce: cfg.nonce }, fields );
	}

	// Message for a failed post (6.10, 8.6); runtime numbers come from the server message.
	function message( r, context ) {
		const d = r.data || {};
		const create = context === 'create';
		if ( d.code === 'unexpected' && r.status === 400 ) {
			return S.X1; // admin-ajax "0": the session ended (8.1).
		}
		switch ( d.code ) {
			case 'not_logged_in':
			case 'bad_nonce':
			case 'bad_origin':
				return S.X1;
			case 'throttled':
			case 'cooldown':
			case 'limit_reached':
				return d.message || S.R12;
			case 'invalid_name':
				return S.M25;
			case 'duplicate_name':
				return S.M35;
			case 'reauth_unavailable':
				return S.R14;
			case 'code_invalid':
				return S.R8;
			case 'reauth_failed':
			case 'no_passkey':
				return S.R11;
			case 'registration_failed':
				return S.P15;
			case 'unavailable':
			case 'disabled_user':
				return S.P12;
			case 'retry':
			case 'network':
			case 'unexpected':
				return create ? S.P14 : S.MG;
			default:
				return d.message || S.MG;
		}
	}

	// Errors stay until the next action; a theme may render them itself (8.6).
	function alertError( region, code, text, context ) {
		const ev = new CustomEvent( 'magicauth:passkey:error', { cancelable: true, detail: { code: code, message: text, context: context } } );
		if ( document.dispatchEvent( ev ) ) {
			P.liveRegion( region, text );
		}
	}

	/* ------------------------------------------------------------ create (2.1 Create, 8.6), prompt and Add */

	// ctx: { ui: { busy }, button, label, status, alert, prompt, reauth( methods ), fail( code, text ), done( r ) }.
	function createError( ctx, e ) {
		const name = ( e && e.name ) || 'unexpected';
		let text = S.P14;
		if ( name === 'NotAllowedError' ) {
			text = S.P10;
			if ( ctx.prompt ) {
				// In-app browsers fail this way and cannot be told apart without UA sniffing (2.1).
				text += ' ' + S.P10b;
				stamp( 'promptfail' );
			}
		} else if ( name === 'InvalidStateError' ) {
			text = S.P11; // This browser already holds one for the account: no server call.
			stamp( 'haslocal' );
		} else if ( name === 'SecurityError' || name === 'NotSupportedError' ) {
			text = S.P12;
		} else if ( name === 'ConstraintError' ) {
			text = S.P13;
		} else if ( name === 'OperationError' ) {
			console.warn( e ); // eslint-disable-line no-console
		} else {
			console.error( e ); // eslint-disable-line no-console
		}
		ctx.fail( name, text );
	}

	// The only create() call. Never retried automatically: a second create() would run outside the
	// click (8.6). Clicks while a ceremony or its server calls are pending are ignored (busy flag).
	async function create( ctx ) {
		if ( ctx.ui.busy ) {
			return;
		}
		ctx.ui.busy = true;
		const undo = pending( ctx.button, ctx.label );
		if ( ctx.alert ) {
			ctx.alert.textContent = '';
		}
		P.liveRegion( ctx.status, S.P7 );
		try {
			// No other await before create() (Safari before 17.4 gesture rule).
			const opts = await P.post( A.registerOptions, owner( {} ) );
			if ( ! opts.ok ) {
				if ( opts.data.code === 'reauth_required' ) {
					ctx.reauth( Array.isArray( opts.data.methods ) ? opts.data.methods : [] );
					return;
				}
				ctx.fail( opts.data.code, message( opts, 'create' ) );
				return;
			}
			let cred;
			try {
				cred = await navigator.credentials.create( { publicKey: parseCreation( opts.data.publicKey ) } );
			} catch ( e ) {
				await learnKey( opts.data.publicKey );
				createError( ctx, e );
				return;
			}
			await learnKey( opts.data.publicKey );
			const json = P.toJSON( cred );
			const r = await P.post( A.register, owner( { credential: JSON.stringify( json ), platform: platform() } ) );
			if ( ! r.ok ) {
				if ( r.data.unknown_credential === true && json.id ) {
					// Only this browser's own new credential, never an ID from the response (7.3).
					P.signal( 'signalUnknownCredential', { rpId: cfg.rpId, credentialId: json.id } );
				}
				ctx.fail( r.data.code, message( r, 'create' ) );
				return;
			}
			stamp( 'haslocal' );
			ctx.done( r );
		} finally {
			ctx.ui.busy = false;
			undo();
		}
	}

	// The only way create() runs: a click on P4, P18 or M4 (2.6 row 18, T-OFFER-3).
	function onCreateClick( ctx ) {
		return function () {
			create( ctx );
		};
	}

	/* ------------------------------------------------------------ step-up view (3.5) */

	// One step-up view: inline on the shortcode, a dialog on the profile, a view of the prompt.
	// o: { ui, show(), hide( confirmed ) }. Listeners are bound once per view.
	function stepUp( reauth, o ) {
		const rq = function ( sel ) {
			return reauth.querySelector( sel );
		};
		const alertEl = rq( '[data-magicauth-pk-reauth-alert]' );
		const step = { id: '' };

		function fail( r ) {
			alertError( alertEl, ( r.data && r.data.code ) || 'unexpected', message( r, 'reauth' ), 'reauth' );
		}

		function show( methods ) {
			rq( '[data-magicauth-pk-reauth-email]' ).hidden = methods.indexOf( 'email_code' ) < 0;
			rq( '[data-magicauth-pk-reauth-passkey]' ).hidden = methods.indexOf( 'passkey' ) < 0;
			rq( '[data-magicauth-pk-reauth-none]' ).hidden = methods.length > 0;
			rq( '[data-magicauth-pk-reauth-form]' ).hidden = true;
			alertEl.textContent = '';
			o.show();
			focus( rq( '[data-magicauth-pk-reauth-title]' ) );
		}

		async function sendCode() {
			if ( o.ui.busy ) {
				return;
			}
			o.ui.busy = true;
			alertEl.textContent = '';
			const r = await P.post( A.reauthEmail, owner( {} ) );
			o.ui.busy = false;
			if ( ! r.ok ) {
				fail( r );
				return;
			}
			step.id = String( r.data.reauth_id || '' );
			rq( '[data-magicauth-pk-reauth-sent]' ).textContent = String( S.R5 ).replace( '%s', String( r.data.sent_to || '' ) );
			rq( '[data-magicauth-pk-reauth-form]' ).hidden = false;
			const input = rq( '[data-magicauth-pk-reauth-code]' );
			input.value = '';
			focus( input );
		}

		async function confirmCode() {
			if ( o.ui.busy || ! step.id ) {
				return;
			}
			o.ui.busy = true;
			alertEl.textContent = '';
			const r = await P.post( A.reauthCode, owner( { reauth_id: step.id, code: rq( '[data-magicauth-pk-reauth-code]' ).value } ) );
			o.ui.busy = false;
			if ( ! r.ok ) {
				fail( r );
				focus( rq( '[data-magicauth-pk-reauth-code]' ) );
				return;
			}
			step.id = '';
			o.hide( true );
		}

		async function withPasskey() {
			if ( o.ui.busy ) {
				return;
			}
			o.ui.busy = true;
			alertEl.textContent = '';
			try {
				const opts = await P.post( A.reauthOptions, owner( {} ) );
				if ( ! opts.ok ) {
					fail( opts );
					return;
				}
				let cred;
				try {
					cred = await navigator.credentials.get( { publicKey: P.parseRequest( opts.data.publicKey ) } );
				} catch ( e ) {
					fail( { status: 0, data: { code: 'reauth_failed' } } );
					return;
				}
				const json = P.toJSON( cred );
				const r = await P.post( A.reauthPasskey, owner( { credential: JSON.stringify( json ) } ) );
				if ( ! r.ok ) {
					if ( r.data.unknown_credential === true && json.id ) {
						P.signal( 'signalUnknownCredential', { rpId: cfg.rpId, credentialId: json.id } );
					}
					fail( r );
					return;
				}
				o.hide( true );
			} finally {
				o.ui.busy = false;
			}
		}

		if ( ! reauth.hasAttribute( 'data-magicauth-pk-bound' ) ) {
			reauth.setAttribute( 'data-magicauth-pk-bound', '' );
			rq( '[data-magicauth-pk-reauth-email]' ).addEventListener( 'click', sendCode );
			rq( '[data-magicauth-pk-reauth-resend]' ).addEventListener( 'click', sendCode );
			rq( '[data-magicauth-pk-reauth-passkey]' ).addEventListener( 'click', withPasskey );
			rq( '[data-magicauth-pk-reauth-cancel]' ).addEventListener( 'click', function () {
				o.hide( false );
			} );
			const form = rq( '[data-magicauth-pk-reauth-form]' );
			if ( form.tagName === 'FORM' ) {
				// R7 is the form's only submit button; Enter submits it, never the profile form or the dialog.
				form.addEventListener( 'submit', function ( e ) {
					e.preventDefault();
					confirmCode();
				} );
			} else {
				rq( '[data-magicauth-pk-reauth-confirm]' ).addEventListener( 'click', confirmCode );
				rq( '[data-magicauth-pk-reauth-code]' ).addEventListener( 'keydown', function ( e ) {
					if ( e.key === 'Enter' ) {
						e.preventDefault();
						confirmCode();
					}
				} );
			}
		}
		return { show: show };
	}

	/* ------------------------------------------------------------ list items (as passkeys-manage.php) */

	function itemEl( it, canRename ) {
		const li = make( 'li', 'magicauth-pk-item' );
		li.setAttribute( 'data-magicauth-pk-item', '' );
		li.setAttribute( 'data-id', String( it.id ) );
		const body = make( 'div', 'magicauth-pk-item__body' );
		const name = make( 'p', 'magicauth-pk-item__name' );
		const bdi = make( 'bdi', '', String( it.name || '' ) );
		bdi.setAttribute( 'data-magicauth-pk-name', '' );
		name.appendChild( bdi );
		body.appendChild( name );
		body.appendChild( make( 'p', 'magicauth-pk-item__label', String( it.label || '' ) ) );

		const meta = make( 'p', 'magicauth-pk-item__meta' );
		meta.appendChild( make( 'span', '', it.provider ? String( S.M31 ).replace( '%s', it.provider ) : S.M30 ) );
		meta.appendChild( document.createTextNode( ' ' ) );
		meta.appendChild( make( 'span', '', it.synced ? S.M6 : ( it.sync_possible ? S.M6b : S.M7 ) ) );
		body.appendChild( meta );

		const dates = make( 'p', 'magicauth-pk-item__meta' );
		const created = make( 'time', '', String( it.created_label || '' ) );
		created.setAttribute( 'datetime', String( it.created || '' ) );
		dates.appendChild( created );
		dates.appendChild( document.createTextNode( ' ' ) );
		if ( typeof it.last_used === 'string' ) {
			const used = make( 'time', '', String( it.last_used_label || '' ) );
			used.setAttribute( 'datetime', it.last_used );
			dates.appendChild( used );
		} else {
			dates.appendChild( make( 'span', '', S.M10 ) );
		}
		body.appendChild( dates );

		if ( it.is_new || it.blocked ) {
			const badges = make( 'p', 'magicauth-pk-badges' );
			if ( it.is_new ) {
				badges.appendChild( make( 'span', 'magicauth-pk-badge', S.M13 ) );
			}
			if ( it.blocked ) {
				badges.appendChild( make( 'span', 'magicauth-pk-badge magicauth-pk-badge--warning', S.M36 ) );
			}
			body.appendChild( badges );
		}
		if ( ! it.usable_here ) {
			body.appendChild( make( 'p', 'magicauth-pk-item__note', S.M11 ) );
		}
		if ( it.blocked ) {
			body.appendChild( make( 'p', 'magicauth-pk-item__warning', S.M12 ) );
		}
		li.appendChild( body );

		const actions = make( 'div', 'magicauth-pk-item__actions' );
		actions.setAttribute( 'data-magicauth-pk-actions', '' );
		const button = function ( attr, visible, suffix ) {
			const b = make( 'button', 'magicauth-pk-btn', visible );
			b.type = 'button';
			b.setAttribute( attr, '' );
			const sr = make( 'span', 'magicauth-pk-sr-only' );
			bdiText( sr, ' ' + suffix, String( it.name || '' ) );
			b.appendChild( sr );
			actions.appendChild( b );
		};
		if ( canRename && ! it.blocked ) {
			button( 'data-magicauth-pk-rename', S.M14v, S.M14s );
		}
		button( 'data-magicauth-pk-remove', S.M18v, S.M18s );
		li.appendChild( actions );
		return li;
	}

	/* ------------------------------------------------------------ one management section */

	function init( sec ) {
		const admin = sec.getAttribute( 'data-magicauth-pk-mode' ) !== 'manage';
		const userId = sec.getAttribute( 'data-magicauth-pk-user' ) || '';
		const adminNonce = sec.getAttribute( 'data-magicauth-pk-admin-nonce' ) || '';
		// Dialogs outside the section (wp-admin footer) are found only through the ids the section names.
		const dialogIds = String( sec.getAttribute( 'data-magicauth-pk-dialogs' ) || '' ).split( ' ' ).filter( function ( id ) {
			return /^[A-Za-z0-9_-]+$/.test( id );
		} );
		const q = function ( sel ) {
			const inside = sec.querySelector( sel );
			if ( inside ) {
				return inside;
			}
			for ( let i = 0; i < dialogIds.length; i++ ) {
				const roots = ownRoots( '[id="' + dialogIds[ i ] + '"]' );
				for ( let j = 0; j < roots.length; j++ ) {
					const hit = roots[ j ].matches( sel ) ? roots[ j ] : roots[ j ].querySelector( sel );
					if ( hit ) {
						return hit;
					}
				}
			}
			return null;
		};
		const list = sec.querySelector( '[data-magicauth-pk-list]' );
		const statusEl = sec.querySelector( '[data-magicauth-pk-status]' );
		const alertEl = sec.querySelector( '[data-magicauth-pk-alert]' );
		const title = sec.querySelector( '[data-magicauth-pk-title]' );
		const empty = sec.querySelector( '[data-magicauth-pk-empty]' );
		const add = sec.querySelector( '[data-magicauth-pk-add]' );
		const removeAll = sec.querySelector( '[data-magicauth-pk-remove-all]' );
		const ui = { busy: false, removing: null };

		const clear = function () {
			if ( alertEl ) {
				alertEl.textContent = '';
			}
		};
		const fail = function ( r, context ) {
			alertError( alertEl, ( r.data && r.data.code ) || 'unexpected', message( r, context ), context );
		};
		const asAdmin = function ( fields ) {
			return Object.assign( { _ajax_nonce: adminNonce, user_id: userId }, fields );
		};

		function render( items ) {
			if ( ! Array.isArray( items ) ) {
				// The action succeeded but the list could not be read (list_error): keep what is shown.
				alertError( alertEl, 'list_error', S.MX, 'list' );
				return;
			}
			list.textContent = '';
			( items || [] ).forEach( function ( it ) {
				list.appendChild( itemEl( it, ! admin ) );
			} );
			const none = ! items || items.length === 0;
			if ( empty ) {
				empty.hidden = ! none;
			}
			if ( removeAll ) {
				removeAll.hidden = none;
			}
		}

		// JavaScript runs: show the controls (without it the list stays read-only, M26).
		sec.querySelectorAll( '[data-magicauth-pk-rename],[data-magicauth-pk-remove],[data-magicauth-pk-signout-others]' ).forEach( function ( b ) {
			b.hidden = false;
		} );
		if ( removeAll ) {
			removeAll.hidden = ! list.querySelector( '[data-magicauth-pk-item]' );
		}
		if ( add ) {
			if ( canCreate() ) {
				add.hidden = false;
			} else {
				const no = sec.querySelector( '[data-magicauth-pk-nocreate]' );
				if ( no ) {
					no.hidden = false;
				}
			}
		}
		if ( ! admin ) {
			signals( cfg.signals );
		}

		/* -------------------------------------------- rename (inline, no <form>: Enter handled here) */

		function rename( li, btn ) {
			if ( ui.busy || li.querySelector( '[data-magicauth-pk-rename-box]' ) ) {
				return;
			}
			clear();
			const id = li.getAttribute( 'data-id' );
			const actions = li.querySelector( '[data-magicauth-pk-actions]' );
			const box = make( 'div', 'magicauth-pk-rename' );
			box.setAttribute( 'data-magicauth-pk-rename-box', '' );
			const label = make( 'label', 'magicauth-pk-label', S.M15 );
			const input = make( 'input', 'magicauth-pk-input' );
			input.type = 'text';
			input.id = 'magicauth-pk-rename-' + id;
			input.maxLength = 64;
			input.value = li.querySelector( '[data-magicauth-pk-name]' ).textContent;
			label.setAttribute( 'for', input.id );
			const row = make( 'div', 'magicauth-pk-actions' );
			const save = make( 'button', 'magicauth-pk-btn magicauth-pk-btn--primary', S.M16 );
			const cancel = make( 'button', 'magicauth-pk-btn', S.M17 );
			save.type = 'button';
			cancel.type = 'button';
			row.appendChild( save );
			row.appendChild( cancel );
			box.appendChild( label );
			box.appendChild( input );
			box.appendChild( row );
			li.appendChild( box );
			if ( actions ) {
				actions.hidden = true;
			}
			focus( input );

			const close = function () {
				box.remove();
				if ( actions ) {
					actions.hidden = false;
				}
				focus( btn );
			};
			const submit = async function () {
				if ( ui.busy ) {
					return;
				}
				ui.busy = true;
				busy( save, true );
				clear();
				const r = await P.post( A.rename, owner( { id: id, name: input.value } ) );
				ui.busy = false;
				busy( save, false );
				if ( ! r.ok ) {
					fail( r, 'rename' );
					focus( input );
					return;
				}
				render( r.data.passkeys );
				const again = list.querySelector( '[data-id="' + id + '"] [data-magicauth-pk-rename]' );
				focus( again || title );
				P.liveRegion( statusEl, S.M23 );
				signals( r.data.signal );
			};
			input.addEventListener( 'keydown', function ( e ) {
				if ( e.key === 'Enter' ) {
					e.preventDefault();
					submit();
				} else if ( e.key === 'Escape' ) {
					e.preventDefault();
					close();
				}
			} );
			save.addEventListener( 'click', submit );
			cancel.addEventListener( 'click', close );
		}

		/* -------------------------------------------- remove (confirm dialog, sign-out checked by default) */

		const removeDialog = q( '[data-magicauth-pk-remove-dialog]' );

		function openRemove( li, btn ) {
			if ( ui.busy || ! removeDialog ) {
				return;
			}
			clear();
			const name = li.querySelector( '[data-magicauth-pk-name]' ).textContent;
			const text = removeDialog.querySelector( '[data-magicauth-pk-remove-text]' );
			if ( text ) {
				bdiText( text, S.M20, name );
			}
			const nameEl = removeDialog.querySelector( '[data-magicauth-pk-remove-name]' );
			if ( nameEl ) {
				nameEl.textContent = name;
			}
			removeDialog.querySelector( '[data-magicauth-pk-signout]' ).checked = true;
			ui.removing = { id: li.getAttribute( 'data-id' ), btn: btn, done: false };
			removeDialog.showModal();
			focus( removeDialog.querySelector( '[tabindex="-1"]' ) );
		}

		async function confirmRemove() {
			const job = ui.removing;
			if ( ui.busy || ! job ) {
				return;
			}
			ui.busy = true;
			const confirmBtn = removeDialog.querySelector( '[data-magicauth-pk-remove-confirm]' );
			busy( confirmBtn, true );
			const out = removeDialog.querySelector( '[data-magicauth-pk-signout]' ).checked ? '1' : '0';
			const r = admin
				? await P.post( A.adminDelete, asAdmin( { id: job.id, signout: out } ) )
				: await P.post( A.delete, owner( { id: job.id, signout_others: out } ) );
			ui.busy = false;
			busy( confirmBtn, false );
			if ( ! r.ok ) {
				removeDialog.close(); // Focus returns to the Remove button; the error shows in the page.
				fail( r, 'remove' );
				return;
			}
			const items = Array.prototype.slice.call( list.querySelectorAll( '[data-magicauth-pk-item]' ) );
			const at = items.findIndex( function ( li ) {
				return li.getAttribute( 'data-id' ) === job.id;
			} );
			job.done = true;
			removeDialog.close();
			render( r.data.passkeys );
			const rest = list.querySelectorAll( '[data-magicauth-pk-remove]' );
			focus( rest[ at ] || rest[ at - 1 ] || title );
			P.liveRegion( statusEl, S.M22 );
			if ( ! admin ) {
				signals( r.data.signal );
			}
		}

		if ( removeDialog && ! removeDialog.hasAttribute( 'data-magicauth-pk-bound' ) ) {
			removeDialog.setAttribute( 'data-magicauth-pk-bound', '' );
			removeDialog.querySelector( '[data-magicauth-pk-remove-confirm]' ).addEventListener( 'click', confirmRemove );
			removeDialog.querySelector( '[data-magicauth-pk-remove-cancel]' ).addEventListener( 'click', function () {
				removeDialog.close();
			} );
			removeDialog.addEventListener( 'close', function () {
				// The close event is a queued task: when the dialog was opened again before it ran, the
				// event belongs to the earlier opening and must not clear the new removal (K1).
				if ( removeDialog.open ) {
					return;
				}
				const job = ui.removing;
				ui.removing = null;
				if ( job && ! job.done ) {
					focus( job.btn ); // Closed any way without removing: back to its Remove button (8.12).
				}
			} );
		}

		/* -------------------------------------------- remove all (another user, admin endpoint) */

		const allDialog = q( '[data-magicauth-pk-remove-all-dialog]' );
		if ( removeAll && allDialog ) {
			let allDone = false;
			removeAll.addEventListener( 'click', function () {
				if ( ui.busy ) {
					return;
				}
				clear();
				allDone = false;
				allDialog.querySelector( '[data-magicauth-pk-signout]' ).checked = true;
				allDialog.showModal();
				focus( allDialog.querySelector( '[tabindex="-1"]' ) );
			} );
			allDialog.querySelector( '[data-magicauth-pk-remove-all-cancel]' ).addEventListener( 'click', function () {
				allDialog.close();
			} );
			allDialog.addEventListener( 'close', function () {
				if ( allDialog.open ) {
					return; // A late close event of an earlier opening (K1).
				}
				focus( allDone ? title : removeAll );
			} );
			allDialog.querySelector( '[data-magicauth-pk-remove-all-confirm]' ).addEventListener( 'click', async function () {
				if ( ui.busy ) {
					return;
				}
				ui.busy = true;
				const out = allDialog.querySelector( '[data-magicauth-pk-signout]' ).checked ? '1' : '0';
				const r = await P.post( A.adminRevokeAll, asAdmin( { signout: out } ) );
				ui.busy = false;
				if ( ! r.ok ) {
					allDialog.close();
					fail( r, 'remove' );
					return;
				}
				allDone = true;
				allDialog.close();
				render( [] );
				P.liveRegion( statusEl, String( r.data.message || '' ) );
			} );
		}

		/* -------------------------------------------- sign out on all other devices (6.14) */

		const signout = sec.querySelector( '[data-magicauth-pk-signout-others]' );
		if ( signout ) {
			signout.addEventListener( 'click', async function () {
				if ( ui.busy ) {
					return;
				}
				ui.busy = true;
				busy( signout, true );
				clear();
				const r = await P.post( A.signoutOthers, owner( {} ) );
				ui.busy = false;
				busy( signout, false );
				if ( ! r.ok ) {
					fail( r, 'signout' );
					return;
				}
				P.liveRegion( statusEl, S.M38 );
			} );
		}

		/* -------------------------------------------- add: create, with step-up when not fresh (2.1, 3.5) */

		const reauth = admin ? null : q( '[data-magicauth-pk-view="reauth"]' );
		const reauthDialog = reauth ? reauth.closest( '[data-magicauth-pk-reauth-dialog]' ) : null;
		const steps = reauth ? stepUp( reauth, {
			ui: ui,
			show: function () {
				reauth.hidden = false;
				if ( reauthDialog && ! reauthDialog.open ) {
					reauthDialog.showModal();
				}
			},
			hide: function ( confirmed ) {
				reauth.hidden = true;
				if ( reauthDialog && reauthDialog.open ) {
					reauthDialog.close();
				}
				focus( add );
				if ( confirmed ) {
					P.liveRegion( statusEl, S.R10 ); // The user clicks Add again: a new gesture.
				}
			},
		} ) : null;
		if ( reauthDialog && ! reauthDialog.hasAttribute( 'data-magicauth-pk-bound' ) ) {
			reauthDialog.setAttribute( 'data-magicauth-pk-bound', '' );
			// Esc counts as cancel; focus returns to Add.
			reauthDialog.addEventListener( 'close', function () {
				if ( ! reauth.hidden ) {
					reauth.hidden = true;
					focus( add );
				}
			} );
		}

		if ( add ) {
			add.addEventListener( 'click', onCreateClick( {
				ui: ui,
				button: add,
				label: '',
				status: statusEl,
				alert: alertEl,
				prompt: false,
				reauth: function ( methods ) {
					if ( steps ) {
						steps.show( methods );
					} else {
						alertError( alertEl, 'reauth_required', S.R14, 'create' );
					}
				},
				fail: function ( code, text ) {
					alertError( alertEl, code || 'unexpected', text, 'create' );
				},
				done: function ( r ) {
					render( r.data.passkeys );
					P.liveRegion( statusEl, S.M24 );
					signals( r.data.signal );
				},
			} ) );
		}

		/* -------------------------------------------- per-item buttons (delegated: the list re-renders) */

		list.addEventListener( 'click', function ( e ) {
			const btn = e.target.closest( 'button' );
			const li = btn && btn.closest( '[data-magicauth-pk-item]' );
			if ( ! li ) {
				return;
			}
			if ( btn.hasAttribute( 'data-magicauth-pk-rename' ) && ! admin ) {
				rename( li, btn );
			} else if ( btn.hasAttribute( 'data-magicauth-pk-remove' ) ) {
				openRemove( li, btn );
			}
		} );
	}

	/* ------------------------------------------------------------ post-login prompt (2.1, 8.5, 8.12) */

	// Client gate (2.1, 8.3): G1 with create(), not a shared device, no recent failure or local passkey
	// for this account in this browser, then G3. Nothing is sent when it fails; cadence stays as it is.
	async function promptGate() {
		if ( ! canCreate() ) {
			return false;
		}
		try {
			if ( window.localStorage.getItem( NOPROMPT ) !== null ) {
				return false;
			}
		} catch ( e ) {
			// Throwing storage counts as absent.
		}
		const mine = entry();
		const now = Date.now();
		if ( typeof mine.promptfail === 'number' && now - mine.promptfail < 30 * DAY ) {
			return false;
		}
		if ( typeof mine.haslocal === 'number' && now - mine.haslocal < 90 * DAY ) {
			return false;
		}
		const c = await P.caps();
		const keys = [ 'passkeyPlatformAuthenticator', 'userVerifyingPlatformAuthenticator', 'hybridTransport' ];
		if ( keys.some( function ( k ) {
			return c[ k ] === true;
		} ) ) {
			return true;
		}
		if ( keys.every( function ( k ) {
			return c[ k ] === false;
		} ) ) {
			return false;
		}
		try {
			const uvpa = PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable;
			return typeof uvpa === 'function' && ( await uvpa.call( PublicKeyCredential ) ) === true;
		} catch ( e ) {
			return false;
		}
	}

	function prompt( dlg ) {
		const views = {};
		[ 'offer', 'reauth', 'success', 'error' ].forEach( function ( name ) {
			views[ name ] = dlg.querySelector( '[data-magicauth-pk-view="' + name + '"]' );
		} );
		const title = dlg.querySelector( '[data-magicauth-pk-title]' );
		const statusEl = dlg.querySelector( '[data-magicauth-pk-status]' );
		const alertEl = dlg.querySelector( '[data-magicauth-pk-alert]' );
		const errorText = dlg.querySelector( '[data-magicauth-pk-error-text]' );
		const success = dlg.querySelector( '[data-magicauth-pk-success]' );
		const offerCreate = views.offer.querySelector( '[data-magicauth-pk-create]' );
		const state = { ui: { busy: false }, view: 'offer', recorded: false, restoring: false, opener: document.activeElement };

		function show( name ) {
			Object.keys( views ).forEach( function ( v ) {
				if ( views[ v ] ) {
					views[ v ].hidden = v !== name;
				}
			} );
			state.view = name;
		}

		// One choice per dialog; a successful creation counts as one (2.1 cadence).
		function choose( choice ) {
			if ( state.recorded ) {
				return;
			}
			state.recorded = true;
			P.post( A.promptChoice, owner( { choice: choice } ) );
		}

		// Error view (8.6): the text, focus on it (8.12), then the alert region.
		function failView( code, text ) {
			show( 'error' );
			errorText.textContent = text;
			focus( errorText );
			alertError( alertEl, code || 'unexpected', text, 'create' );
		}

		const steps = views.reauth ? stepUp( views.reauth, {
			ui: state.ui,
			show: function () {
				show( 'reauth' );
			},
			hide: function ( confirmed ) {
				show( 'offer' );
				focus( offerCreate );
				if ( confirmed ) {
					P.liveRegion( statusEl, S.R10 ); // P4 again: a new gesture.
				}
			},
		} ) : null;

		dlg.querySelectorAll( '[data-magicauth-pk-create]' ).forEach( function ( btn ) {
			btn.addEventListener( 'click', onCreateClick( {
				ui: state.ui,
				button: btn,
				label: S.P7,
				status: statusEl,
				alert: alertEl,
				prompt: true,
				reauth: function ( methods ) {
					if ( steps ) {
						steps.show( methods );
					} else {
						failView( 'reauth_required', S.R14 );
					}
				},
				fail: failView,
				done: function ( r ) {
					state.recorded = true;
					if ( ! dlg.open && ! state.restoring ) {
						// Closed while the passkey was saved (a repeated Esc can still get through): show the
						// outcome. A failure after a close stays closed: the dismissal is not re-offered.
						prompting = state;
						dlg.showModal();
					}
					show( 'success' );
					focus( success );
					P.liveRegion( statusEl, success.textContent );
					signals( r.data.signal );
				},
			} ) );
		} );
		dlg.querySelectorAll( '[data-magicauth-pk-later]' ).forEach( function ( btn ) {
			btn.addEventListener( 'click', function () {
				if ( state.ui.busy ) {
					return;
				}
				// "Not now" after a failure is not a decline: the user could not make one (2.1).
				choose( state.view === 'error' ? 'failed' : 'later' );
				dlg.close();
			} );
		} );
		const shared = dlg.querySelector( '[data-magicauth-pk-shared]' );
		if ( shared ) {
			shared.addEventListener( 'click', function () {
				if ( state.ui.busy ) {
					return;
				}
				try {
					window.localStorage.setItem( NOPROMPT, '1' );
				} catch ( e ) {
					// The cookie still covers this browser.
				}
				choose( 'device' );
				dlg.close();
			} );
		}
		[ '[data-magicauth-pk-close]', '[data-magicauth-pk-done]' ].forEach( function ( sel ) {
			const btn = dlg.querySelector( sel );
			if ( btn ) {
				btn.addEventListener( 'click', function () {
					if ( state.ui.busy ) {
						return; // A creation is pending: its outcome shows here.
					}
					dlg.close();
				} );
			}
		} );
		// Esc while a creation is pending: stay open for its outcome.
		dlg.addEventListener( 'cancel', function ( e ) {
			if ( state.ui.busy ) {
				e.preventDefault();
			}
		} );

		// Esc, the back gesture and the close button end here: a dismissal unless a choice was made.
		dlg.addEventListener( 'close', function () {
			if ( dlg.open ) {
				return; // A late close event of an earlier opening (reopened by done()).
			}
			prompting = null;
			if ( ! state.restoring ) {
				choose( state.view === 'error' ? 'failed' : 'dismiss' );
			}
			state.recorded = true;
			const back = state.opener;
			if ( back && back !== document.body && document.body.contains( back ) && typeof back.focus === 'function' ) {
				back.focus();
			} else if ( document.body ) {
				document.body.setAttribute( 'tabindex', '-1' );
				document.body.focus();
				document.body.removeAttribute( 'tabindex' );
			}
		} );

		prompting = state;
		dlg.showModal();
		focus( title );
	}

	/* ------------------------------------------------------------ start */

	function start() {
		// No credential for this RP ID: this browser cannot hold one for the account (5.3); promptfail stays.
		if ( Array.isArray( cfg.passkeys ) && ! cfg.passkeys.some( function ( it ) {
			return it && it.usable_here;
		} ) ) {
			forget();
		}
		const sections = ownRoots( '[data-magicauth-pk-manage]' );
		sections.forEach( function ( sec ) {
			init( sec );
		} );
		if ( sections.length === 0 && cfg.signals ) {
			signals( cfg.signals ); // Session-time signals on a prompt page (8.7).
		}
		const dlg = ownRoots( '[data-magicauth-pk-prompt]' )[ 0 ] || null;
		if ( dlg && cfg.prompt && cfg.prompt.show === true && typeof dlg.showModal === 'function' ) {
			promptGate().then( function ( ok ) {
				if ( ok && ! dlg.open ) {
					prompt( dlg );
				}
			} );
		}
	}

	if ( document.readyState === 'loading' ) {
		document.addEventListener( 'DOMContentLoaded', start );
	} else {
		start();
	}
}() );
