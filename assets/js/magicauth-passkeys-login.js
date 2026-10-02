// MagicAuth passkeys: sign-in only (SPEC 2.2, 8.4, 8.6, 8.9). Autofill (conditional mediation), the
// "Sign in with a passkey" button, verify, then a top-level completion POST. ES2017, vanilla.
( function () {
	'use strict';

	const api = window.MagicAuthPasskeys;
	const cfg = window.magicauthPasskeysConfig;
	if ( ! api || ! cfg || ! cfg.actions ) {
		return;
	}

	const i18n = cfg.i18n || {};
	const PARAM = 'magicauth_passkey_error';
	const STRINGS = { passkey_failed: 'L3', throttled: 'L4', other_account: 'L5', retry: 'L6', unavailable: 'L7', reverify_required: 'L8' };
	const URL_STRINGS = { passkey_failed: 'L3', other_account: 'L5', retry: 'L6', reverify_required: 'L8' };
	const IDLE_REFRESHES = 6; // About 54 minutes of timer refreshes, then wait for focus or visibility.
	const THROTTLE_MS = 60000;
	const EXPIRY_MARGIN_MS = 5000;
	const FOCUS_MARGIN_S = 30;

	let root = null;
	let button = null;
	let statusEl = null;
	let errorEl = null;
	let input = null;
	let g4 = false;
	let current = null; // { ac, issuedAt, ttl, refreshAfter } of the conditional request.
	let pending = null; // Its promise; never rejects.
	let restartsLeft = 1;
	let refreshes = 0;
	let timer = 0;
	let stopped = false;
	let autofillOff = false;
	let busy = false;
	let completing = false;
	let l3bShown = false;
	let throttledUntil = 0;

	function say( key ) {
		return i18n[ key ] || i18n.L3 || '';
	}

	function emit( name, detail, cancelable ) {
		return document.dispatchEvent( new CustomEvent( 'magicauth:passkey:' + name, { detail: detail, cancelable: cancelable } ) );
	}

	function status( text ) {
		api.liveRegion( statusEl, text );
	}

	// Errors stay until the next action; a theme can cancel the event and render the message itself.
	function showError( code, message, context ) {
		if ( emit( 'error', { code: code, message: message, context: context }, true ) ) {
			api.liveRegion( errorEl, message );
		}
	}

	function clearError() {
		if ( errorEl ) {
			errorEl.textContent = '';
		}
	}

	function marked( code ) {
		const e = new Error( code );
		e.code = code;
		e.shown = true;
		return e;
	}

	function redirectTo() {
		const own = ( button && button.getAttribute( 'data-magicauth-redirect-to' ) ) || ( root && root.getAttribute( 'data-magicauth-redirect-to' ) );
		if ( own ) {
			return own;
		}
		const form = ( input && input.form ) || ( button && button.form );
		const field = form ? form.querySelector( 'input[name="redirect_to"]' ) : null;
		return field && field.value ? field.value : window.location.href;
	}

	function abortCurrent() {
		clearTimeout( timer );
		if ( current ) {
			current.ac.abort();
			current = null;
		}
	}

	function start( kind ) {
		if ( stopped || autofillOff || busy || ! input || ! g4 ) {
			return;
		}
		if ( kind !== 'recover' ) {
			restartsLeft = 1; // A planned start gets a fresh error budget.
		}
		const req = { ac: new AbortController(), issuedAt: 0, ttl: 600, refreshAfter: 540 };
		current = req;
		pending = run( req ).catch( function ( e ) {
			onConditionalError( e, req );
		} );
	}

	// Error and expiry recovery; never resets the budget.
	function restart() {
		start( 'recover' );
	}

	function num( value, fallback ) {
		return typeof value === 'number' && value > 0 ? value : fallback;
	}

	function schedule( ms ) {
		clearTimeout( timer );
		timer = setTimeout( function () {
			maybeRefresh( true );
		}, Math.max( 0, ms ) );
	}

	async function run( req ) {
		const r = await api.post( cfg.actions.signinOptions );
		if ( req.ac.signal.aborted ) {
			return;
		}
		if ( ! r.ok ) {
			// Throttled, unavailable, unexpected: stop autofill silently; the button still works.
			autofillOff = true;
			current = null;
			return;
		}
		req.issuedAt = Date.now();
		req.ttl = num( r.data.ttl, 600 );
		req.refreshAfter = num( r.data.refresh_after, 540 );
		refreshes++;
		schedule( req.refreshAfter * 1000 );
		const cred = await navigator.credentials.get( {
			mediation: 'conditional',
			signal: req.ac.signal,
			publicKey: api.parseRequest( r.data.publicKey ),
		} );
		if ( current === req ) {
			current = null;
			clearTimeout( timer );
		}
		if ( Date.now() - req.issuedAt >= req.ttl * 1000 - EXPIRY_MARGIN_MS ) {
			// Signed over an expired challenge: needs a new pick, so it spends no budget.
			showError( 'expired', say( 'L11' ), 'conditional' );
			restart();
			return;
		}
		// Clicks wait while this pick is verified: no second ceremony during the completion (r1-frontend-03).
		const own = ! busy; // A click already waiting on this pick keeps its own busy state.
		if ( own ) {
			setBusy( true );
		}
		try {
			await finish( cred, 'conditional' );
		} finally {
			if ( own ) {
				setBusy( false );
			}
		}
	}

	// "Ours" is decided from the controller, never from the rejection's type (w3c/webauthn 2240).
	function onConditionalError( e, req ) {
		if ( req.ac.signal.aborted ) {
			return;
		}
		if ( current === req ) {
			current = null;
		}
		const code = e && e.code;
		if ( ( code === 'passkey_failed' || code === 'retry' || ( e && e.name === 'NotAllowedError' ) ) && restartsLeft-- > 0 ) {
			restart();
			return;
		}
		if ( ! ( e && e.shown ) ) {
			window.console.warn( 'MagicAuth: passkey autofill stopped.', e );
		}
		autofillOff = true;
	}

	// Timer, visibility, focus, pageshow. A user-driven trigger resets the idle cap.
	function maybeRefresh( fromTimer ) {
		if ( ! fromTimer ) {
			refreshes = 0;
		}
		if ( stopped || autofillOff || busy || ! current || ! current.issuedAt ) {
			return;
		}
		if ( document.visibilityState !== 'visible' || ( fromTimer && refreshes > IDLE_REFRESHES ) ) {
			return;
		}
		const age = Date.now() - current.issuedAt;
		if ( document.activeElement === input ) {
			// Accept that the autofill list re-opens, but only close to expiry.
			if ( age >= ( current.ttl - FOCUS_MARGIN_S ) * 1000 ) {
				abortCurrent();
				start( 'refresh' );
			} else if ( fromTimer ) {
				schedule( ( current.ttl - FOCUS_MARGIN_S ) * 1000 - age );
			}
		} else if ( age >= current.refreshAfter * 1000 ) {
			abortCurrent();
			start( 'refresh' );
		}
	}

	async function finish( cred, source ) {
		emit( 'start', { source: source }, false );
		const json = api.toJSON( cred );
		const r = await api.post( cfg.actions.signin, { credential: JSON.stringify( json ), redirect_to: redirectTo() } );
		if ( r.ok && typeof r.data.complete === 'string' ) {
			emit( 'success', { redirect: r.data.redirect }, false );
			status( say( 'L10' ) );
			completing = true;
			stopped = true;
			abortCurrent();
			submitCompletion( r.data.complete );
			return;
		}
		if ( r.data.unknown_credential === true ) {
			api.signal( 'signalUnknownCredential', { rpId: cfg.rpId, credentialId: json.id } );
		}
		serverError( r, source );
		throw marked( r.data.code );
	}

	function serverError( r, source ) {
		const code = r.data.code;
		if ( code === 'unexpected' || code === 'network' ) {
			autofillOff = true;
		}
		if ( code === 'unavailable' ) {
			hideButton();
		}
		// A runtime number in the copy only the server can pluralise (SPEC 6.10).
		const message = code === 'throttled' && r.data.retry_after && r.data.message ? r.data.message : say( STRINGS[ code ] || 'L3' );
		showError( code, message, source );
		if ( code === 'throttled' ) {
			throttle();
		}
	}

	// Modal get() and parse failures (SPEC 8.6).
	function clientError( e ) {
		const name = e && e.name;
		if ( name === 'AbortError' ) {
			return;
		}
		if ( name === 'SecurityError' || name === 'NotSupportedError' ) {
			hideButton();
			showError( name, say( 'L7' ), 'button' );
			return;
		}
		let message = say( 'L3' );
		if ( name === 'NotAllowedError' && ! l3bShown ) {
			l3bShown = true;
			message += ' ' + say( 'L3b' );
		} else if ( name !== 'NotAllowedError' && name !== 'ConstraintError' ) {
			window.console.error( 'MagicAuth: passkey sign-in failed.', e );
		}
		showError( name || 'unexpected', message, 'button' );
	}

	// A focused button that hides would drop focus to the body (WCAG 2.4.3): move it to the email input,
	// else to the error region.
	function hideButton() {
		autofillOff = true;
		abortCurrent();
		if ( ! button ) {
			return;
		}
		const hadFocus = document.activeElement === button;
		button.hidden = true;
		if ( ! hadFocus ) {
			return;
		}
		if ( input && typeof input.focus === 'function' ) {
			input.focus();
		} else if ( errorEl && typeof errorEl.focus === 'function' ) {
			errorEl.setAttribute( 'tabindex', '-1' );
			errorEl.focus();
		}
	}

	// Throttled: the button keeps focus, gets aria-disabled and ignores clicks for 60 s (SPEC 8.12).
	function throttle() {
		throttledUntil = Date.now() + THROTTLE_MS;
		autofillOff = true;
		abortCurrent();
		if ( ! button ) {
			return;
		}
		button.setAttribute( 'aria-disabled', 'true' );
		setTimeout( function () {
			throttledUntil = 0;
			if ( ! busy ) {
				button.removeAttribute( 'aria-disabled' );
			}
			status( say( 'L1' ) );
		}, THROTTLE_MS );
	}

	function setBusy( on ) {
		busy = on;
		if ( ! button ) {
			return;
		}
		button.classList.toggle( 'is-loading', on );
		if ( on ) {
			button.setAttribute( 'aria-busy', 'true' );
			button.setAttribute( 'aria-disabled', 'true' );
		} else {
			button.removeAttribute( 'aria-busy' );
			if ( Date.now() >= throttledUntil ) {
				button.removeAttribute( 'aria-disabled' );
			}
		}
	}

	async function onClick( ev ) {
		ev.preventDefault();
		if ( busy || completing || Date.now() < throttledUntil ) {
			return;
		}
		setBusy( true );
		clearError();
		status( say( 'L2' ) );
		emit( 'start', { source: 'button' }, false );
		// Started inside the gesture; the last promise awaited before get() (pre-17.4 WebKit, checklist 5.3).
		const optionsFetch = api.post( cfg.actions.signinOptions );
		const settled = pending || Promise.resolve();
		abortCurrent();
		try {
			// Chrome rejects a modal get() while a conditional one is pending: settle it first.
			await settled;
			if ( completing || stopped ) {
				return; // The conditional pick finished meanwhile: the completion is on its way.
			}
			const opts = await optionsFetch;
			if ( completing || stopped ) {
				return;
			}
			if ( ! opts.ok ) {
				serverError( opts, 'button' );
				return;
			}
			const publicKey = api.parseRequest( opts.data.publicKey );
			let cred;
			try {
				cred = await navigator.credentials.get( { publicKey: publicKey } );
			} catch ( e ) {
				if ( ! e || e.name !== 'OperationError' ) {
					throw e;
				}
				// Another request was still pending (ours): abort it and retry once, silently.
				abortCurrent();
				await ( pending || Promise.resolve() );
				cred = await navigator.credentials.get( { publicKey: publicKey } );
			}
			await finish( cred, 'button' );
		} catch ( e ) {
			if ( ! ( e && e.shown ) ) {
				clientError( e );
			}
		} finally {
			setBusy( false );
			if ( ! completing ) {
				restart(); // The button never spends the autofill budget.
			}
		}
	}

	// Top-level POST navigation: wp_login interstitials (two-factor, terms) run as on any sign-in.
	function submitCompletion( token ) {
		const form = document.createElement( 'form' );
		form.method = 'post';
		form.action = cfg.ajaxUrl;
		form.hidden = true;
		const fields = { action: cfg.actions.complete, token: token, redirect_to: redirectTo(), return_to: window.location.href };
		Object.keys( fields ).forEach( function ( name ) {
			const field = document.createElement( 'input' );
			field.type = 'hidden';
			field.name = name;
			field.value = fields[ name ];
			form.appendChild( field );
		} );
		document.body.appendChild( form );
		form.submit();
	}

	// A failed completion returns here with ?magicauth_passkey_error=<code>: show it, drop the parameter.
	function showReturnError() {
		let url;
		try {
			url = new URL( window.location.href );
		} catch ( e ) {
			return;
		}
		const code = url.searchParams.get( PARAM );
		if ( code === null ) {
			return;
		}
		url.searchParams.delete( PARAM );
		try {
			window.history.replaceState( window.history.state, '', url.toString() );
		} catch ( e ) {
			// The message still shows.
		}
		showError( code, say( URL_STRINGS[ code ] || 'L3' ), 'complete' );
	}

	async function conditionalAvailable() {
		const caps = await api.caps();
		if ( caps.conditionalGet === true ) {
			return true;
		}
		try {
			return typeof PublicKeyCredential.isConditionalMediationAvailable === 'function' &&
				( await PublicKeyCredential.isConditionalMediationAvailable() ) === true;
		} catch ( e ) {
			return false;
		}
	}

	// Back/forward cache restore: a completion or an email submit did not leave the page for good (a
	// wp_login interstitial, a cancelled navigation). Everything they stopped starts again.
	function onRestore() {
		completing = false;
		stopped = false;
		setBusy( false );
		clearError();
		if ( statusEl && statusEl.textContent === say( 'L10' ) ) {
			statusEl.textContent = '';
		}
		refreshes = 0;
		abortCurrent();
		start( 'refresh' );
	}

	// The form that holds the webauthn input and the sign-in block: look-alike markup elsewhere on the page
	// (post content above a shortcode form) never takes the button, root or regions (r1-frontend-01).
	function scopeForm( inputs ) {
		for ( let i = 0; i < inputs.length; i++ ) {
			const form = inputs[ i ].form;
			if ( form && form.querySelector( '[data-magicauth-passkey-signin]' ) ) {
				return form;
			}
		}
		return null;
	}

	async function init() {
		if ( ! api.g1() ) {
			return;
		}
		// Exactly one autofill input; none or several: no autofill.
		const inputs = document.querySelectorAll( 'input[autocomplete~="webauthn"]' );
		const scope = scopeForm( inputs );
		const find = function ( sel ) {
			return ( scope && scope.querySelector( sel ) ) || document.querySelector( sel );
		};
		root = find( '[data-magicauth-passkey-root]' );
		button = find( '[data-magicauth-passkey-signin]' );
		statusEl = find( '[data-magicauth-passkey-status]' ) || document.getElementById( 'magicauth-status' );
		errorEl = find( '[data-magicauth-passkey-error]' ) || document.getElementById( 'magicauth-status' );
		if ( root ) {
			root.hidden = false;
		}
		if ( button ) {
			button.hidden = false;
			button.addEventListener( 'click', onClick );
		}
		showReturnError();

		window.addEventListener( 'pagehide', abortCurrent );
		window.addEventListener( 'pageshow', function ( e ) {
			if ( e.persisted ) {
				onRestore();
			} else {
				maybeRefresh( false );
			}
		} );

		input = inputs.length === 1 ? inputs[ 0 ] : null;
		if ( ! input ) {
			return;
		}
		if ( input.form ) {
			input.form.addEventListener( 'submit', function () {
				stopped = true;
				abortCurrent();
			} );
		}
		document.addEventListener( 'visibilitychange', function () {
			maybeRefresh( false );
		} );
		input.addEventListener( 'focus', function () {
			maybeRefresh( false );
		} );

		g4 = await conditionalAvailable();
		start( 'init' );
	}

	if ( document.readyState === 'loading' ) {
		document.addEventListener( 'DOMContentLoaded', init );
	} else {
		init();
	}
}() );
