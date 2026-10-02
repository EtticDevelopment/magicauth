// MagicAuth passkeys: shared helpers (SPEC 8.1). No creation code here. ES2017, vanilla.
( function () {
	'use strict';

	// Base64url codec and JSON (de)serialisation: the 03 section 3 fallback, used only where the
	// native parse*FromJSON / toJSON methods are missing (Safari before 18.4).
	const B64U = /^[A-Za-z0-9_-]*$/;

	function encode( buf ) {
		const bytes = buf instanceof ArrayBuffer ? new Uint8Array( buf ) : new Uint8Array( buf.buffer, buf.byteOffset, buf.byteLength );
		let bin = '';
		for ( let i = 0; i < bytes.length; i += 0x8000 ) {
			bin += String.fromCharCode.apply( null, bytes.subarray( i, i + 0x8000 ) );
		}
		return btoa( bin ).replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=+$/, '' );
	}

	function decode( str ) {
		if ( typeof str !== 'string' || ! B64U.test( str ) || str.length % 4 === 1 ) {
			throw new DOMException( 'Invalid base64url', 'EncodingError' );
		}
		let b64 = str.replace( /-/g, '+' ).replace( /_/g, '/' );
		b64 += '='.repeat( ( 4 - ( b64.length % 4 ) ) % 4 );
		const bin = atob( b64 );
		const out = new Uint8Array( bin.length );
		for ( let i = 0; i < bin.length; i++ ) {
			out[ i ] = bin.charCodeAt( i );
		}
		return out.buffer;
	}

	function descs( list ) {
		return ( list || [] ).map( function ( d ) {
			const out = { type: d.type, id: decode( d.id ) };
			if ( d.transports ) {
				out.transports = d.transports;
			}
			return out;
		} );
	}

	function parseRequest( json ) {
		if ( typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function' ) {
			return PublicKeyCredential.parseRequestOptionsFromJSON( json );
		}
		return Object.assign( {}, json, { challenge: decode( json.challenge ), allowCredentials: descs( json.allowCredentials ) } );
	}

	function toJSON( cred ) {
		if ( typeof cred.toJSON === 'function' ) {
			return cred.toJSON();
		}
		const r = cred.response;
		const out = {
			id: cred.id,
			rawId: encode( cred.rawId ),
			type: cred.type,
			authenticatorAttachment: cred.authenticatorAttachment === null ? undefined : cred.authenticatorAttachment,
			clientExtensionResults: cred.getClientExtensionResults(),
		};
		if ( typeof r.attestationObject !== 'undefined' ) {
			const pk = typeof r.getPublicKey === 'function' ? r.getPublicKey() : null;
			out.response = {
				clientDataJSON: encode( r.clientDataJSON ),
				attestationObject: encode( r.attestationObject ),
				authenticatorData: typeof r.getAuthenticatorData === 'function' ? encode( r.getAuthenticatorData() ) : undefined,
				transports: typeof r.getTransports === 'function' ? r.getTransports() : [],
				publicKeyAlgorithm: typeof r.getPublicKeyAlgorithm === 'function' ? r.getPublicKeyAlgorithm() : undefined,
			};
			if ( pk ) {
				out.response.publicKey = encode( pk );
			}
		} else {
			out.response = {
				clientDataJSON: encode( r.clientDataJSON ),
				authenticatorData: encode( r.authenticatorData ),
				signature: encode( r.signature ),
			};
			if ( r.userHandle ) {
				out.response.userHandle = encode( r.userHandle );
			}
		}
		return out;
	}

	// admin-ajax POST (SPEC 8.1). Resolves { ok, status, data }; never rejects.
	async function post( action, fields ) {
		const cfg = window.magicauthPasskeysConfig || {};
		let res;
		try {
			res = await fetch( cfg.ajaxUrl, {
				method: 'POST',
				credentials: 'same-origin',
				cache: 'no-store',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams( Object.assign( { action: action }, fields || {} ) ),
			} );
		} catch ( e ) {
			return { ok: false, status: 0, data: { code: 'network' } };
		}
		let body = null;
		if ( /^application\/json\b/i.test( res.headers.get( 'Content-Type' ) || '' ) ) {
			try {
				body = await res.json();
			} catch ( e ) {
				body = null;
			}
		}
		if ( ! body || typeof body !== 'object' || typeof body.success !== 'boolean' ) {
			// Not the wp_send_json envelope: admin-ajax's "0", an edge error page.
			return { ok: false, status: res.status, data: { code: 'unexpected' } };
		}
		const data = body.data && typeof body.data === 'object' ? body.data : {};
		if ( ! body.success && typeof data.code !== 'string' ) {
			data.code = 'unexpected';
		}
		return { ok: body.success, status: res.status, data: data };
	}

	// Signals wrapper (03 section 7): feature-detected, every rejection swallowed.
	async function signal( method, options ) {
		try {
			const fn = window.PublicKeyCredential && PublicKeyCredential[ method ];
			if ( typeof fn !== 'function' ) {
				return;
			}
			await fn.call( PublicKeyCredential, options );
		} catch ( e ) {
			// TypeError or SecurityError: never user-visible.
		}
	}

	// getClientCapabilities(), or {} when missing or rejecting (absent key = unknown, SPEC 8.3).
	async function caps() {
		if ( ! window.PublicKeyCredential || typeof PublicKeyCredential.getClientCapabilities !== 'function' ) {
			return {};
		}
		try {
			return ( await PublicKeyCredential.getClientCapabilities() ) || {};
		} catch ( e ) {
			return {};
		}
	}

	// G1 for sign-in (SPEC 8.3).
	function g1() {
		return window.isSecureContext === true && !! window.PublicKeyCredential && !! navigator.credentials &&
			typeof navigator.credentials.get === 'function';
	}

	// Clear, then set on the next frame, so a live region re-announces identical text (SPEC 8.12).
	function liveRegion( el, text ) {
		if ( ! el ) {
			return;
		}
		el.textContent = '';
		const set = function () {
			el.textContent = text;
		};
		if ( typeof window.requestAnimationFrame === 'function' ) {
			window.requestAnimationFrame( set );
		} else {
			setTimeout( set, 0 );
		}
	}

	window.MagicAuthPasskeys = {
		b64u: { encode: encode, decode: decode },
		parseRequest: parseRequest,
		toJSON: toJSON,
		post: post,
		signal: signal,
		caps: caps,
		g1: g1,
		liveRegion: liveRegion,
	};
}() );
