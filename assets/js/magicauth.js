// Front-end polish only — form works without JS. Server normalizes input.
( function () {
	'use strict';

	function init() {
		var emailInput = document.getElementById( 'magicauth-email' );
		if ( emailInput ) {
			enhanceEmailInput( emailInput );
		}

		var codeInput = document.getElementById( 'magicauth-code' );
		if ( codeInput ) {
			enhanceCodeInput( codeInput );
			try {
				codeInput.focus( { preventScroll: true } );
			} catch ( e ) {
				codeInput.focus();
			}
		}

		attachSubmitLoading();
		initToast();
		initLangSwitcher();
	}

	// Language switcher: native <details> handles open/close on its own. This
	// adds outside-click + Escape dismissal and mirrors aria-expanded on the
	// summary for screen readers. Fully functional without JS.
	function initLangSwitcher() {
		var widgets = document.querySelectorAll( '.magicauth-lang' );
		if ( ! widgets.length ) {
			return;
		}

		Array.prototype.forEach.call( widgets, function ( details ) {
			var summary = details.querySelector( 'summary' );
			if ( ! summary ) {
				return;
			}
			summary.setAttribute( 'aria-expanded', details.open ? 'true' : 'false' );
			details.addEventListener( 'toggle', function () {
				summary.setAttribute( 'aria-expanded', details.open ? 'true' : 'false' );
			} );
		} );

		document.addEventListener( 'click', function ( ev ) {
			Array.prototype.forEach.call( widgets, function ( details ) {
				if ( details.open && ! details.contains( ev.target ) ) {
					details.removeAttribute( 'open' );
				}
			} );
		} );

		document.addEventListener( 'keydown', function ( ev ) {
			if ( 'Escape' !== ev.key && 'Esc' !== ev.key ) {
				return;
			}
			Array.prototype.forEach.call( widgets, function ( details ) {
				if ( ! details.open ) {
					return;
				}
				details.removeAttribute( 'open' );
				var summary = details.querySelector( 'summary' );
				if ( summary ) {
					summary.focus();
				}
			} );
		} );
	}

	// Submit-loading state; page navigates after, so no cleanup. Skip if button disabled.
	function attachSubmitLoading() {
		var forms = document.querySelectorAll( '.magicauth-form' );
		Array.prototype.forEach.call( forms, function ( form ) {
			form.addEventListener( 'submit', function () {
				var btn = form.querySelector( 'button[type="submit"]' );
				if ( ! btn || btn.disabled ) {
					return;
				}
				btn.classList.add( 'is-loading' );
				btn.setAttribute( 'aria-busy', 'true' );
			} );
		} );
	}

	function initToast() {
		var toast = document.getElementById( 'magicauth-toast' );
		if ( ! toast ) {
			return;
		}

		// Next frame so transition catches.
		if ( typeof window.requestAnimationFrame === 'function' ) {
			window.requestAnimationFrame( function () {
				toast.classList.add( 'is-visible' );
			} );
		} else {
			toast.classList.add( 'is-visible' );
		}

		var dismissed = false;
		function dismiss() {
			if ( dismissed ) {
				return;
			}
			dismissed = true;
			toast.classList.remove( 'is-visible' );
			setTimeout( function () {
				if ( toast.parentNode ) {
					toast.parentNode.removeChild( toast );
				}
			}, 220 );
		}

		// Errors/warnings linger — recovery text needs a beat to read.
		var hasLongDwell = toast.classList.contains( 'magicauth-toast--error' ) || toast.classList.contains( 'magicauth-toast--warning' );
		var dwell = hasLongDwell ? 10000 : 4000;
		var auto  = setTimeout( dismiss, dwell );

		var close = toast.querySelector( '.magicauth-toast__close' );
		if ( close ) {
			close.addEventListener( 'click', function () {
				clearTimeout( auto );
				dismiss();
			} );
		}

		// Strip toast flags so refresh doesn't re-trigger.
		try {
			if ( window.history && typeof window.history.replaceState === 'function' && typeof window.URL === 'function' ) {
				var url = new window.URL( window.location.href );
				var keys = [ 'magicauth_sent', 'magicauth_link_invalid', 'magicauth_error', 'magicauth_blocked', 'magicauth_block_secs' ];
				var changed = false;
				for ( var i = 0; i < keys.length; i++ ) {
					if ( url.searchParams.has( keys[ i ] ) ) {
						url.searchParams.delete( keys[ i ] );
						changed = true;
					}
				}
				if ( changed ) {
					window.history.replaceState( {}, '', url.toString() );
				}
			}
		} catch ( e ) {
			// best-effort
		}
	}

	function enhanceEmailInput( input ) {
		var button = input.form ? input.form.querySelector( 'button[type="submit"]' ) : null;
		if ( ! button ) {
			return;
		}

		// Loose "x@y.z" check just to enable the button; server's is_email() is the real gate.
		var emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

		function update() {
			var value = ( input.value || '' ).trim();
			var ok = emailRe.test( value );
			if ( ok ) {
				button.removeAttribute( 'disabled' );
				button.removeAttribute( 'aria-disabled' );
			} else {
				button.setAttribute( 'disabled', 'disabled' );
				button.setAttribute( 'aria-disabled', 'true' );
			}
		}

		update();
		input.addEventListener( 'input', update );
		input.addEventListener( 'change', update );
	}

	function enhanceCodeInput( input ) {
		var validRe = /[^A-HJ-KMNP-TV-Z0-9]/g; // strip lookalikes after fold
		var foldMap = { O: '0', I: '1', L: '1', U: 'V' };

		input.addEventListener( 'input', function () {
			var raw = ( input.value || '' ).toUpperCase();
			raw = raw.replace( /[OILU]/g, function ( ch ) {
				return foldMap[ ch ] || ch;
			} );
			raw = raw.replace( /[\s-]+/g, '' );
			raw = raw.replace( validRe, '' );
			raw = raw.slice( 0, 6 );

			var formatted = raw.length > 3
				? raw.slice( 0, 3 ) + '-' + raw.slice( 3 )
				: raw;
			if ( input.value !== formatted ) {
				input.value = formatted;
			}

			if ( raw.length === 6 ) {
				announce( 'Code complete. Submitting.' );
				if ( input.form ) {
					// Defer so screen readers can read the live region.
					setTimeout( function () {
						input.form.requestSubmit
							? input.form.requestSubmit()
							: input.form.submit();
					}, 50 );
				}
			}
		} );
	}

	function announce( text ) {
		var status = document.getElementById( 'magicauth-status' );
		if ( ! status ) {
			return;
		}
		status.textContent = '';
		// Reflow so the live region re-announces identical text.
		void status.offsetHeight;
		status.textContent = text;
	}

	if ( document.readyState === 'loading' ) {
		document.addEventListener( 'DOMContentLoaded', init );
	} else {
		init();
	}
} )();
