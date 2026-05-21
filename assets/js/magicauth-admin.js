/** MagicAuth admin: media pickers, color sync, dirty tracking, toasts, modal, recovery + profile actions. Vanilla JS. */

(function () {
	'use strict';

	if ( document.readyState === 'loading' ) {
		document.addEventListener( 'DOMContentLoaded', init );
	} else {
		init();
	}

	function init() {
		initMediaPickers();
		initColorPickers();
		initRowDirtyMarks();
		initDirtyTracking();
		initCharCounters();
		initHexValidation();
		initFormSubmission();
		initNoticeDismissal();
		initWpNoticeScoop();
		initToastFromUrl();
		initDiscardFlash();
		initRecoveryActions();
		initSaltFix();
		initUserProfile();
	}

	// Media pickers (logo + agency favicon, via wp.media)
	function initMediaPickers() {
		var pickers = document.querySelectorAll( '[data-magicauth-media-picker]' );
		Array.prototype.forEach.call( pickers, bindMediaPicker );
	}

	function bindMediaPicker( root ) {
		var idInput  = root.querySelector( '[data-magicauth-media-id]' );
		var preview  = root.querySelector( '[data-magicauth-media-preview]' );
		var pickBtn  = root.querySelector( '[data-magicauth-media-pick]' );
		var clearBtn = root.querySelector( '[data-magicauth-media-clear]' );
		if ( ! idInput || ! pickBtn ) {
			return;
		}

		var frame;
		pickBtn.addEventListener( 'click', function ( ev ) {
			ev.preventDefault();
			if ( ! frame ) {
				frame = wp.media( {
					title: pickBtn.textContent || 'Choose image',
					button: { text: 'Use this image' },
					library: { type: [ 'image/png', 'image/jpeg', 'image/webp', 'image/svg+xml' ] },
					multiple: false
				} );
				frame.on( 'select', function () {
					var attachment = frame.state().get( 'selection' ).first().toJSON();
					idInput.value = attachment.id;
					if ( preview ) {
						preview.innerHTML = '';
						var img = document.createElement( 'img' );
						img.src = attachment.url;
						img.alt = '';
						preview.appendChild( img );
						preview.classList.add( 'magicauth-media__preview--filled' );
					}
					if ( clearBtn ) {
						clearBtn.style.display = '';
					}
					idInput.dispatchEvent( new Event( 'change', { bubbles: true } ) );
				} );
			}
			frame.open();
		} );

		if ( clearBtn ) {
			clearBtn.addEventListener( 'click', function ( ev ) {
				ev.preventDefault();
				idInput.value = '0';
				if ( preview ) {
					preview.innerHTML = '';
					preview.classList.remove( 'magicauth-media__preview--filled' );
				}
				clearBtn.style.display = 'none';
				idInput.dispatchEvent( new Event( 'change', { bubbles: true } ) );
			} );
		}
	}

	// Color picker — native swatch synced with hex text input
	function initColorPickers() {
		document.querySelectorAll( '.magicauth-admin .magicauth-color' ).forEach( function ( color ) {
			var swatch = color.querySelector( 'input[type="color"]' );
			var text   = color.querySelector( 'input[type="text"]' );
			if ( ! swatch || ! text ) {
				return;
			}

			swatch.addEventListener( 'input', function () {
				text.value = swatch.value.toUpperCase();
				text.dispatchEvent( new Event( 'input', { bubbles: true } ) );
			} );

			text.addEventListener( 'input', function () {
				var v = text.value.trim();
				if ( /^#?[0-9a-fA-F]{6}$/.test( v ) ) {
					swatch.value = v.charAt( 0 ) === '#' ? v : '#' + v;
				}
			} );
		} );
	}

	// Per-row dirty mark — auto-injected, opacity toggled via .is-dirty
	function initRowDirtyMarks() {
		document.querySelectorAll( '.magicauth-admin .magicauth-row' ).forEach( function ( row ) {
			var control = row.querySelector( '.magicauth-row__control' );
			if ( ! control ) {
				return;
			}
			var mark = document.createElement( 'span' );
			mark.className = 'magicauth-row__dirty-mark';
			mark.setAttribute( 'aria-hidden', 'true' );
			control.appendChild( mark );
		} );
	}

	// Dirty tracking — per-field signature compared against page-load snapshot.
	// A "field" = inputs sharing a `name` (text, radio group, checkbox group, hidden+checkbox toggle).
	var dirtySet, initialSig;
	var dirtyEl, numEl, labelEl, saveBtn, discardBtn, form;
	var IGNORE_NAMES = { option_page: 1, action: 1, _wpnonce: 1, _wp_http_referer: 1, submit: 1 };

	function initDirtyTracking() {
		dirtyEl    = document.querySelector( '[data-dirty]' );
		numEl      = document.querySelector( '[data-dirty-num]' );
		labelEl    = document.querySelector( '[data-dirty-label]' );
		saveBtn    = document.querySelector( '[data-save]' );
		discardBtn = document.querySelector( '[data-discard]' );
		form       = document.querySelector( '.magicauth-admin form' );
		if ( ! dirtyEl || ! saveBtn || ! form ) {
			return;
		}

		dirtySet   = {};
		initialSig = {};
		captureInitialState();
		renderDirty();

		form.addEventListener( 'input', onInteract );
		form.addEventListener( 'change', onInteract );
	}

	function isTrackable( name ) {
		return !! name && ! IGNORE_NAMES[ name ];
	}

	function cssEscape( s ) {
		if ( window.CSS && CSS.escape ) {
			return CSS.escape( s );
		}
		return String( s ).replace( /(["\\])/g, '\\$1' );
	}

	function fieldSignature( name ) {
		var els = form.querySelectorAll( '[name="' + cssEscape( name ) + '"]' );
		if ( ! els.length ) {
			return '';
		}
		var hasCheckable = false;
		for ( var i = 0; i < els.length; i++ ) {
			if ( els[ i ].type === 'checkbox' || els[ i ].type === 'radio' ) {
				hasCheckable = true;
				break;
			}
		}
		if ( hasCheckable ) {
			var vals = [];
			for ( var j = 0; j < els.length; j++ ) {
				var el = els[ j ];
				if ( ( el.type === 'checkbox' || el.type === 'radio' ) && el.checked ) {
					vals.push( el.value );
				}
			}
			vals.sort();
			return vals.join( '|' );
		}
		// Last wins, matching PHP $_POST behavior for duplicate names.
		return els[ els.length - 1 ].value;
	}

	function captureInitialState() {
		var seen = {};
		var els  = form.querySelectorAll( '[name]' );
		for ( var i = 0; i < els.length; i++ ) {
			var name = els[ i ].name;
			if ( seen[ name ] || ! isTrackable( name ) ) {
				continue;
			}
			seen[ name ]       = 1;
			initialSig[ name ] = fieldSignature( name );
		}
	}

	function updateFieldDirty( name ) {
		if ( ! isTrackable( name ) || ! ( name in initialSig ) ) {
			return;
		}
		var current = fieldSignature( name );
		if ( current === initialSig[ name ] ) {
			delete dirtySet[ name ];
		} else {
			dirtySet[ name ] = 1;
		}
		var el = form.querySelector( '[name="' + cssEscape( name ) + '"]' );
		if ( el ) {
			var row = el.closest( '.magicauth-row' );
			if ( row ) {
				row.classList.toggle( 'is-dirty', !! dirtySet[ name ] );
			}
		}
		renderDirty();
	}

	function onInteract( ev ) {
		var t = ev.target;
		if ( ! t.matches || ! t.matches( 'input, select, textarea' ) ) {
			return;
		}
		if ( ! t.name ) {
			return;
		}
		updateFieldDirty( t.name );
	}

	function dirtyCount() {
		return Object.keys( dirtySet ).length;
	}

	function renderDirty() {
		if ( ! dirtyEl ) {
			return;
		}
		var count = dirtyCount();
		if ( count === 0 ) {
			dirtyEl.classList.add( 'is-clean' );
			if ( labelEl ) {
				labelEl.textContent = '';
			}
			if ( saveBtn ) {
				saveBtn.setAttribute( 'disabled', '' );
			}
			if ( discardBtn ) {
				discardBtn.setAttribute( 'disabled', '' );
			}
		} else {
			dirtyEl.classList.remove( 'is-clean' );
			if ( numEl ) {
				numEl.textContent = count;
			}
			if ( labelEl ) {
				labelEl.textContent = count === 1 ? ' unsaved change' : ' unsaved changes';
			}
			if ( saveBtn ) {
				saveBtn.removeAttribute( 'disabled' );
			}
			if ( discardBtn ) {
				discardBtn.removeAttribute( 'disabled' );
			}
		}
	}

	// Char counters under capped text inputs
	function initCharCounters() {
		document.querySelectorAll( '[data-counter]' ).forEach( function ( el ) {
			var max = parseInt( el.getAttribute( 'maxlength' ), 10 );
			if ( ! max ) {
				return;
			}
			var counter = document.createElement( 'div' );
			counter.className = 'magicauth-field-counter';
			el.parentNode.appendChild( counter );

			function update() {
				var len = el.value.length;
				counter.textContent = len + ' / ' + max;
				counter.classList.toggle( 'magicauth-field-counter--warn', len >= max - 5 && len < max );
				counter.classList.toggle( 'magicauth-field-counter--error', len >= max );
			}

			el.addEventListener( 'input', update );
			update();
		} );
	}

	// Live hex validation
	function initHexValidation() {
		document.querySelectorAll( '[data-validate-hex]' ).forEach( function ( el ) {
			var colorEl = el.closest( '.magicauth-color' );
			if ( ! colorEl ) {
				return;
			}
			var msgEl = null;

			function validate() {
				var v = el.value.trim();
				var valid = /^#?[0-9a-fA-F]{6}$/.test( v );
				if ( v && ! valid ) {
					colorEl.classList.add( 'is-invalid' );
					el.classList.add( 'magicauth-input--invalid' );
					if ( ! msgEl ) {
						msgEl = document.createElement( 'div' );
						msgEl.className = 'magicauth-field-msg magicauth-field-msg--error';
						msgEl.innerHTML = '<svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="6" r="5"/><line x1="6" y1="3.5" x2="6" y2="6.5"/><circle cx="6" cy="8.5" r="0.6" fill="currentColor"/></svg><span>Use a 6-character hex like <code>#0F5CFA</code></span>';
						colorEl.parentNode.appendChild( msgEl );
					}
				} else {
					colorEl.classList.remove( 'is-invalid' );
					el.classList.remove( 'magicauth-input--invalid' );
					if ( msgEl ) {
						msgEl.remove();
						msgEl = null;
					}
				}
			}

			el.addEventListener( 'input', validate );
		} );
	}

	// Form submission — Save = native submit, Discard = reload with sessionStorage flag
	function initFormSubmission() {
		if ( ! form ) {
			return;
		}

		form.addEventListener( 'submit', function () {
			// Loading state before browser navigates.
			setLoading( saveBtn, true, 'Saving…' );
			setLoading( discardBtn, true, 'Saving…' );
		} );

		if ( discardBtn ) {
			discardBtn.addEventListener( 'click', function ( e ) {
				if ( discardBtn.hasAttribute( 'disabled' ) ) {
					return;
				}
				e.preventDefault();
				try {
					sessionStorage.setItem( 'magicauth_discarded', '1' );
				} catch ( err ) { /* private mode / quota */ }
				window.location.reload();
			} );
		}
	}

	// Notice dismissal
	function initNoticeDismissal() {
		document.querySelectorAll( '.magicauth-admin .magicauth-notice__close' ).forEach( function ( btn ) {
			btn.addEventListener( 'click', function () {
				var notice = btn.closest( '.magicauth-notice' );
				if ( ! notice ) {
					return;
				}
				notice.style.transition = 'opacity 160ms ease, transform 160ms ease';
				notice.style.opacity = '0';
				notice.style.transform = 'translateY(-4px)';
				setTimeout( function () { notice.remove(); }, 180 );
			} );
		} );
	}

	// Toast system — floating stack on body
	var toastStack;

	function getToastStack() {
		if ( ! toastStack ) {
			toastStack = document.querySelector( '.magicauth-toast-stack' );
			if ( ! toastStack ) {
				toastStack = document.createElement( 'div' );
				toastStack.className = 'magicauth-toast-stack';
				toastStack.setAttribute( 'aria-live', 'polite' );
				document.body.appendChild( toastStack );
			}
		}
		return toastStack;
	}

	function toastIcon( type ) {
		if ( type === 'success' ) {
			return '<svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3,6.5 5,8.5 9,4"/></svg>';
		}
		if ( type === 'error' ) {
			return '<svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="3" x2="9" y2="9"/><line x1="9" y1="3" x2="3" y2="9"/></svg>';
		}
		return '<svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="6" r="4.5"/><line x1="6" y1="5.5" x2="6" y2="8.5"/><circle cx="6" cy="3.6" r="0.4" fill="currentColor"/></svg>';
	}

	function showToast( opts ) {
		var type     = opts.type || 'success';
		var message  = opts.message || '';
		var duration = opts.duration || 3500;
		var stack    = getToastStack();

		var toast = document.createElement( 'div' );
		toast.className = 'magicauth-toast magicauth-toast--' + type;
		toast.innerHTML =
			'<span class="magicauth-toast__icon">' + toastIcon( type ) + '</span>' +
			'<span class="magicauth-toast__msg"></span>' +
			'<button class="magicauth-toast__close" aria-label="Dismiss" type="button">&times;</button>';
		toast.querySelector( '.magicauth-toast__msg' ).textContent = message;
		stack.appendChild( toast );

		var timer;
		var dismiss = function () {
			clearTimeout( timer );
			if ( toast.classList.contains( 'is-leaving' ) ) {
				return;
			}
			toast.classList.add( 'is-leaving' );
			setTimeout( function () { toast.remove(); }, 200 );
		};
		toast.querySelector( '.magicauth-toast__close' ).addEventListener( 'click', dismiss );
		timer = setTimeout( dismiss, duration );
	}

	function initToastFromUrl() {
		var params  = new URLSearchParams( window.location.search );
		var changed = false;

		if ( params.get( 'settings-updated' ) === 'true' ) {
			showToast( { type: 'success', message: 'Settings saved.', duration: 7000 } );
			params.delete( 'settings-updated' );
			changed = true;
		}

		var test = params.get( 'magicauth-test' );
		if ( test === 'sent' ) {
			showToast( {
				type: 'success',
				message: 'Test email sent. Check your inbox (and spam folder).',
				duration: 9000
			} );
			params.delete( 'magicauth-test' );
			changed = true;
		} else if ( test === 'fail' ) {
			showToast( {
				type: 'error',
				message: "wp_mail returned false. Check your server's mail configuration.",
				duration: 12000
			} );
			params.delete( 'magicauth-test' );
			changed = true;
		}

		if ( changed ) {
			var newSearch = params.toString();
			var newUrl = window.location.pathname + ( newSearch ? '?' + newSearch : '' );
			window.history.replaceState( {}, '', newUrl );
		}
	}

	// Discard flash — sessionStorage flag set pre-reload, consumed here.
	function initDiscardFlash() {
		var flag;
		try {
			flag = sessionStorage.getItem( 'magicauth_discarded' );
			if ( flag ) {
				sessionStorage.removeItem( 'magicauth_discarded' );
			}
		} catch ( err ) { return; }
		if ( flag === '1' ) {
			showToast( { type: 'info', message: 'Changes discarded.', duration: 6000 } );
		}
	}

	// WP notice scooper — options-head.php auto-calls settings_errors(), rendering a duplicate .notice
	// above our wrap. Reroute into toasts. Tight scope (only id^="setting-error-") so unrelated admin
	// notices stay where users expect them.
	function initWpNoticeScoop() {
		var wrap = document.querySelector( '.wrap.magicauth-admin' );
		if ( ! wrap || ! wrap.parentNode ) {
			return;
		}
		var notices = wrap.parentNode.querySelectorAll( 'div[id^="setting-error-"]' );
		Array.prototype.forEach.call( notices, function ( notice ) {
			var msgEl = notice.querySelector( 'p' ) || notice;
			var msg   = ( msgEl.textContent || '' ).trim();
			if ( ! msg ) {
				notice.remove();
				return;
			}
			var type = 'info';
			if ( notice.classList.contains( 'notice-success' ) || notice.classList.contains( 'updated' ) ) {
				type = 'success';
			} else if ( notice.classList.contains( 'notice-error' ) || notice.classList.contains( 'error' ) ) {
				type = 'error';
			} else if ( notice.classList.contains( 'notice-warning' ) ) {
				type = 'info';
			}
			showToast( { type: type, message: msg, duration: type === 'error' ? 12000 : 8000 } );
			notice.remove();
		} );
	}

	// Confirm modal
	function showConfirm( opts ) {
		var title       = opts.title;
		var lede        = opts.lede || '';
		var body        = opts.body || '';
		var confirmText = opts.confirmText || 'Confirm';
		var cancelText  = opts.cancelText || 'Cancel';
		var danger      = ! ! opts.danger;
		var onConfirm   = opts.onConfirm;

		var backdrop = document.createElement( 'div' );
		backdrop.className = 'magicauth-modal-backdrop';
		backdrop.innerHTML =
			'<div class="magicauth-modal" role="dialog" aria-modal="true">' +
				'<div class="magicauth-modal__head">' +
					'<span class="magicauth-modal__icon ' + ( danger ? 'magicauth-modal__icon--danger' : 'magicauth-modal__icon--warn' ) + '">' +
						'<svg viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' +
							'<path d="M9 2.2L17 16H1L9 2.2Z"/><line x1="9" y1="7.5" x2="9" y2="11"/><circle cx="9" cy="13" r="0.7" fill="currentColor"/>' +
						'</svg>' +
					'</span>' +
					'<div class="magicauth-modal__head-text">' +
						'<h3 data-modal-title></h3>' +
						( lede ? '<p class="magicauth-modal__lede" data-modal-lede></p>' : '' ) +
					'</div>' +
				'</div>' +
				'<div class="magicauth-modal__body" data-modal-body></div>' +
				'<div class="magicauth-modal__foot">' +
					'<button class="magicauth-btn magicauth-btn--ghost" data-cancel type="button"></button>' +
					'<button class="magicauth-btn ' + ( danger ? 'magicauth-btn--danger' : 'magicauth-btn--primary' ) + '" data-confirm type="button"></button>' +
				'</div>' +
			'</div>';
		backdrop.querySelector( '[data-modal-title]' ).textContent = title;
		if ( lede ) {
			backdrop.querySelector( '[data-modal-lede]' ).textContent = lede;
		}
		backdrop.querySelector( '[data-modal-body]' ).innerHTML = body;
		backdrop.querySelector( '[data-cancel]' ).textContent  = cancelText;
		backdrop.querySelector( '[data-confirm]' ).textContent = confirmText;

		document.body.appendChild( backdrop );

		if ( typeof opts.onBody === 'function' ) {
			opts.onBody( backdrop.querySelector( '[data-modal-body]' ) );
		}

		var confirmBtn = backdrop.querySelector( '[data-confirm]' );
		var cancelBtn  = backdrop.querySelector( '[data-cancel]' );

		function close() {
			if ( backdrop.classList.contains( 'is-leaving' ) ) {
				return;
			}
			backdrop.classList.add( 'is-leaving' );
			setTimeout( function () { backdrop.remove(); }, 140 );
		}

		cancelBtn.addEventListener( 'click', function () {
			if ( confirmBtn.classList.contains( 'magicauth-btn--loading' ) ) {
				return;
			}
			close();
		} );

		confirmBtn.addEventListener( 'click', function () {
			if ( confirmBtn.classList.contains( 'magicauth-btn--loading' ) ) {
				return;
			}
			setLoading( confirmBtn, true, 'Working…' );
			cancelBtn.setAttribute( 'disabled', '' );
			Promise.resolve( onConfirm && onConfirm() ).then( function ( keepOpen ) {
				setLoading( confirmBtn, false );
				cancelBtn.removeAttribute( 'disabled' );
				// onConfirm may return false to keep the modal open (e.g. a failed re-check).
				if ( keepOpen !== false ) {
					close();
				}
			} ).catch( function () {
				setLoading( confirmBtn, false );
				cancelBtn.removeAttribute( 'disabled' );
				close();
			} );
		} );

		backdrop.addEventListener( 'click', function ( e ) {
			if ( e.target === backdrop && ! confirmBtn.classList.contains( 'magicauth-btn--loading' ) ) {
				close();
			}
		} );

		function escHandler( e ) {
			if ( e.key === 'Escape' && ! confirmBtn.classList.contains( 'magicauth-btn--loading' ) ) {
				close();
				document.removeEventListener( 'keydown', escHandler );
			}
		}
		document.addEventListener( 'keydown', escHandler );

		setTimeout( function () { confirmBtn.focus(); }, 50 );
	}

	// Loading state helper
	function setLoading( btn, on, label ) {
		if ( ! btn ) {
			return;
		}
		if ( on ) {
			if ( ! btn.dataset.origHtml ) {
				btn.dataset.origHtml = btn.innerHTML;
			}
			btn.classList.add( 'magicauth-btn--loading' );
			btn.setAttribute( 'disabled', '' );
			var txt = label || btn.dataset.origHtml;
			btn.innerHTML = '<span class="magicauth-btn__spinner"></span><span class="magicauth-btn__label">' + txt + '</span>';
		} else {
			btn.classList.remove( 'magicauth-btn--loading' );
			btn.removeAttribute( 'disabled' );
			if ( btn.dataset.origHtml ) {
				btn.innerHTML = btn.dataset.origHtml;
				delete btn.dataset.origHtml;
			}
		}
	}

	// Recovery actions — Revoke all tokens / Reset throttle counters
	function initRecoveryActions() {
		var root = document.querySelector( '.magicauth-recovery' );
		if ( ! root ) {
			return;
		}

		var ajaxurl = root.getAttribute( 'data-ajaxurl' ) || ( window.ajaxurl || '' );
		var nonce   = root.getAttribute( 'data-nonce' ) || '';

		root.addEventListener( 'click', function ( ev ) {
			var btn = ev.target.closest( '[data-magicauth-admin-recovery]' );
			if ( ! btn ) {
				return;
			}
			ev.preventDefault();

			var action   = btn.getAttribute( 'data-magicauth-admin-recovery' );
			var isRevoke = action === 'revoke_all_tokens';

			showConfirm( {
				title:       isRevoke ? 'Revoke all magic-links and codes?' : 'Reset throttle counters?',
				lede:        isRevoke
					? 'This invalidates every outstanding sign-in link and code site-wide.'
					: 'This clears every per-IP, per-email, and per-row rate-limit counter.',
				body:        isRevoke
					? '<p>Anyone with an unconsumed link in their inbox will need to request a new one.</p><p>Active sessions are <strong>not</strong> signed out. This cannot be undone.</p>'
					: '<p>Use this when a probe has pinned the throttle and locked out legitimate users.</p>',
				confirmText: isRevoke ? 'Revoke all' : 'Reset counters',
				cancelText:  'Cancel',
				danger:      isRevoke,
				onConfirm:   function () {
					return fetch( ajaxurl, {
						method: 'POST',
						credentials: 'same-origin',
						headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
						body: new URLSearchParams( {
							action: 'magicauth_admin_' + action,
							_ajax_nonce: nonce
						} )
					} )
						.then( function ( res ) { return res.json(); } )
						.then( function ( payload ) {
							if ( ! payload || ! payload.success ) {
								showToast( {
									type: 'error',
									message: ( payload && payload.data && payload.data.message ) || 'Request failed.'
								} );
								return;
							}
							showToast( {
								type: 'success',
								message: ( payload.data && payload.data.message ) || 'Done.'
							} );
						} )
						.catch( function () {
							showToast( { type: 'error', message: 'Network error. Please try again.' } );
						} );
				}
			} );
		} );
	}

	// Salt-fix wizard — "Fix WordPress salts"
	function initSaltFix() {
		var root = document.querySelector( '.magicauth-recovery' );
		if ( ! root ) {
			return;
		}
		var btn = root.querySelector( '[data-magicauth-salt-fix]' );
		if ( ! btn ) {
			return;
		}

		var ajaxurl = root.getAttribute( 'data-ajaxurl' ) || ( window.ajaxurl || '' );
		var nonce   = root.getAttribute( 'data-nonce' ) || '';

		function post( mode ) {
			return fetch( ajaxurl, {
				method: 'POST',
				credentials: 'same-origin',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams( { action: 'magicauth_admin_fix_salts', mode: mode, _ajax_nonce: nonce } )
			} ).then( function ( res ) { return res.json(); } );
		}

		function escapeHtml( str ) {
			return String( str ).replace( /[&<>"']/g, function ( c ) {
				return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ c ];
			} );
		}

		var effects =
			'<p>Fresh, random values will be generated for all eight WordPress security keys.</p>' +
			'<ul class="magicauth-modal-list">' +
				'<li><strong>Everyone is signed out.</strong> All sessions (including yours) end — you will sign in again right after.</li>' +
				'<li><strong>Pending sign-in links and codes stop working.</strong> They were signed with the old keys, so anyone mid-sign-in requests a fresh email.</li>' +
				'<li><strong>The branded login screen stays off.</strong> This only clears the block; you turn the replacement on yourself when ready.</li>' +
			'</ul>';

		// Open the wizard for the writable (auto-write) case.
		function openAutoWrite() {
			showConfirm( {
				title:       'Fix WordPress salts',
				lede:        'wp-config.php is writable, so MagicAuth can update it for you.',
				body:        effects + '<p>A backup is not left in the web root (it would expose your database credentials); the file is replaced atomically instead.</p>',
				confirmText: 'Generate & write salts',
				cancelText:  'Cancel',
				onConfirm:   function () {
					return post( 'apply' ).then( function ( payload ) {
						if ( ! payload || ! payload.success ) {
							showToast( { type: 'error', message: ( payload && payload.data && payload.data.message ) || 'Could not write wp-config.php.' } );
							return;
						}
						showToast( { type: 'success', message: payload.data.message || 'Salts updated. Signing you out…' } );
						setTimeout( function () { window.location.reload(); }, 1800 );
					} ).catch( function () {
						showToast( { type: 'error', message: 'Network error. Please try again.' } );
					} );
				}
			} );
		}

		// Open the wizard for the manual (copy-and-paste) case.
		function openManual( block ) {
			var body =
				effects +
				'<p>wp-config.php is not writable from PHP on this server, so copy these lines and replace the matching salt lines in <code>wp-config.php</code>, then save it:</p>' +
				'<textarea class="magicauth-salt-block" readonly rows="8">' + escapeHtml( block ) + '</textarea>' +
				'<button type="button" class="magicauth-btn magicauth-btn--ghost magicauth-btn--sm" data-salt-copy>Copy to clipboard</button>';

			showConfirm( {
				title:       'Fix WordPress salts',
				lede:        'Copy these fresh salts into wp-config.php.',
				body:        body,
				confirmText: 'I have updated wp-config.php',
				cancelText:  'Close',
				onBody:      function ( bodyEl ) {
					var copyBtn = bodyEl.querySelector( '[data-salt-copy]' );
					var area    = bodyEl.querySelector( '.magicauth-salt-block' );
					if ( ! copyBtn || ! area ) {
						return;
					}
					copyBtn.addEventListener( 'click', function () {
						area.focus();
						area.select();
						var done = function () { copyBtn.textContent = 'Copied'; setTimeout( function () { copyBtn.textContent = 'Copy to clipboard'; }, 1500 ); };
						if ( navigator.clipboard && navigator.clipboard.writeText ) {
							navigator.clipboard.writeText( area.value ).then( done, function () {} );
						} else {
							try { document.execCommand( 'copy' ); done(); } catch ( e ) {}
						}
					} );
				},
				onConfirm:   function () {
					return post( 'recheck' ).then( function ( payload ) {
						if ( ! payload || ! payload.success ) {
							showToast( { type: 'error', message: ( payload && payload.data && payload.data.message ) || 'Still detecting weak salts.' } );
							return false; // keep the modal open so they can fix and retry
						}
						showToast( { type: 'success', message: payload.data.message || 'Salts updated.' } );
						setTimeout( function () { window.location.reload(); }, 1500 );
					} ).catch( function () {
						showToast( { type: 'error', message: 'Network error. Please try again.' } );
						return false;
					} );
				}
			} );
		}

		function openWizard() {
			setLoading( btn, true, 'Checking…' );
			post( 'preview' ).then( function ( payload ) {
				setLoading( btn, false );
				if ( ! payload || ! payload.success ) {
					showToast( { type: 'error', message: ( payload && payload.data && payload.data.message ) || 'Could not start the wizard.' } );
					return;
				}
				if ( payload.data.writable ) {
					openAutoWrite();
				} else {
					openManual( payload.data.block || '' );
				}
			} ).catch( function () {
				setLoading( btn, false );
				showToast( { type: 'error', message: 'Network error. Please try again.' } );
			} );
		}

		btn.addEventListener( 'click', function ( ev ) {
			ev.preventDefault();
			openWizard();
		} );

		// Auto-open when arriving from the admin notice's "Fix it for me" button.
		try {
			if ( new URLSearchParams( window.location.search ).get( 'magicauth-fix-salts' ) === '1' ) {
				openWizard();
			}
		} catch ( e ) {}
	}

	// User-profile actions — surfaced through toasts
	function initUserProfile() {
		var root = document.querySelector( '.magicauth-user-fields' );
		if ( ! root ) {
			return;
		}

		var nonce   = root.getAttribute( 'data-nonce' ) || '';
		var userId  = root.getAttribute( 'data-user-id' ) || '';
		var ajaxurl = root.getAttribute( 'data-ajaxurl' ) || ( window.ajaxurl || '' );
		var output  = document.getElementById( 'magicauth-user-link-output' );

		root.addEventListener( 'click', function ( ev ) {
			var trigger = ev.target.closest( '[data-magicauth-action]' );
			if ( ! trigger ) {
				return;
			}
			ev.preventDefault();
			var action = trigger.getAttribute( 'data-magicauth-action' );

			fetch( ajaxurl, {
				method: 'POST',
				credentials: 'same-origin',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams( {
					action: 'magicauth_' + action,
					user_id: userId,
					_ajax_nonce: nonce
				} )
			} )
				.then( function ( res ) { return res.json(); } )
				.then( function ( payload ) {
					if ( ! payload || ! payload.success ) {
						showToast( {
							type: 'error',
							message: ( payload && payload.data && payload.data.message ) || 'Request failed.'
						} );
						return;
					}
					if ( payload.data && payload.data.message ) {
						showToast( { type: 'success', message: payload.data.message } );
					}
					if ( payload.data && payload.data.link && output ) {
						output.style.display = 'block';
						var input = output.querySelector( 'input' );
						if ( input ) {
							input.value = payload.data.link;
						}
					}
				} )
				.catch( function () {
					showToast( { type: 'error', message: 'Network error.' } );
				} );
		} );
	}
})();
