=== MagicAuth ===
Contributors: ettic
Tags: login, passwordless, magic link, authentication, security
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 8.0
Stable tag: 1.1.1
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Passwordless WordPress sign-in via email magic link or typeable 6-character code.

== Description ==

MagicAuth lets your users sign in without a password. Each sign-in email contains both a clickable magic link AND a typeable 6-character code, so cross-device flows work cleanly: request from desktop, type the code from your phone, or click the link wherever.

Optional passkeys (off by default): after someone has signed in once with email, they can create a passkey on their device and sign in next time with their fingerprint, face or screen lock instead of an email round trip. Email sign-in always stays available as the first-login, new-device and recovery path.

= Highlights =

* Single sign-in email contains both a magic link and a Crockford-base32 6-character code.
* Optional passkey sign-in (WebAuthn): a passkey button and passkey autofill on the sign-in form. Passkeys can only be created by a user who is already signed in, never from the sign-in form or an email.
* Optional branded login screen replaces `wp-login.php` with a logo and brand color.
* Drop-in `[magicauth_login]` shortcode for any page.
* Per-IP, per-email, and per-row throttling, on by default.
* WP privacy exporter and eraser hooks.
* Admins can issue, send, and reset magic links from the user-edit screen.
* Three-layer recovery (always-visible password link, `?magicauth=off` URL parameter, `MAGICAUTH_DISABLE` constant) so no admin gets locked out.

= Security =

* Tokens are 256-bit (`random_bytes(32)`).
* Verifiers stored as `hash_hmac('sha256', $plaintext, wp_salt('auth'))`; comparisons use `hash_equals()`.
* URLs never carry a `user_id`; lookups use an opaque selector.
* IPs are HMAC-truncated, never stored as plaintext.
* All response paths emit a uniform generic error and a 50 to 150 ms timing jitter.

= Out of scope =

To keep the surface area small and the security model easy to reason about, a few things are intentionally not included:

* SMS, phone OTP, QR codes, and third-party SSO: email-based auth (plus optional passkeys) only.
* A passwordless-only or passkey-only mode: email sign-in always stays available, and passkeys never replace it.
* User registration: MagicAuth signs existing users in; account creation stays with core or your registration plugin.
* CAPTCHA providers (reCAPTCHA, Turnstile, hCaptcha): built-in throttling covers abuse; pair with a dedicated plugin if you need more.
* REST API, WP-CLI, and multisite network mode: deferred; the shortcode and `wp-login.php` replacement cover these use cases.

Some of these may land in a future version. Telemetry and phone-based auth won't.

== Installation ==

1. Upload the plugin to `/wp-content/plugins/magicauth` or install via the WordPress Plugin admin.
2. Activate it through the **Plugins** screen.
3. Configure under **Settings > MagicAuth**.
4. Drop `[magicauth_login]` on any page, or enable the branded `wp-login.php` replacement in settings.

== Frequently Asked Questions ==

= I'm locked out. How do I get back in? =

Three layers, in order of effort:

1. Use the always-visible "Sign in with password" link on the sign-in form. Falls back to the native WordPress login.
2. Append `?magicauth=off` to your `wp-login.php` URL.
3. Add `define('MAGICAUTH_DISABLE', true);` to `wp-config.php` (file-system access required).

= MagicAuth says my WordPress salts (security keys) are weak. What do I do? =

Generate fresh keys at https://api.wordpress.org/secret-key/1.1/salt/, paste the eight `define()` lines into `wp-config.php` (replacing the existing ones), save, and reload the MagicAuth settings page. The notice clears itself. It is advisory and does not block the branded login screen. Full guide: https://docs.ettic.nl/docs/magicauth/weak-salts

= Does MagicAuth replace passwords? =

By default, no. Passwords still work. Enable "Replace default sign-in" in Settings to make MagicAuth the primary sign-in surface; the password link remains visible for recovery. Passkeys are optional and never replace email sign-in: the email link and code stay available on every sign-in form.

= How do passkeys work with MagicAuth? =

Turn them on under **Settings > MagicAuth > Passkeys** (off by default; the site must run on HTTPS with the PHP OpenSSL extension, and the settings page says why when it cannot). Then:

1. A person signs in with the email link or code as before.
2. Signed in, they can create a passkey: from a one-time offer shown after an email sign-in ("Offer a passkey after email sign-in"), from the `[magicauth_passkeys]` management page, or from their own profile in wp-admin. Creating a passkey needs a recent sign-in; otherwise they confirm with a code from their email or an existing passkey first.
3. Next time, the sign-in form offers "Sign in with a passkey" and the browser's passkey autofill. Email sign-in stays right next to it.

Passkeys are never offered or created on the sign-in form, on logged-out pages or in any email, and an administrator cannot create one for someone else. People manage their passkeys (rename, remove, sign out on all other devices) on the page that holds `[magicauth_passkeys]` (choose it as "Passkey management page") or on their wp-admin profile. Administrators can remove a user's passkeys on the user-edit screen. A lost device is handled by signing in with email and removing that passkey. Changing an account's email address removes its passkeys (filter `magicauth_passkey_revoke_on_email_change`), and "Disable MagicAuth sign-in for this user" blocks passkey sign-in too.

The offer appears at most once per email sign-in session. "Not now" waits 30 days, then 90 days, then stops; closing it waits 7 days; "This is a shared device" stops it in that browser. New passkey, removed passkeys and blocked passkey notifications are emailed to the account owner; none of them asks anyone to create a passkey.

= Can I customize the email or login UI? =

Yes. Templates can be overridden by copying them into `your-theme/magicauth/`. Filters cover subject line, from address, headers, and rendered HTML/plaintext bodies; see the **Hooks** section.

== Privacy ==

MagicAuth registers a WordPress privacy exporter and eraser. Personal data stored is limited to: `user_id`, an HMAC of the user's email and IP, and timestamps for each sign-in attempt. Verifiers are not exportable; only metadata about issued/consumed tokens. Sign-in links created by an administrator on the user-edit screen also record that administrator's user ID until the link expires.

Passkeys (only once the module has been turned on) add:

* Passkey records: user ID, credential ID, public key, user handle, flags (backup eligible and backed up), signature counter, transports, provider ID (AAGUID), the passkey's name, the site address it belongs to, when it was added and last used, and when a possible copy was detected.
* User meta: the passkey user handle (a random identifier, the same for all of a user's passkeys), the offer cadence (declines and next offer date), when the email address was last verified, when it last changed, and when the account details last changed.
* Short-lived rows: single-use challenges (minutes) and per-session state (step-up time and method, offer and sync markers) that ends with the session. The sign-in method and time are also kept inside WordPress's own session record until the session ends.
* Cookies: `magicauth_pk_bind` (12 minutes, sign-in security binding), `magicauth_pk_fresh` (10 minutes, ties a recent sign-in to this browser) and `magicauth_pk_shared` (1 year, set only when someone marks the device as shared). They are strictly necessary or set at the person's request.
* Browser storage: `magicauth:pk:noprompt` (this browser is shared) and `magicauth:pk:acct`, keyed by a hash of the user handle, which remembers for 90 days that this browser holds a passkey for the account (dropped once the account has no passkey for this site) and for 30 days that creating one failed here.

Not stored: private keys, biometrics, attestation statements, IP addresses (beyond the existing HMAC'd throttle keys) and user agents (read once to name a new passkey). MagicAuth makes no remote lookups.

The passkeys exporter ("MagicAuth passkeys") exports every field above except the public key. The eraser deletes the passkey records, challenges, session state and user meta (on multisite the time of the last email change stays, so passkeys created before it stay blocked on the network's other sites); the person keeps their account and signs in by email. Passkeys saved in a browser or password manager are not removed by the site: the person deletes them there.

== Theme contract ==

For themes that render their own login form (a login wall) and want passkey sign-in on it. Stable from 1.1.0.

* Assets: `add_filter( 'magicauth_force_frontend_assets', '__return_true' )` on the login request. With passkeys on, MagicAuth then also loads its passkey sign-in scripts and `magicauth-passkeys-login.css`. `magicauth_enqueue_frontend_style` (false) skips `magicauth.css`; `magicauth_passkeys_enqueue_style` (false) skips both passkey stylesheets. A theme that drops them must keep the rule `[data-magicauth-passkey-root][hidden],[data-magicauth-passkey-signin][hidden]{display:none !important}`.
* Autofill input: exactly one `<input autocomplete="username webauthn">` (`webauthn` last). It may be the email field that posts `magicauth_email`.
* Button: any `<button type="button" data-magicauth-passkey-signin hidden>`; the script shows it when the browser supports passkeys. Optional wrapper `[data-magicauth-passkey-root][hidden]`, shown with it.
* Messages: `[data-magicauth-passkey-status]` (progress) and `[data-magicauth-passkey-error]` (errors), always rendered, never `hidden`; fallback `#magicauth-status`.
* Destination: `data-magicauth-redirect-to` on the button or wrapper, else the form's `redirect_to` field, else the current URL. MagicAuth validates it.
* Events on `document`: `magicauth:passkey:start`, `magicauth:passkey:success` (`detail.redirect`, informational) and `magicauth:passkey:error` (cancelable, to show the message yourself). An error after the final step comes back as `?magicauth_passkey_error=<code>`; the script shows it and removes the parameter.
* Helpers: `magicauth_passkeys_enabled()` and `magicauth_passkey_signin_button( [ 'redirect_to' => $url ] )`, which prints the default sign-in block. On MagicAuth's own form, `magicauth_passkey_signin_markup( $html, $state )` replaces that block.
* Never call the registration endpoints from logged-out pages (they refuse) or add passkey creation copy to a login page.

Signed-in pages must call `wp_footer()` (the offer and passkey sync run there). The offer, management list and step-up view can be overridden by copying `passkey-prompt.php`, `passkeys-manage.php` or `passkey-reauth.php` into `your-theme/magicauth/`; scripts bind only to the `data-magicauth-pk-*` attributes listed in each template, never to classes. Keep `data-magicauth-pk-render` on the section, its dialogs and the offer dialog: the scripts ignore any copy without it. After the first change the list items are rebuilt with the plugin's own item markup. Styling uses the existing `--magicauth-*` tokens plus `--magicauth-pk-dialog-max-width`, `--magicauth-pk-backdrop` and `--magicauth-color-warning`. A page that renders `[magicauth_passkeys]` from a block theme template instead of post content should be chosen as the management page or use `magicauth_force_passkeys_manage_assets`.

Developer hooks for passkeys:

* Filters: `magicauth_passkey_prompt_eligible( $show, $user )`, `magicauth_passkey_prompt_methods( $methods )` (sign-in methods that trigger the offer; `link` and `code` by default, can also add `reset` or `passkey`, never `admin_link` or `password`), `magicauth_passkey_prompt_strings( $strings, $user )`, `magicauth_passkey_manage_strings( $strings )`, `magicauth_passkey_manage_url( $url, $user )`, `magicauth_passkey_max_per_user` (default 10, at most 25), `magicauth_passkey_revoke_on_email_change( true, $user, $old_user )`, `magicauth_passkey_admin_capability` (default `manage_options`) and `magicauth_current_user_can_revoke_passkeys( $can, $target_id )`.
* Actions: `magicauth_passkey_added( $user_id, $passkey_id )`, `magicauth_passkey_used( $user_id, $passkey_id )`, `magicauth_passkey_removed( $user_id, $passkey_id, $by )`, `magicauth_passkeys_revoked( $user_id, $actor_id, $count, $reason )` and `magicauth_passkey_signin_failed( $reason, $user_id )`.
* Emails: each passkey email has its own filters `{prefix}_template_args`, `{prefix}_html`, `{prefix}_plaintext`, `{prefix}_subject` and `{prefix}_send`, with prefix `magicauth_passkey_added`, `magicauth_confirm_code`, `magicauth_passkeys_removed` or `magicauth_passkey_blocked`; `magicauth_email_from` and `magicauth_email_headers` receive the email type as an extra argument. Templates `email-passkey-added.php`, `email-confirm-code.php`, `email-passkeys-removed.php` and `email-passkey-blocked.php` (each with a `-plain` version) can be overridden like the other emails.
* The relying party ID is the host of the site address; keep it that way. The `wp-config.php` constant `MAGICAUTH_PASSKEY_RP_ID` (a suffix of the host) exists for operators who know they need it; a parent domain lets every subdomain use the passkeys, and once passkeys exist, changing the ID makes them unusable.

== Third-party code ==

Passkey verification uses a vendored copy of `report-uri/passkeys-php` 2.0.1 (Report-URI Ltd.'s fork of `lbuchs/WebAuthn` by Lukas Buchs, with CBOR and ByteBuffer code by Thomas Bleeker), MIT licensed, with a small set of documented patches. The licence and patch list ship in `includes/ThirdParty/Passkeys/` (`LICENSE`, `NOTICE.md`, `VENDORED.md`). MagicAuth makes no network calls for passkeys.

== Changelog ==

= 1.1.1 =
* Fix: on Safari 26 and later, Apple Passwords no longer reports an updated user name at the start of every session and on every visit of the passkey management page. The browser is now told the account's email address and display name only when one of them changed since it was last told, also when the change was made outside the profile screen. The list of valid passkeys is still sent once per session.
* Fix: no PHP 8.5 deprecation notice when a logo is uploaded on the settings page.

= 1.1.0 =
* New: optional passkeys, off by default. Turn them on under Settings > MagicAuth > Passkeys. The sign-in form gets a "Sign in with a passkey" button and passkey autofill; signed-in users create passkeys from a one-time offer after an email sign-in, the new `[magicauth_passkeys]` management page or their wp-admin profile. Creating a passkey needs a recent email or passkey sign-in, or a confirmation code. Email sign-in stays available everywhere.
* New: passkey settings: "Offer a passkey after email sign-in", "Passkey management page", "Require an email sign-in every (days)" (0 turns it off and is the default; when set, a passkey stops working until the person signs in with email again), the per-IP passkey limits, and diagnostics. Passkeys cannot be turned on where they cannot work safely, for example when the site address is an IP address or is not served over HTTPS (localhost excepted), when the home and site addresses differ, or when another WordPress site shares the address (subfolder install or subdirectory multisite).
* New: passkey management: rename and remove passkeys, "Sign out on all other devices", and "Remove all passkeys" for administrators on the user-edit screen (also while passkeys are turned off).
* New: security emails when a passkey is added, when passkeys are removed by an administrator, from a session that did not recently sign in, or because the account's email address changed, and when a passkey is blocked because it may have been copied. Changing an account's email address removes its passkeys.
* New: privacy exporter and eraser for passkey data; Dutch translations for every new string, with the term "passkey" (glossed once as "toegangssleutel of wachtwoordsleutel"). German and Spanish show the new strings in English for now.
* New: the database is upgraded on the first request after a file deploy (no reactivation needed): three new tables for passkeys, challenges and session state, and a column on the sign-in requests table. Sign-in links and codes sent before the update stop working with it; request a new one.
* Change: "Disable magic-link sign-in for this user" is now "Disable MagicAuth sign-in for this user (email link, code and passkeys)" and also blocks passkey sign-in. Passkeys are kept and work again when the option is cleared.
* Change: a sign-in link or code created by an administrator on the user-edit screen now signs in with the method `admin_link`.
* Fix: signing in with a code, a password or a password reset while already signed in as another account no longer switches the browser to that account. The form shows an error instead, an emailed code stays unused and the password is not reset; sign out first to switch accounts. A sign-in link already refused this. Resetting your own password while signed in keeps you signed in, as before.
* Fix: "Disable magic-link sign-in for this user" (user profile) now also stops a sign-in link or code that was emailed before the box was ticked. Password sign-in is not affected by this setting, as before.
* Fix: changing an account's email address now cancels the sign-in links and codes already sent to the old address, also while passkeys are turned off. Before, such a link or code kept working until it expired.
* Fix: on multisite, users marked as spam can no longer sign in through MagicAuth.
* Fix: the sign-in link in the email now keeps a destination that holds `&` or `#` (for example a lesson link with several parameters or an anchor). Before, everything after the first `&` or the `#` was lost.
* Change: when the `magicauth_redirect_to` filter returns a `wp-login.php` URL or a URL on another host, the user now lands on the home page. Before, a `wp-login.php` URL was followed and another host fell back to the dashboard. The dashboard (`admin_url()`) itself is still used when the admin address differs from the site address.
* Fix: the email sign-in form now submits without JavaScript. Its button is no longer rendered disabled; with JavaScript it still stays disabled until the field holds an email address.
* Fix: themes can override the sign-in form and the branded login page wrapper by copying `login-form.php` or `login-shell.php` into `your-theme/magicauth/` (child theme first, then parent theme), for the `[magicauth_login]` shortcode and the branded `wp-login.php` screens. Before, only the email templates could be overridden.
* Fix: deleting a user now also deletes that user's pending sign-in links and codes right away, instead of leaving them for the daily cleanup.
* Fix: deleting the plugin now also removes its remaining options, user settings and temporary data (unless `MAGICAUTH_KEEP_DATA` is defined).
* Developers: theme contract for passkey sign-in on a theme's own login form (see "Theme contract"), new filter `magicauth_enqueue_frontend_style`, and the passkey filters and actions listed there.
* Developers: `magicauth_pre_set_auth_cookie`, `magicauth_redirect_to` and `magicauth_remember_default` receive the sign-in method (`link`, `code`, `admin_link`, `password`, `reset`, `passkey`) as a new last argument. New action `magicauth_login_completed( $user_id, $method )` (fires after `wp_login`, so not when a `wp_login` callback such as a two-factor screen ends the request) and new filter `magicauth_allow_login( true, $user, $method )` to refuse a sign-in.

= 1.0.5 =
* Fix: clicking the sign-in link in the email now returns you to the page you were trying to reach, matching what typing the code already did. Previously the link path ignored the destination and dropped you on the homepage or dashboard. The destination is validated to your own site (off-site and `wp-login.php` targets are refused), so it cannot be used as an open redirect.

= 1.0.4 =
* Fix: on the code-entry screen the in-card language switcher now stays anchored in a divided footer (with the same divider as the first screen) instead of dangling at the bottom of the card.

= 1.0.3 =
* Fix: sign-in emails are now sent from an address on your own site domain (configurable local part, default `login@`) instead of the WordPress admin address, so they pass SPF/DKIM/DMARC and are far less likely to be flagged as spam. A new "Sender email address" setting controls the local part.
* New: full translation support. The login screen, transactional emails, and the entire admin UI (including JavaScript dialogs) are now translatable.
* New: bundled translations for Dutch (nl_NL), German (de_DE), and Spanish (es_ES). English remains the default.
* Internal: load the text domain on `init`, ship a `.pot` template, and generate `.mo`, `.l10n.php` (WP 6.5+ fast format), and JSON (for JS strings via `wp_set_script_translations`).

= 1.0.2 =
* New: a compact, on-brand language switcher in the branded sign-in card footer on multilingual sites (translate icon plus the current language), replacing WordPress's full-width selector that rendered detached below the card.
* New: "Hide language switcher" setting (Settings > MagicAuth > Branding) to remove it entirely. The native recovery login at `?magicauth=off` always keeps the WordPress default.

= 1.0.1 =
* Fix: the weak-salt warning tooltip on the settings screen was clipped by the card edge. It now displays in full, and its "!" marker is shown in red to draw attention.

= 1.0.0 =
* Initial release.

== Upgrade Notice ==

= 1.1.1 =
Optional passkeys, off by default. The database upgrades itself on the first request after the update. Signing in with a code or password, or resetting a password, while signed in as another account is now refused: sign out first. The per-user disable option also stops links and codes already sent.

= 1.1.0 =
Optional passkeys, off by default. The database upgrades itself on the first request after the update. Signing in with a code or password, or resetting a password, while signed in as another account is now refused: sign out first. The per-user disable option also stops links and codes already sent.
