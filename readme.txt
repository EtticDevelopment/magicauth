=== MagicAuth ===
Contributors: ettic
Tags: login, passwordless, magic link, authentication, security
Requires at least: 6.4
Tested up to: 7.0
Requires PHP: 8.0
Stable tag: 1.0.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Passwordless WordPress sign-in via email magic link or typeable 6-character code.

== Description ==

MagicAuth lets your users sign in without a password. Each sign-in email contains both a clickable magic link AND a typeable 6-character code, so cross-device flows work cleanly: request from desktop, type the code from your phone, or click the link wherever.

= Highlights =

* Single sign-in email contains both a magic link and a Crockford-base32 6-character code.
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

= Out of scope for v1.0 =

To keep the surface area small and the security model easy to reason about, a few things are intentionally not included in v1.0:

* SMS, phone OTP, QR codes, and third-party SSO — email-based auth only.
* User registration — MagicAuth signs existing users in; account creation stays with core or your registration plugin.
* CAPTCHA providers (reCAPTCHA, Turnstile, hCaptcha) — built-in throttling covers abuse; pair with a dedicated plugin if you need more.
* REST API, WP-CLI, and multisite network mode — deferred; the shortcode and `wp-login.php` replacement cover v1.0 use cases.

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

= Does MagicAuth replace passwords? =

By default, no. Passwords still work. Enable "Replace default sign-in" in Settings to make MagicAuth the primary sign-in surface; the password link remains visible for recovery.

= Can I customize the email or login UI? =

Yes. Templates can be overridden by copying them into `your-theme/magicauth/`. Filters cover subject line, from address, headers, and rendered HTML/plaintext bodies; see the **Hooks** section.

== Privacy ==

MagicAuth registers a WordPress privacy exporter and eraser. Personal data stored is limited to: `user_id`, an HMAC of the user's email and IP, and timestamps for each sign-in attempt. Verifiers are not exportable; only metadata about issued/consumed tokens.
