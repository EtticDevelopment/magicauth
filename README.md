<div align="center">

# MagicAuth

**Passwordless WordPress sign-in via email magic link or typeable 6-character code.**

One email, two ways in: click the link on the device that has the email, or type the 6-character code on the device you're trying to sign in on. Cross-device flows just work.

[![License: GPL v2 or later](https://img.shields.io/badge/License-GPLv2%2B-blue.svg)](LICENSE)
[![PHP 8.0+](https://img.shields.io/badge/PHP-8.0%2B-777BB4.svg)](https://www.php.net/)
[![WordPress 6.4+](https://img.shields.io/badge/WordPress-6.4%2B-21759B.svg)](https://wordpress.org/)
[![WordPress Plugin Version](https://img.shields.io/wordpress/plugin/v/magicauth?style=flat-square)](https://wordpress.org/plugins/magicauth/)
[![Tested WP Version](https://img.shields.io/wordpress/plugin/tested/magicauth?style=flat-square)](https://wordpress.org/plugins/magicauth/)

</div>

---

MagicAuth is a focused, single-purpose authentication plugin. No SMS, no QR codes, no third-party SSO, no SaaS subscription, no telemetry. The whole plugin is one moving part: send the user a sign-in email, let them in.

## What's inside

* **One email, two methods.** Every sign-in email carries both a clickable magic link and a typeable Crockford-base32 6-character code. Users pick whichever works for the device they're on.
* **Branded login screen.** Optional drop-in replacement for `wp-login.php` with your logo and brand color. Toggleable from settings.
* **`[magicauth_login]` shortcode.** Embed the sign-in form on any page or post. Works inside any theme.
* **Throttling, on by default.** Per-IP, per-email, and per-row rate limits. No admin opt-in required and no admin override path.
* **Three-layer recovery.** Always-visible "Sign in with password" link, `?magicauth=off` URL parameter, and `MAGICAUTH_DISABLE` PHP constant. No admin can get locked out, ever.
* **Admin user-profile integration.** Issue, send, and reset magic links from the user-edit screen. Per-user disable for accounts that should never receive sign-in emails.
* **WP privacy exporter and eraser.** Honors WordPress's built-in personal-data export and erasure tools out of the box.

## Security posture

* **256-bit tokens.** `bin2hex(random_bytes(32))`. Never `wp_rand`, `wp_generate_password`, or `sha1`.
* **HMAC-stored verifiers.** Plaintext exists only in the URL or email. The database stores `hash_hmac('sha256', $plaintext, wp_salt('auth'))`. Comparisons run through `hash_equals()`.
* **Opaque selectors.** URLs never carry a `user_id`. Lookups use a randomly-generated selector.
* **Atomic consume.** Token consumption is a single `UPDATE ... WHERE consumed_at IS NULL` gated on the row state. Auth cookies are set only after the row is provably consumed; TOCTOU is closed.
* **No enumeration oracle.** All response paths emit a uniform generic error and a 50 to 150 ms timing jitter. No admin override.
* **HMAC-truncated IPs.** IPs are stored only as a 16-character HMAC. Source is `$_SERVER['REMOTE_ADDR']`; never `X-Forwarded-For` or `CF-Connecting-IP`.
* **Weak-salts detection.** On activation, MagicAuth checks `wp-config.php` for placeholder salts. Branded login replacement refuses to enable until salts are set.

## Install

**From WordPress.org**: coming soon at https://wordpress.org/plugins/magicauth/ (pending review).

**Manually:**

1. Download the latest release from [Releases](../../releases).
2. WP Admin > Plugins > Add New > Upload Plugin > upload the zip > Activate.
3. Visit **Settings > MagicAuth** to set your logo, brand color, and behavior.
4. Drop `[magicauth_login]` on a page, or toggle "Replace WordPress login screen" to take over `wp-login.php`.

## Recovery, when something goes wrong

If MagicAuth is misbehaving, three independent escape hatches are wired up by default:

1. The "Sign in with password" link on every MagicAuth login form. Bytes-identical for every visitor (no email lookup, no role check) so it cannot be used for user enumeration.
2. Append `?magicauth=off` to `wp-login.php` to fall back to the native WordPress login for the current session.
3. Add `define('MAGICAUTH_DISABLE', true);` to `wp-config.php`. Disables MagicAuth entirely, plugin keeps its data, no uninstall required.

## Stack

* **PHP 8.0+** (strict types throughout)
* **WordPress 6.4+**
* **No vendored runtime dependencies.** Composer is dev-only (PHPStan, PHPUnit, WP coding standards).
* Vanilla JS, no jQuery on the front end. Plain CSS scoped to `.magicauth-`.
* No external CSS frameworks, no build step, no Node toolchain required.

## Local development

```bash
git clone https://github.com/EtticDevelopment/magicauth.git
cd magicauth

# Install dev dependencies (PHPStan, PHPUnit, etc.)
composer install

# Symlink into a local WordPress install
ln -s "$(pwd)" /path/to/wordpress/wp-content/plugins/magicauth

# Activate via WP-CLI
wp plugin activate magicauth --path=/path/to/wordpress
```

### Run the test suite

```bash
composer test
```

The model-layer tests use a self-contained PHPUnit bootstrap with a SQLite-backed `$wpdb` shim, so atomic UPDATE-with-WHERE semantics are tested against a real database, not mocks.

### Run static analysis

```bash
composer phpstan
```

### Run Plugin Check before submitting changes

```bash
wp plugin check magicauth \
  --categories=plugin_repo,security,performance,general,accessibility \
  --severity=warning
```

Should report **"No errors found."**

## Out of scope for v1.0

MagicAuth aims to do one thing well: passwordless sign-in for a single WordPress site. To keep the surface area small and the security model easy to reason about, the following are intentionally not included in v1.0:

* **SMS, phone OTP, QR codes** — email-based auth only.
* **User registration** — MagicAuth signs existing users in; account creation stays with WordPress core or your registration plugin of choice.
* **Third-party integrations** (WooCommerce, Easy Digital Downloads, Elementor, FluentCRM) — MagicAuth works with any plugin that uses the standard WordPress login, but ships no bespoke integrations.
* **CAPTCHA providers** (reCAPTCHA, hCaptcha, Turnstile) — built-in throttling handles abuse; pair with a dedicated CAPTCHA plugin if you need more.
* **REST API endpoints, WP-CLI commands, Gutenberg block** — deferred; the shortcode and `wp-login.php` replacement cover v1.0 use cases.
* **Multisite network mode** — single-site only for now.
* **Audit log / event-stream export** — out of scope for v1.0.
* **Telemetry, analytics, license checks** — zero outbound HTTP from the plugin, and that's a permanent design choice.

Some of these may land in a future version; others (telemetry, phone-based auth) won't. If you're working on a contribution that touches one of these areas, open an issue first so we can talk through fit before you invest the time.

## Contributing

Issues and pull requests welcome. Before opening a PR:

1. Run the test suite (`composer test`). Should pass.
2. Run PHPStan (`composer phpstan`). Should be clean at level 6.
3. Run Plugin Check (above). Should report zero errors.
4. Keep PHP 8.0 as the floor.
5. If you're adding a user-facing string, wrap it in the `magicauth` text domain.

## Status

**1.0.0** is the first public release.

## License

[GPL-2.0-or-later](LICENSE). Same as WordPress core.

## Acknowledgements

Built and maintained by **[Ettic](https://plugins.ettic.nl)**.
