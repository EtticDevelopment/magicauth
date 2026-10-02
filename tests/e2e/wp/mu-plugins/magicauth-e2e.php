<?php
/**
 * Plugin Name: MagicAuth E2E support
 * Description: Test-only fixture of the passkeys E2E suite (SPEC 14.2). Mounted into WordPress Playground by tests/e2e/run.mjs; never shipped.
 *
 * Inert unless MAGICAUTH_E2E is defined (the E2E blueprint defines it). Provides:
 * - mail capture (pre_wp_mail short-circuit, one option row per mail);
 * - admin-ajax test actions (logged in or out): magicauth_e2e_mail (captured mail),
 *   magicauth_e2e_get (reads) and magicauth_e2e_set (writes: user meta, session and
 *   challenge time travel, settings, flags, throttle reset);
 * - fixture pages: the theme-style login wall (/wall/ and the logged-out view of
 *   /deep/link/, contract 8.9) and /account-tpl/ (the shortcode rendered from a
 *   template, so early management-page detection misses it);
 * - per-test flags: a wp_login hook that redirects to /terms/ and exits (E27), a
 *   forced rpId in the sign-in options (E19), theme stylesheets (E20, E24b).
 *
 * Works with any MagicAuth version (the 1.0.5 baseline of E26 has no passkey classes).
 *
 * @package MagicAuth\Tests
 */

defined( 'ABSPATH' ) || exit;

if ( ! defined( 'MAGICAUTH_E2E' ) || ! MAGICAUTH_E2E ) {
	return;
}

const MAGICAUTH_E2E_FLAGS = 'magicauth_e2e_flags';
const MAGICAUTH_E2E_MAIL  = 'magicauth_e2e_mail_';

/** Current flags (array of name => value). */
function magicauth_e2e_flags(): array {
	$flags = get_option( MAGICAUTH_E2E_FLAGS, [] );
	return is_array( $flags ) ? $flags : [];
}

function magicauth_e2e_flag( string $name ) {
	$flags = magicauth_e2e_flags();
	return $flags[ $name ] ?? null;
}

/* ------------------------------------------------------------------ mail capture */

// One row per mail, so two requests that send at once never overwrite each other.
add_filter(
	'pre_wp_mail',
	static function ( $short, $atts ) {
		$to   = $atts['to'] ?? [];
		$to   = is_array( $to ) ? $to : array_map( 'trim', explode( ',', (string) $to ) );
		$seq  = sprintf( '%.6f', microtime( true ) ) . '_' . bin2hex( random_bytes( 4 ) );
		$mail = [
			'seq'     => $seq,
			'to'      => array_values( array_map( 'strtolower', $to ) ),
			'subject' => (string) ( $atts['subject'] ?? '' ),
			'message' => (string) ( $atts['message'] ?? '' ),
			'headers' => $atts['headers'] ?? [],
		];
		add_option( MAGICAUTH_E2E_MAIL . $seq, $mail, '', false );
		return true;
	},
	10,
	2
);

function magicauth_e2e_mails(): array {
	global $wpdb;
	$rows = $wpdb->get_col( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name LIKE %s ORDER BY option_name ASC", $wpdb->esc_like( MAGICAUTH_E2E_MAIL ) . '%' ) );
	$out  = [];
	foreach ( $rows as $row ) {
		$mail = maybe_unserialize( $row );
		if ( is_array( $mail ) ) {
			$out[] = $mail;
		}
	}
	return $out;
}

// What the module saw when it decided enabled() (init, before Module::register()).
add_action(
	'init',
	static function () {
		$avail                            = class_exists( '\MagicAuth\Passkeys\Module' ) ? \MagicAuth\Passkeys\Module::available() : null;
		$GLOBALS['magicauth_e2e_at_init'] = [
			'home'      => home_url(),
			'site'      => site_url(),
			'setting'   => function_exists( 'magicauth_get_setting' ) ? magicauth_get_setting( 'passkeys_enabled', false ) : null,
			'available' => is_wp_error( $avail ) ? $avail->get_error_message() : $avail,
		];
	},
	-1
);

/* ------------------------------------------------------------------ test actions */

function magicauth_e2e_input(): array {
	// phpcs:ignore WordPress.Security.NonceVerification.Missing -- test-only fixture.
	$raw  = isset( $_POST['data'] ) ? wp_unslash( (string) $_POST['data'] ) : '{}';
	$data = json_decode( $raw, true );
	return is_array( $data ) ? $data : [];
}

function magicauth_e2e_user( $ref ): ?WP_User {
	if ( is_numeric( $ref ) ) {
		$user = get_userdata( (int) $ref );
	} else {
		$user = get_user_by( 'login', (string) $ref );
		if ( ! $user ) {
			$user = get_user_by( 'email', (string) $ref );
		}
	}
	return $user instanceof WP_User ? $user : null;
}

function magicauth_e2e_table( string $name ): string {
	global $wpdb;
	return $wpdb->prefix . $name;
}

function magicauth_e2e_b64u( string $raw ): string {
	return rtrim( strtr( base64_encode( $raw ), '+/', '-_' ), '=' );
}

/** Everything a test reads about a user. */
function magicauth_e2e_user_state( WP_User $user ): array {
	global $wpdb;
	$uid      = (int) $user->ID;
	$sessions = get_user_meta( $uid, 'session_tokens', true );
	$out      = [];
	foreach ( is_array( $sessions ) ? $sessions : [] as $verifier => $session ) {
		$out[] = [
			'verifier'   => substr( (string) $verifier, 0, 12 ),
			'method'     => $session['magicauth_method'] ?? null,
			'auth_at'    => $session['magicauth_auth_at'] ?? null,
			'fresh'      => isset( $session['magicauth_fresh_hash'] ),
			'expiration' => $session['expiration'] ?? null,
		];
	}
	$passkeys = [];
	$table    = magicauth_e2e_table( 'magicauth_passkeys' );
	if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table ) {
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT id, rp_id, credential_id, credential_hash, user_handle, sign_count, backup_eligible, backup_state, name, created_at, last_used_at, counter_anomaly_at FROM {$table} WHERE user_id = %d ORDER BY id ASC", $uid ), ARRAY_A );
		$passkeys = is_array( $rows ) ? $rows : [];
	}
	$state = [];
	$table = magicauth_e2e_table( 'magicauth_passkey_sessions' );
	if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table ) {
		$rows  = $wpdb->get_results( $wpdb->prepare( "SELECT reauth_at, reauth_method, prompt_done, signals_at FROM {$table} WHERE user_id = %d", $uid ), ARRAY_A );
		$state = is_array( $rows ) ? $rows : [];
	}
	return [
		'id'           => $uid,
		'login'        => $user->user_login,
		'email'        => $user->user_email,
		'display_name' => $user->display_name,
		'now'          => time(),
		'meta'         => [
			'magicauth_passkey_prompt'      => get_user_meta( $uid, 'magicauth_passkey_prompt', true ),
			'magicauth_passkey_user_handle' => get_user_meta( $uid, 'magicauth_passkey_user_handle', true ),
			'magicauth_email_verified_at'   => get_user_meta( $uid, 'magicauth_email_verified_at', true ),
			'magicauth_email_changed_at'    => get_user_meta( $uid, 'magicauth_email_changed_at', true ),
			'magicauth_passkey_details_at'  => get_user_meta( $uid, 'magicauth_passkey_details_at', true ),
			'magicauth_disabled'            => get_user_meta( $uid, 'magicauth_disabled', true ),
		],
		'sessions'     => $out,
		'passkeys'     => $passkeys,
		'state'        => $state,
	];
}

function magicauth_e2e_send( $data ): void {
	nocache_headers();
	wp_send_json_success( $data );
}

function magicauth_e2e_fail( string $message ): void {
	nocache_headers();
	wp_send_json_error( [ 'message' => $message ], 400 );
}

/** Mail: list (optionally for one address, after a seq) or clear. */
function magicauth_e2e_mail_action(): void {
	$in = magicauth_e2e_input();
	if ( 'clear' === ( $in['op'] ?? '' ) ) {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $wpdb->esc_like( MAGICAUTH_E2E_MAIL ) . '%' ) );
		magicauth_e2e_send( [ 'cleared' => true ] );
	}
	$to    = strtolower( (string) ( $in['to'] ?? '' ) );
	$after = (string) ( $in['after'] ?? '' );
	$mails = array_values(
		array_filter(
			magicauth_e2e_mails(),
			static function ( $m ) use ( $to, $after ) {
				return ( '' === $to || in_array( $to, $m['to'], true ) ) && ( '' === $after || strcmp( $m['seq'], $after ) > 0 );
			}
		)
	);
	magicauth_e2e_send( [ 'mails' => $mails ] );
}

/** Reads. */
function magicauth_e2e_get_action(): void {
	$in = magicauth_e2e_input();
	switch ( $in['op'] ?? '' ) {
		case 'env':
			$plugin = WP_PLUGIN_DIR . '/magicauth';
			$module = class_exists( '\MagicAuth\Passkeys\Module' );
			$avail  = $module ? \MagicAuth\Passkeys\Module::available() : null;
			magicauth_e2e_send(
				[
					'setup'           => (int) get_option( 'magicauth_e2e_setup', 0 ),
					'php'             => PHP_VERSION,
					'wp'              => get_bloginfo( 'version' ),
					'magicauth'       => defined( 'MAGICAUTH_VERSION' ) ? MAGICAUTH_VERSION : null,
					'openssl'         => function_exists( 'openssl_verify' ),
					'sodium'          => function_exists( 'sodium_crypto_sign_verify_detached' ),
					'sodium_ext'      => extension_loaded( 'sodium' ),
					'openssl_ed25519' => defined( 'OPENSSL_KEYTYPE_ED25519' ),
					'algs'            => $module ? \MagicAuth\Passkeys\Module::supported_algs() : null,
					'enabled'         => $module ? \MagicAuth\Passkeys\Module::enabled() : null,
					'available'       => is_wp_error( $avail ) ? $avail->get_error_message() : $avail,
					'at_init'         => $GLOBALS['magicauth_e2e_at_init'] ?? null,
					'rp_id'           => class_exists( '\MagicAuth\Passkeys\RelyingParty' ) ? \MagicAuth\Passkeys\RelyingParty::id() : null,
					'db_version'      => (int) get_option( 'magicauth_db_version' ),
					'settings'        => get_option( 'magicauth_settings' ),
					'plugin_dirs'     => [
						'vendor'     => is_dir( $plugin . '/vendor' ),
						'tests'      => is_dir( $plugin . '/tests' ),
						'tools'      => is_dir( $plugin . '/tools' ),
						'thirdparty' => is_file( $plugin . '/includes/ThirdParty/Passkeys/LICENSE' ),
					],
				]
			);
			break;
		case 'user':
			$user = magicauth_e2e_user( $in['user'] ?? '' );
			if ( ! $user ) {
				magicauth_e2e_fail( 'no user' );
			}
			magicauth_e2e_send( magicauth_e2e_user_state( $user ) );
			break;
		case 'challenges':
			global $wpdb;
			$table = magicauth_e2e_table( 'magicauth_passkey_challenges' );
			magicauth_e2e_send( [ 'rows' => $wpdb->get_results( "SELECT id, ceremony, user_id, created_at, expires_at, consumed_at FROM {$table} ORDER BY id ASC", ARRAY_A ) ] );
			break;
		case 'debug_log':
			$file = WP_CONTENT_DIR . '/debug.log';
			magicauth_e2e_send( [ 'log' => is_file( $file ) ? (string) file_get_contents( $file ) : '' ] );
			break;
		default:
			magicauth_e2e_fail( 'unknown op' );
	}
}

/** Writes. */
function magicauth_e2e_set_action(): void {
	global $wpdb;
	$in   = magicauth_e2e_input();
	$op   = (string) ( $in['op'] ?? '' );
	$user = isset( $in['user'] ) ? magicauth_e2e_user( $in['user'] ) : null;

	switch ( $op ) {
		case 'reset':
			// Throttle transients and outstanding sign-in tokens, between sign-ins.
			add_filter( 'magicauth_throttle_allow_reset_all', '__return_true' );
			if ( class_exists( '\MagicAuth\Auth\Throttle' ) ) {
				\MagicAuth\Auth\Throttle::reset_all();
			}
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", '_transient_magicauth_throttle_%', '_transient_timeout_magicauth_throttle_%' ) );
			wp_cache_flush();
			magicauth_e2e_send( [ 'reset' => true ] );
			break;

		case 'create_user':
			$login = sanitize_user( (string) ( $in['login'] ?? '' ), true );
			$id    = username_exists( $login );
			if ( ! $id ) {
				$id = wp_insert_user(
					[
						'user_login'   => $login,
						'user_pass'    => 'password',
						'user_email'   => (string) ( $in['email'] ?? ( $login . '@example.com' ) ),
						'display_name' => (string) ( $in['display_name'] ?? $login ),
						'role'         => (string) ( $in['role'] ?? 'subscriber' ),
					]
				);
				if ( is_wp_error( $id ) ) {
					magicauth_e2e_fail( $id->get_error_message() );
				}
			}
			magicauth_e2e_send( magicauth_e2e_user_state( get_userdata( (int) $id ) ) );
			break;

		case 'send_link':
			// What the email form does after its gates: issue a token to the user's mailbox and mail it.
			if ( ! $user ) {
				magicauth_e2e_fail( 'no user' );
			}
			$issued = \MagicAuth\Auth\TokenManager::issue( (int) $user->ID, $user->user_email, (string) ( $in['redirect_to'] ?? '' ) );
			if ( ! is_array( $issued ) ) {
				magicauth_e2e_fail( 'issue failed' );
			}
			\MagicAuth\Email\Mailer::send_magic_link( (int) $user->ID, $issued['link_url'], $issued['code_plaintext'], $issued['expires_at'] );
			magicauth_e2e_send( [ 'sent' => true ] );
			break;

		case 'meta':
			// { user, set: { key: value }, delete: [ keys ] }
			if ( ! $user ) {
				magicauth_e2e_fail( 'no user' );
			}
			foreach ( (array) ( $in['set'] ?? [] ) as $key => $value ) {
				update_user_meta( (int) $user->ID, (string) $key, $value );
			}
			foreach ( (array) ( $in['delete'] ?? [] ) as $key ) {
				delete_user_meta( (int) $user->ID, (string) $key );
			}
			magicauth_e2e_send( magicauth_e2e_user_state( $user ) );
			break;

		case 'shift':
			// Time travel: move the user's session creation stamps (and step-up stamps) back by N seconds.
			if ( ! $user ) {
				magicauth_e2e_fail( 'no user' );
			}
			$secs     = (int) ( $in['seconds'] ?? 0 );
			$sessions = get_user_meta( (int) $user->ID, 'session_tokens', true );
			if ( is_array( $sessions ) ) {
				foreach ( $sessions as $verifier => $session ) {
					if ( isset( $session['magicauth_auth_at'] ) && is_int( $session['magicauth_auth_at'] ) ) {
						$sessions[ $verifier ]['magicauth_auth_at'] = $session['magicauth_auth_at'] - $secs;
					}
					if ( isset( $session['login'] ) ) {
						$sessions[ $verifier ]['login'] = (int) $session['login'] - $secs;
					}
				}
				// Test-only rewrite of core's record; production code never does this (SPEC 3.2).
				update_user_meta( (int) $user->ID, 'session_tokens', $sessions );
			}
			$table = magicauth_e2e_table( 'magicauth_passkey_sessions' );
			$wpdb->query( $wpdb->prepare( "UPDATE {$table} SET reauth_at = reauth_at - %d WHERE user_id = %d AND reauth_at > %d", $secs, (int) $user->ID, $secs ) );
			magicauth_e2e_send( magicauth_e2e_user_state( $user ) );
			break;

		case 'shift_challenges':
			// Server-side half of client clock travel: every challenge row ages by N seconds.
			$secs  = (int) ( $in['seconds'] ?? 0 );
			$table = magicauth_e2e_table( 'magicauth_passkey_challenges' );
			$rows  = $wpdb->get_results( "SELECT id, created_at, expires_at FROM {$table}", ARRAY_A );
			foreach ( (array) $rows as $row ) {
				$wpdb->update(
					$table,
					[
						'created_at' => gmdate( 'Y-m-d H:i:s', strtotime( $row['created_at'] . ' UTC' ) - $secs ),
						'expires_at' => gmdate( 'Y-m-d H:i:s', strtotime( $row['expires_at'] . ' UTC' ) - $secs ),
					],
					[ 'id' => (int) $row['id'] ]
				);
			}
			magicauth_e2e_send( [ 'shifted' => count( (array) $rows ) ] );
			break;

		case 'passkey_delete':
			// A credential row vanishes server-side (E12).
			$table = magicauth_e2e_table( 'magicauth_passkeys' );
			magicauth_e2e_send( [ 'deleted' => (int) $wpdb->delete( $table, [ 'id' => (int) ( $in['id'] ?? 0 ) ] ) ] );
			break;

		case 'settings':
			// Merge into magicauth_settings without the admin sanitizer (fixture setup, not the settings UI).
			remove_all_filters( 'sanitize_option_magicauth_settings' );
			$settings = get_option( 'magicauth_settings', [] );
			$settings = is_array( $settings ) ? $settings : [];
			foreach ( (array) ( $in['set'] ?? [] ) as $key => $value ) {
				if ( 'throttle' === $key && is_array( $value ) ) {
					$settings['throttle'] = array_merge( (array) ( $settings['throttle'] ?? [] ), $value );
				} else {
					$settings[ $key ] = $value;
				}
			}
			update_option( 'magicauth_settings', $settings );
			magicauth_e2e_send( [ 'settings' => get_option( 'magicauth_settings' ) ] );
			break;

		case 'option':
			foreach ( (array) ( $in['set'] ?? [] ) as $key => $value ) {
				update_option( (string) $key, $value );
			}
			magicauth_e2e_send( [ 'ok' => true ] );
			break;

		case 'flags':
			update_option( MAGICAUTH_E2E_FLAGS, (array) ( $in['flags'] ?? [] ) );
			magicauth_e2e_send( [ 'flags' => magicauth_e2e_flags() ] );
			break;

		case 'clear_log':
			$file = WP_CONTENT_DIR . '/debug.log';
			if ( is_file( $file ) ) {
				file_put_contents( $file, '' );
			}
			magicauth_e2e_send( [ 'ok' => true ] );
			break;

		default:
			magicauth_e2e_fail( 'unknown op' );
	}
}

foreach ( [ 'mail', 'get', 'set' ] as $magicauth_e2e_kind ) {
	add_action( 'wp_ajax_magicauth_e2e_' . $magicauth_e2e_kind, 'magicauth_e2e_' . $magicauth_e2e_kind . '_action' );
	add_action( 'wp_ajax_nopriv_magicauth_e2e_' . $magicauth_e2e_kind, 'magicauth_e2e_' . $magicauth_e2e_kind . '_action' );
}
unset( $magicauth_e2e_kind );

/* ------------------------------------------------------------------ site fixtures */

// The fixture runs every sign-in from one address; the per-network issuance cap
// would otherwise end autofill mid-suite (filter clamps to 5000).
add_filter(
	'magicauth_passkey_options_ip_max',
	static function () {
		return 5000;
	}
);

// B17 (pre-existing, SPEC Appendix D): the rank helper refuses administrators on other
// roles because core's allcaps holds role-name keys. It stays open until the rank model is
// decided (review r2-regress-01 reverted K2), so E15b and E18 need this filter.
add_filter(
	'magicauth_current_user_can_control_user',
	static function ( $can ) {
		return $can || current_user_can( 'manage_options' );
	}
);

/** Fixture page check by path (works before and after the main query). */
function magicauth_e2e_is( string $path ): bool {
	$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
	$uri = (string) wp_parse_url( $uri, PHP_URL_PATH );
	return untrailingslashit( $uri ) === untrailingslashit( $path );
}

function magicauth_e2e_is_wall(): bool {
	return magicauth_e2e_is( '/wall/' ) || ( magicauth_e2e_is( '/deep/link/' ) && ! is_user_logged_in() );
}

// Theme contract (8.9): the wall forces MagicAuth's front-end assets.
add_filter(
	'magicauth_force_frontend_assets',
	static function ( $force ) {
		return $force || magicauth_e2e_is_wall();
	}
);

// /wall/ and the logged-out view of /deep/link/ render the theme's own sign-in markup.
add_filter(
	'the_content',
	static function ( $content ) {
		if ( ! in_the_loop() || ! is_main_query() || ! magicauth_e2e_is_wall() ) {
			return $content;
		}
		ob_start();
		include __DIR__ . '/magicauth-e2e/wall.php';
		return (string) ob_get_clean();
	},
	99
);

// /account-tpl/: the management shortcode printed by a template, not by post content.
add_filter(
	'template_include',
	static function ( $template ) {
		if ( magicauth_e2e_is( '/account-tpl/' ) ) {
			return __DIR__ . '/magicauth-e2e/account-template.php';
		}
		return $template;
	}
);

// Flag "terms" (E27): a wp_login callback that redirects to a terms page and exits.
add_action(
	'wp_login',
	static function () {
		if ( magicauth_e2e_flag( 'terms' ) ) {
			wp_safe_redirect( home_url( '/terms/' ) );
			exit;
		}
	},
	99
);

// Flag "rp_override" (E19): the sign-in options name an RP ID this site cannot use.
add_action(
	'admin_init',
	static function () {
		$action = isset( $_POST['action'] ) ? (string) wp_unslash( $_POST['action'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( 'magicauth_passkey_signin_options' !== $action || ! magicauth_e2e_flag( 'rp_override' ) ) {
			return;
		}
		ob_start(
			static function ( $body ) {
				return (string) preg_replace( '/"rpId":"[^"]*"/', '"rpId":"example.com"', (string) $body );
			}
		);
	},
	0
);

// Flag "locale" (E24): the site language, without core language packs (sanitize_option
// refuses WPLANG values that are not installed; MagicAuth ships its own catalogues).
foreach ( [ 'locale', 'determine_locale' ] as $magicauth_e2e_hook ) {
	add_filter(
		$magicauth_e2e_hook,
		static function ( $locale ) {
			$flag = magicauth_e2e_flag( 'locale' );
			return is_string( $flag ) && '' !== $flag ? $flag : $locale;
		}
	);
}
unset( $magicauth_e2e_hook );

// Flags "theme_css" (E20) and "focus_css" (E24b): theme stylesheets that fight the plugin.
add_action(
	'wp_head',
	static function () {
		$css = '';
		if ( magicauth_e2e_flag( 'theme_css' ) ) {
			$css .= '.magicauth-shell button.magicauth-button--secondary,.e2e-wall button.e2e-wall__passkey{display:flex}';
		}
		if ( magicauth_e2e_flag( 'focus_css' ) ) {
			$css .= '.entry-content button,.wp-block-post-content button{all:unset}:focus{outline:none}';
		}
		if ( '' !== $css ) {
			echo '<style id="magicauth-e2e-theme">' . $css . '</style>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- fixed test CSS.
		}
	},
	99
);
