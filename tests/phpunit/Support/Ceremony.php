<?php
/**
 * Passkey ceremonies for PHPUnit: a site with the module's preconditions
 * (https home, DB version 2), users with a user_registered snapshot, register
 * and sign-in challenges issued through ChallengeStore, options built by
 * Passkeys\Options, credentials produced by SoftAuthenticator and returned as
 * the form field string the endpoints receive. Test support only.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Support;

use MagicAuth\Passkeys\ChallengeStore;
use MagicAuth\Passkeys\Clock;
use MagicAuth\Passkeys\CredentialStore;
use MagicAuth\Passkeys\Freshness;
use MagicAuth\Passkeys\Module;
use MagicAuth\Passkeys\Options;
use MagicAuth\Passkeys\Verifier;
use WP_User;

final class Ceremony {

	public const NOW = 1790000000;

	public const RP = 'academy.example.com';

	public const ORIGIN = 'https://academy.example.com';

	public const REGISTERED = '2026-09-30 08:00:00';

	/** Freshness::session_hash() stand-in. */
	public const SESSION = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

	/** magicauth_pk_bind cookie value of "this browser". */
	public const COOKIE = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

	/** Fresh state, MySQL changed-rows semantics, pinned clock, the academy host. */
	public static function site(): void {
		global $wpdb, $magicauth_test_state;
		magicauth_test_reset_state();
		$wpdb->mysql_changed_rows       = true;
		$magicauth_test_state['home']   = self::ORIGIN;
		$magicauth_test_state['is_ssl'] = true;
		update_option( 'magicauth_db_version', 2 );
		Clock::set_for_tests( self::NOW );
	}

	public static function user( int $id, string $registered = self::REGISTERED ): WP_User {
		$user                  = magicauth_test_register_user( $id, "learner{$id}@example.test" );
		$user->user_registered = $registered;
		$user->display_name    = "Learner {$id}";
		return $user;
	}

	/**
	 * register_options as the endpoint does it (6.4): handle, challenge row, options.
	 *
	 * @return array{options:array<string,mixed>,handle:string,challenge:string}
	 */
	public static function register_options( WP_User $user, string $session = self::SESSION, string $algs = '' ): array {
		$handle    = (string) CredentialStore::user_handle( (int) $user->ID, true );
		$algs      = '' !== $algs ? $algs : implode( ',', Module::supported_algs() );
		$challenge = ChallengeStore::issue( 'register', (int) $user->ID, $session, '', $algs, ChallengeStore::TTL['register'], $handle );
		if ( ! is_string( $challenge ) ) {
			throw new \RuntimeException( 'register challenge refused' );
		}
		$rows = CredentialStore::for_user( $user, self::RP );
		return [
			'options'   => Options::creation( $user, $handle, $challenge, array_map( 'intval', explode( ',', $algs ) ), (array) $rows ),
			'handle'    => $handle,
			'challenge' => $challenge,
		];
	}

	/**
	 * A registration credential field for fresh options.
	 *
	 * @param array<string,mixed>|\Closure $o SoftAuthenticator overrides, or a closure
	 *                                        mapping the issued options to them.
	 */
	public static function registration( SoftAuthenticator $auth, WP_User $user, $o = [], string $session = self::SESSION, string $algs = '' ): string {
		$issued = self::register_options( $user, $session, $algs );
		$o      = $o instanceof \Closure ? $o( $issued['options'] ) : $o;
		return self::encode( $auth->register( $issued['options'], self::ORIGIN, $o ) );
	}

	/** Verified and stored; returns the row id. */
	public static function enrol( SoftAuthenticator $auth, WP_User $user ): int {
		$record = Verifier::verify_registration( self::registration( $auth, $user ), $user, self::SESSION );
		if ( ! is_array( $record ) ) {
			throw new \RuntimeException( 'enrol failed: ' . $record->get_error_code() );
		}
		$id = Verifier::store_registration( $record );
		if ( ! is_int( $id ) ) {
			throw new \RuntimeException( 'store failed: ' . $id->get_error_code() );
		}
		return $id;
	}

	/**
	 * signin_options as the endpoint does it (6.2).
	 *
	 * @return array<string,mixed> Request options.
	 */
	public static function signin_options( string $cookie = self::COOKIE ): array {
		$challenge = ChallengeStore::issue( 'signin', 0, '', $cookie, '', ChallengeStore::TTL['signin'] );
		if ( ! is_string( $challenge ) ) {
			throw new \RuntimeException( 'signin challenge refused' );
		}
		return Options::request( $challenge );
	}

	/**
	 * A sign-in credential field for fresh options.
	 *
	 * @param array<string,mixed>|\Closure $o SoftAuthenticator overrides, or a closure
	 *                                        mapping the issued options to them.
	 */
	public static function assertion( SoftAuthenticator $auth, $o = [], string $cookie = self::COOKIE ): string {
		$options = self::signin_options( $cookie );
		$o       = $o instanceof \Closure ? $o( $options ) : $o;
		return self::encode( $auth->assert( $options, self::ORIGIN, $o ) );
	}

	/* -------------------------------------------- account endpoint requests */

	/** Setting on and the per-request enabled() value forgotten. */
	public static function enable_module(): void {
		$settings                     = (array) get_option( 'magicauth_settings', [] );
		$settings['passkeys_enabled'] = true;
		update_option( 'magicauth_settings', $settings );
		Module::reset_for_tests();
	}

	/**
	 * Signs $user in with a new core session stamped like Login::establish()
	 * does ($method, $auth_at, and the fresh hash when $fresh), makes it the
	 * request's session and puts the fresh cookie into $_COOKIE when
	 * $send_cookie. $method null gives an unstamped session (user switching,
	 * core form). Returns the session token.
	 */
	public static function sign_in( WP_User $user, ?string $method = 'link', ?int $auth_at = null, bool $fresh = true, bool $send_cookie = true ): string {
		global $magicauth_test_state;
		$cookie = bin2hex( random_bytes( 32 ) );
		$stamp  = [];
		if ( null !== $method ) {
			$stamp['magicauth_method']  = $method;
			$stamp['magicauth_auth_at'] = $auth_at ?? Clock::now();
			if ( $fresh ) {
				$stamp['magicauth_fresh_hash'] = hash_hmac( 'sha256', 'magicauth-passkey-fresh|' . $cookie, wp_salt( 'auth' ) );
			}
		}
		$cb = static function ( $session ) use ( $stamp ) {
			return array_merge( (array) $session, $stamp );
		};
		add_filter( 'attach_session_information', $cb, 10, 2 );
		$token = \WP_Session_Tokens::get_instance( (int) $user->ID )->create( Clock::now() + DAY_IN_SECONDS );
		remove_filter( 'attach_session_information', $cb, 10 );

		magicauth_test_login_as( (int) $user->ID );
		$magicauth_test_state['session_token'] = $token;
		unset( $_COOKIE[ Freshness::COOKIE ] );
		if ( $send_cookie && $fresh && null !== $method ) {
			$_COOKIE[ Freshness::COOKIE ] = $cookie;
		}
		return $token;
	}

	/**
	 * A POST from the allowed origin with the account nonce, as the account
	 * script sends it; $_POST and $_REQUEST hold the fields.
	 *
	 * @param array<string,mixed> $fields
	 */
	public static function account_post( array $fields = [], string $nonce_action = 'magicauth_passkeys' ): void {
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$_SERVER['HTTP_ORIGIN']    = self::ORIGIN;
		unset( $_SERVER['HTTP_REFERER'], $_SERVER['CONTENT_LENGTH'] );
		$_POST    = $fields;
		$_REQUEST = $fields + [ '_ajax_nonce' => wp_create_nonce( $nonce_action ) ];
	}

	/**
	 * Calls an endpoint handler (AccountEndpoints unless $class says otherwise)
	 * and returns what it sent; nothing else may be printed.
	 *
	 * @return array{status:?int,success:bool,data:array<string,mixed>,body:string}
	 */
	public static function call( string $handler, string $class = \MagicAuth\Passkeys\AccountEndpoints::class ): array {
		ob_start();
		try {
			call_user_func( [ $class, $handler ] );
		} catch ( \MagicAuth\Tests\Stubs\JsonResponseSent $sent ) {
			$out = (string) ob_get_clean();
			if ( '' !== $out ) {
				throw new \RuntimeException( 'printed before the JSON: ' . $out );
			}
			$payload = is_array( $sent->payload ) ? $sent->payload : [];
			return [
				'status'  => $sent->status,
				'success' => true === ( $payload['success'] ?? null ),
				'data'    => is_array( $payload['data'] ?? null ) ? $payload['data'] : [],
				'body'    => $sent->body,
			];
		}
		ob_end_clean();
		throw new \RuntimeException( $handler . ' sent no response' );
	}

	/** @param array<string,mixed> $credential */
	public static function encode( array $credential ): string {
		return (string) json_encode( $credential, JSON_UNESCAPED_SLASHES ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode
	}

	/** @return array<string,mixed> */
	public static function decode( string $credential ): array {
		return (array) json_decode( $credential, true );
	}

	/** @return array<string,mixed>|null */
	public static function row( int $id ): ?array {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . CredentialStore::table() . ' WHERE id = %d', $id ), ARRAY_A );
		return is_array( $row ) ? $row : null;
	}

	public static function count_rows(): int {
		global $wpdb;
		return (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . CredentialStore::table() );
	}
}
