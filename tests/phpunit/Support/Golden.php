<?php
/**
 * Renders the 1.0.5 golden outputs (SPEC 15 step 1, 14.1) through the test
 * harness: login-form states A to E, the [magicauth_login] shortcode logged
 * out and logged in, and the magic-link and disabled-notice emails (HTML,
 * plain text, subject and headers), each normalised by Normalise.
 *
 * Uses only entry points that exist in 1.0.5 (Shortcode::render(),
 * Mailer::send_magic_link(), Mailer::send_disabled_notice() and the
 * login-form template with the context from LoginScreen::build_context()),
 * so the same code renders the fixtures from a 1.0.5 worktree and the
 * comparison from this tree. Fixed inputs throughout; request globals are
 * restored afterwards. Needs ext-intl: the language switcher's names come
 * from \Locale::getDisplayName().
 *
 * Test support only; never shipped.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Support;

use MagicAuth\Email\Mailer;
use MagicAuth\Frontend\LoginScreen;
use MagicAuth\Frontend\Shortcode;

final class Golden {

	public const DIR = __DIR__ . '/../fixtures/1.0.5';

	public const USER_ID = 7;

	public const LINK = 'https://example.test/?magicauth=verify&s=0123456789abcdef&v=abababababababababababababababababababababababababababababababab';

	private const LOGO_ID = 5;

	private const SESSION_ID = '0123456789abcdef0123456789abcdef';

	/** The request each login-form state is rendered for. */
	private const LOGIN_URIS = [
		'a' => '/wp-login.php?action=magicauth',
		'b' => '/wp-login.php?action=magicauth&magicauth_step=code&magicauth_sid=' . self::SESSION_ID,
		'c' => '/wp-login.php?action=magicauth&magicauth_step=password',
		'd' => '/wp-login.php?action=lostpassword',
		'e' => '/wp-login.php?action=rp&key=resetkey0123456789&login=student',
	];

	/** @return array<int,string> Fixture file names, in render order. */
	public static function files(): array {
		return [
			'login-form-a.html',
			'login-form-b.html',
			'login-form-c.html',
			'login-form-d.html',
			'login-form-e.html',
			'shortcode-logged-out.html',
			'shortcode-logged-in.html',
			'email-magic-link.html',
			'email-magic-link.txt',
			'email-magic-link.meta.json',
			'email-disabled-notice.html',
			'email-disabled-notice.txt',
			'email-disabled-notice.meta.json',
		];
	}

	/** @return array<string,string> File name => normalised content. */
	public static function render_all(): array {
		if ( ! class_exists( 'Locale' ) ) {
			throw new \RuntimeException( 'the golden fixtures need ext-intl (language switcher names)' );
		}
		$server = $_SERVER;
		$get    = $_GET;
		$cookie = $_COOKIE;
		try {
			$out = [];
			foreach ( [ 'a', 'b', 'c', 'd', 'e' ] as $state ) {
				$out[ 'login-form-' . $state . '.html' ] = Normalise::html( self::login_form( $state ) );
			}
			$out['shortcode-logged-out.html'] = Normalise::html( self::shortcode( false ) );
			$out['shortcode-logged-in.html']  = Normalise::html( self::shortcode( true ) );
			foreach ( self::emails() as $name => $mail ) {
				$out[ $name . '.html' ]      = Normalise::html( (string) $mail['message'] );
				$out[ $name . '.txt' ]       = Normalise::text( (string) $mail['alt_body'] );
				$out[ $name . '.meta.json' ] = json_encode( // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode
					[
						'to'      => $mail['to'],
						'subject' => $mail['subject'],
						'headers' => $mail['headers'],
					],
					JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
				) . "\n";
			}
			return $out;
		} finally {
			$_SERVER = $server;
			$_GET    = $get;
			$_COOKIE = $cookie;
			magicauth_test_reset_state();
		}
	}

	private static function request( string $uri ): void {
		global $magicauth_test_state;
		magicauth_test_reset_state();
		$magicauth_test_state['is_ssl'] = true;
		$_SERVER['HTTP_HOST']           = 'example.test';
		$_SERVER['REQUEST_URI']         = $uri;
		$_GET                           = [];
		$_COOKIE                        = [];
	}

	/**
	 * Login-form template rendered with the context LoginScreen builds itself:
	 * the request of each state is set up (query, session transient, logo,
	 * one installed translation) and login_context() reads it as the render
	 * paths do.
	 */
	private static function login_form( string $state ): string {
		global $magicauth_test_state;
		self::request( self::LOGIN_URIS[ $state ] );
		$query = (string) wp_parse_url( self::LOGIN_URIS[ $state ], PHP_URL_QUERY );
		parse_str( $query, $_GET );
		$magicauth_test_state['options']['magicauth_settings'] = [ 'logo_attachment_id' => self::LOGO_ID ];
		$magicauth_test_state['available_languages']          = [ 'nl_NL' ];
		magicauth_test_register_attachment( self::LOGO_ID, 'https://example.test/wp-content/uploads/logo.png' );
		set_transient( 'magicauth_session_' . self::SESSION_ID, [ 'email' => 'student@example.test' ], 600 );

		$context = self::login_context( $state );

		ob_start();
		( static function ( string $tpl, array $args ): void {
			extract( $args, EXTR_SKIP ); // phpcs:ignore WordPress.PHP.DontExtract.extract_extract
			include $tpl;
		} )( MAGICAUTH_DIR . 'templates/login-form.php', $context );
		return (string) ob_get_clean();
	}

	/**
	 * The context LoginScreen passes to the template for $state, from its own
	 * resolve_state() and build_context() (both private in 1.0.5; resolve_state()
	 * is public @internal since build step 4, build_context() still private, so
	 * reflection keeps one code path for the 1.0.5 capture and this tree), the
	 * same way render_branded(), render_lostpassword_action() and
	 * render_resetpass_action() call them for the current request. The template
	 * is the plugin's own login-form.php: LoginScreen resolves it through
	 * Mailer::locate_template() since step 4 (B6), which finds no theme
	 * override under the harness default theme directory.
	 *
	 * @return array<string,mixed>
	 */
	public static function login_context( string $state ): array {
		$call = static function ( string $method, ...$args ) {
			$ref = new \ReflectionMethod( LoginScreen::class, $method );
			if ( PHP_VERSION_ID < 80100 ) {
				$ref->setAccessible( true );
			}
			return $ref->invoke( null, ...$args );
		};

		if ( 'd' === $state || 'e' === $state ) {
			$context = $call( 'build_context', $state, '' );
			if ( 'e' === $state ) {
				$context['reset_key']   = trim( (string) wp_unslash( $_GET['key'] ?? '' ) );
				$context['reset_login'] = trim( (string) wp_unslash( $_GET['login'] ?? '' ) );
			}
			return $context;
		}

		$step     = isset( $_GET['magicauth_step'] ) ? sanitize_key( wp_unslash( (string) $_GET['magicauth_step'] ) ) : '';
		$resolved = $call( 'resolve_state', $step );
		if ( $resolved !== $state ) {
			throw new \LogicException( "request for state {$state} resolves to {$resolved}" );
		}
		$session_id = isset( $_GET['magicauth_sid'] ) ? sanitize_key( wp_unslash( (string) $_GET['magicauth_sid'] ) ) : '';
		return $call( 'build_context', $resolved, $session_id );
	}

	private static function shortcode( bool $logged_in ): string {
		self::request( '/login/' );
		$user               = magicauth_test_register_user( self::USER_ID, 'student@example.test' );
		$user->display_name = 'Student Example';
		$user->user_login   = 'student';
		if ( $logged_in ) {
			magicauth_test_login_as( self::USER_ID );
		}
		return Shortcode::render( [] );
	}

	/** @return array<string,array<string,mixed>> Recorded wp_mail() calls by fixture base name. */
	private static function emails(): array {
		global $magicauth_test_state;
		$out = [];

		self::request( '/' );
		$user               = magicauth_test_register_user( self::USER_ID, 'student@example.test' );
		$user->display_name = 'Student Example';
		$user->user_login   = 'student';
		Mailer::send_magic_link( self::USER_ID, self::LINK, 'ABCDEF', '2026-10-01 12:10:00' );
		$out['email-magic-link'] = $magicauth_test_state['mail'][0];

		self::request( '/' );
		$user               = magicauth_test_register_user( self::USER_ID, 'student@example.test' );
		$user->display_name = 'Student Example';
		$user->user_login   = 'student';
		Mailer::send_disabled_notice( self::USER_ID );
		$out['email-disabled-notice'] = $magicauth_test_state['mail'][0];

		return $out;
	}
}
