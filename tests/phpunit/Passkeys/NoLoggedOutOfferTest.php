<?php
/**
 * T-OFFER (SPEC 2.6 rows 1 to 5, 14.1, decision 2), the parts build step 12
 * owns: 1 the logged-out login form (states A to E, module on) and the
 * printed login config never offer or mention creating a passkey, state A
 * carries only the sign-in block, an unknown magicauth_step renders state A
 * with the login script; 3 static scans of the login and core scripts; 4 the
 * sign-in strings L1 to L11 and L3b (en_US). Build step 15 adds T-OFFER-2
 * (login email msgids and their nl_NL msgstr, and the login emails rendered
 * in every shipped locale) and the nl_NL half of 4. T-OFFER-5
 * ([magicauth_passkeys] logged out) came with step 13.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Email\Mailer;
use MagicAuth\Frontend\Shortcode;
use MagicAuth\Passkeys\AccountEndpoints;
use MagicAuth\Passkeys\Assets;
use MagicAuth\Passkeys\SignInEndpoints;
use MagicAuth\Tests\Support\Ceremony;
use MagicAuth\Tests\Support\Golden;
use MagicAuth\Tests\Support\Po;
use PHPUnit\Framework\TestCase;

final class NoLoggedOutOfferTest extends TestCase {

	/** The wp-login.php request of each state (as Golden renders them). */
	private const LOGIN_URIS = [
		'a' => '/wp-login.php?action=magicauth',
		'b' => '/wp-login.php?action=magicauth&magicauth_step=code&magicauth_sid=0123456789abcdef0123456789abcdef',
		'c' => '/wp-login.php?action=magicauth&magicauth_step=password',
		'd' => '/wp-login.php?action=lostpassword',
		'e' => '/wp-login.php?action=rp&key=resetkey0123456789&login=student',
	];

	/** The login emails (decision 2: never mention passkeys, 10.1). */
	private const LOGIN_EMAIL_TEMPLATES = [
		'templates/email-magic-link.php',
		'templates/email-magic-link-plain.php',
		'templates/email-disabled-notice.php',
		'templates/email-disabled-notice-plain.php',
	];

	/** The term in English and both Dutch platform words (Q2). */
	private const PASSKEY_WORDS = '/passkey|toegangssleutel|wachtwoordsleutel/i';

	/** Dutch creation wording (T-OFFER-4). */
	private const NL_CREATION = '/\b(aanmaken|toevoegen)\b/i';

	private const NL_L10N = MAGICAUTH_DIR . 'languages/magicauth-nl_NL.l10n.php';

	/** Creation wording, case-insensitive, as words. */
	private const CREATION = '/\b(create|creating|created|add|adding|added|register|registration|reauth|prompt)\b/i';

	protected function setUp(): void {
		Ceremony::site();
		Ceremony::enable_module();
		$_SERVER['HTTP_HOST'] = 'academy.example.com';
	}

	protected function tearDown(): void {
		global $post;
		$post = null;
		$_GET = [];
		unset( $_SERVER['HTTP_HOST'], $_SERVER['REQUEST_URI'] );
		magicauth_test_reset_state();
	}

	/** The template as LoginScreen renders it for $state's request, logged out, module on. */
	private static function render_state( string $state ): string {
		$_SERVER['REQUEST_URI'] = self::LOGIN_URIS[ $state ];
		$_GET                   = [];
		parse_str( (string) wp_parse_url( self::LOGIN_URIS[ $state ], PHP_URL_QUERY ), $_GET );
		$context = Golden::login_context( $state );
		ob_start();
		( static function ( string $tpl, array $args ): void {
			extract( $args, EXTR_SKIP ); // phpcs:ignore WordPress.PHP.DontExtract.extract_extract
			include $tpl;
		} )( MAGICAUTH_DIR . 'templates/login-form.php', $context );
		return (string) ob_get_clean();
	}

	private static function login_config_json(): string {
		return (string) wp_json_encode( Assets::login_config(), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES );
	}

	/**
	 * Messages of the signed-in passkey surfaces built so far (P, M and R
	 * fallbacks of the account endpoints), none of which may reach a
	 * logged-out page. The shared "not available" first sentence (P12) is
	 * also the start of L7 and carries no creation wording.
	 *
	 * @return array<int,string>
	 */
	private static function account_msgids(): array {
		$message = new \ReflectionMethod( AccountEndpoints::class, 'message' );
		if ( PHP_VERSION_ID < 80100 ) {
			$message->setAccessible( true );
		}
		$out = [];
		foreach ( [ 'reauth_required', 'reauth_unavailable', 'limit_reached', 'registration_failed', 'duplicate_name', 'code_invalid', 'reauth_failed', 'throttled', 'retry' ] as $code ) {
			$out[] = (string) $message->invoke( null, $code );
		}
		return $out;
	}

	private function assert_no_offer( string $text, string $label ): void {
		$this->assertDoesNotMatchRegularExpression( self::CREATION, $text, $label );
		foreach ( [ 'Create a passkey', 'Add a passkey', 'toegangssleutel', 'wachtwoordsleutel' ] as $phrase ) {
			$this->assertStringNotContainsStringIgnoringCase( $phrase, $text, $label );
		}
		foreach ( self::account_msgids() as $msgid ) {
			$this->assertStringNotContainsString( $msgid, $text, $label . ': account msgid' );
		}
	}

	/* ----------------------------------------------------------------- 1 */

	public function test_1_logged_out_states_and_config_never_offer_creation(): void {
		foreach ( array_keys( self::LOGIN_URIS ) as $state ) {
			$this->assert_no_offer( self::render_state( $state ), 'state ' . $state );
		}
		$this->assert_no_offer( self::login_config_json(), 'login config' );
	}

	public function test_1_state_a_carries_only_the_signin_block(): void {
		$html = self::render_state( 'a' );
		$this->assertStringContainsString( 'autocomplete="username webauthn"', $html );
		$this->assertStringContainsString( SignInEndpoints::strings()['L1'], $html );
		$this->assertSame( 1, substr_count( $html, 'data-magicauth-passkey-root' ) );
		$this->assertSame( 1, substr_count( $html, 'data-magicauth-passkey-signin' ) );
		$this->assertStringNotContainsString( 'data-magicauth-pk-', $html, 'no account markup' );
		$this->assertStringNotContainsString( 'magicauth_passkey_register', $html );
	}

	public function test_1_states_b_to_e_carry_no_passkey_markup(): void {
		foreach ( [ 'b', 'c', 'd', 'e' ] as $state ) {
			$html = self::render_state( $state );
			$this->assertStringNotContainsStringIgnoringCase( 'passkey', $html, $state );
			$this->assertStringNotContainsString( 'webauthn', $html, $state );
		}
	}

	public function test_1_login_config_is_exactly_the_signin_shape(): void {
		$config = Assets::login_config();
		$this->assertSame( [ 'ajaxUrl', 'rpId', 'homeUrl', 'actions', 'i18n' ], array_keys( $config ) );
		$this->assertSame(
			[
				'signinOptions' => 'magicauth_passkey_signin_options',
				'signin'        => 'magicauth_passkey_signin',
				'complete'      => 'magicauth_passkey_complete',
			],
			$config['actions']
		);
		$this->assertSame( [ 'L1', 'L2', 'L3', 'L3b', 'L4', 'L5', 'L6', 'L7', 'L8', 'L9', 'L10', 'L11' ], array_keys( $config['i18n'] ) );
		$this->assertSame( 'https://academy.example.com/wp-admin/admin-ajax.php', $config['ajaxUrl'] );
		$this->assertSame( Ceremony::RP, $config['rpId'] );
		$this->assertSame( 'https://academy.example.com/', $config['homeUrl'] );

		// No per-user data: the same for a visitor and for a signed-in user (cache-safe).
		Ceremony::user( 7 );
		magicauth_test_login_as( 7 );
		$this->assertSame( $config, Assets::login_config() );
	}

	public function test_1_unknown_step_renders_state_a_with_the_login_script(): void {
		global $post, $magicauth_test_state;
		$_GET                   = [ 'magicauth_step' => 'bogus' ];
		$_SERVER['REQUEST_URI'] = '/login/?magicauth_step=bogus';
		$post                   = new \WP_Post( '[magicauth_login]' );

		$html = Shortcode::render( [] );
		$this->assertStringContainsString( 'data-magicauth-passkey-signin', $html );
		$this->assertStringContainsString( 'username webauthn', $html );

		Assets::enqueue_front();
		$this->assertArrayHasKey( Assets::LOGIN_HANDLE, $magicauth_test_state['enqueued_scripts'] ?? [] );
	}

	public function test_1_toasts_carry_no_passkey_string(): void {
		$this->assertStringNotContainsStringIgnoringCase( 'passkey', (string) file_get_contents( MAGICAUTH_DIR . 'includes/Frontend/Toast.php' ) );
	}

	/* ----------------------------------------------------------------- 2 */

	public function test_2_login_email_msgids_and_their_nl_msgstr_never_mention_passkeys(): void {
		$nl    = Po::entries( MAGICAUTH_DIR . 'languages/magicauth-nl_NL.po' );
		$by_id = [];
		foreach ( $nl as $entry ) {
			$by_id[ $entry['id'] ] = $entry;
			if ( null !== $entry['plural'] ) {
				$by_id[ $entry['plural'] ] = $entry;
			}
		}

		$msgids = [];
		foreach ( self::LOGIN_EMAIL_TEMPLATES as $template ) {
			$source = Po::source_msgids( MAGICAUTH_DIR . $template );
			$this->assertNotSame( [], $source, $template );
			// The catalogue's references agree with the source scan.
			$referenced = [];
			foreach ( Po::referenced_from( $nl, $template ) as $entry ) {
				$referenced[] = $entry['id'];
				if ( null !== $entry['plural'] ) {
					$referenced[] = $entry['plural'];
				}
			}
			sort( $source );
			sort( $referenced );
			$this->assertSame( $source, $referenced, $template );
			$msgids = array_merge( $msgids, $source );
		}
		// Subjects and fallbacks the two login dispatchers build.
		$msgids = array_merge( $msgids, Po::method_msgids( Mailer::class, [ 'dispatch', 'dispatch_disabled_notice', 'build_args', 'build_disabled_notice_args' ] ) );
		$this->assertGreaterThan( 15, count( $msgids ) );

		foreach ( array_unique( $msgids ) as $msgid ) {
			$this->assertDoesNotMatchRegularExpression( self::PASSKEY_WORDS, $msgid );
			$this->assertArrayHasKey( $msgid, $by_id, $msgid );
			foreach ( $by_id[ $msgid ]['str'] as $str ) {
				$this->assertNotSame( '', $str, 'translated: ' . $msgid );
				$this->assertDoesNotMatchRegularExpression( self::PASSKEY_WORDS, $str, $msgid );
			}
		}
	}

	/** @return array<string,array{string}> */
	public static function shipped_locales(): array {
		return [
			'en_US' => [ 'en_US' ],
			'nl_NL' => [ 'nl_NL' ],
			'de_DE' => [ 'de_DE' ],
			'es_ES' => [ 'es_ES' ],
		];
	}

	/** @dataProvider shipped_locales */
	public function test_2_login_emails_never_mention_passkeys_in_any_shipped_locale( string $locale ): void {
		global $magicauth_test_state;
		update_option( 'magicauth_settings', [ 'company_name' => 'Example Academy', 'passkeys_enabled' => true ] );
		$user         = Ceremony::user( 7 );
		$user->locale = $locale;
		if ( 'en_US' !== $locale ) {
			magicauth_test_load_translations( $locale, MAGICAUTH_DIR . 'languages/magicauth-' . $locale . '.l10n.php' );
		}

		$this->assertTrue( Mailer::send_magic_link( 7, Ceremony::ORIGIN . '/?magicauth=verify&s=abc&v=def', 'ABC2EF', gmdate( 'Y-m-d H:i:s', Ceremony::NOW + 600 ) ) );
		$this->assertTrue( Mailer::send_disabled_notice( 7 ) );

		$mails = $magicauth_test_state['mail'] ?? [];
		$this->assertCount( 2, $mails );
		foreach ( $mails as $mail ) {
			foreach ( [ $mail['subject'], $mail['message'], $mail['alt_body'] ] as $part ) {
				$this->assertDoesNotMatchRegularExpression( self::PASSKEY_WORDS, (string) $part, $locale );
			}
		}
		if ( 'nl_NL' === $locale ) {
			$this->assertStringContainsString( 'Heb je dit niet aangevraagd', $mails[0]['message'], 'rendered in Dutch' );
			$this->assertStringContainsString( 'Inlogcode:', $mails[0]['alt_body'] );
		}
	}

	/* ----------------------------------------------------------------- 3 */

	/** @return array<string,array{string}> */
	public static function signin_scripts(): array {
		return [
			'login' => [ 'assets/js/magicauth-passkeys-login.js' ],
			'core'  => [ 'assets/js/magicauth-passkeys-core.js' ],
		];
	}

	/** @dataProvider signin_scripts */
	public function test_3_signin_scripts_contain_no_creation_code( string $file ): void {
		$source = (string) file_get_contents( MAGICAUTH_DIR . $file );
		$this->assertNotSame( '', $source );
		$this->assertStringNotContainsString( 'credentials.create', $source );
		$this->assertStringNotContainsString( 'parseCreation', $source );
		$this->assertStringNotContainsStringIgnoringCase( 'register', $source );
		$this->assertDoesNotMatchRegularExpression( '/mediation[^;]{0,80}create|create[^;]{0,80}mediation/is', $source );
		$this->assertDoesNotMatchRegularExpression( '/magicauth_passkey_(register|rename|delete|reauth|prompt|signout)/', $source, 'no account action name' );
		$this->assertStringNotContainsString( 'innerHTML', $source, 'textContent and setAttribute only' );
	}

	/**
	 * T-OFFER-3, account script (build steps 13 and 14): one create() call,
	 * in create(), which only onCreateClick()'s click listener runs; the
	 * prompt (P4, P18) and the management Add (M4) share it. Never
	 * conditional.
	 */
	public function test_3_account_script_creates_only_from_the_click_path(): void {
		$source = (string) file_get_contents( MAGICAUTH_DIR . 'assets/js/magicauth-passkeys-account.js' );
		$this->assertNotSame( '', $source );
		$this->assertSame( 1, substr_count( $source, 'credentials.create' ), 'exactly one credentials.create' );
		$this->assertSame( 1, preg_match_all( '/navigator\.credentials\.create\(/', $source ) );
		$this->assertDoesNotMatchRegularExpression( '/mediation/i', $source, 'no conditional create, no conditional anything' );
		$this->assertStringNotContainsString( 'innerHTML', $source, 'textContent and setAttribute only' );
		$this->assertStringNotContainsString( 'nopriv', $source );

		// The call sits in create( ctx ).
		$this->assertSame( 1, preg_match( '/\n\tasync function create\( ctx \) \{\n(.*?)\n\t\}\n/s', $source, $m ) );
		$this->assertStringContainsString( 'navigator.credentials.create(', $m[1] );

		// create() is called exactly once, inside the listener onCreateClick() returns.
		$code = (string) preg_replace( '#//[^\n]*#', '', $source );
		$this->assertSame( 1, preg_match_all( '/(?<![\w.])create\(\s*ctx\s*\)(?!\s*\{)/', $code ), 'one call site' );
		$this->assertSame( 1, preg_match( '/\n\tfunction onCreateClick\( ctx \) \{\n\t\treturn function \(\) \{\n\t\t\tcreate\( ctx \);\n\t\t\};\n\t\}\n/', $code ) );

		// onCreateClick() is only ever passed to a click listener: P4 and P18 in the prompt, M4 on the page.
		$uses   = preg_match_all( '/(?<![\w.])onCreateClick\(/', $code ) - 1;
		$clicks = substr_count( $code, "addEventListener( 'click', onCreateClick(" );
		$this->assertSame( 2, $clicks );
		$this->assertSame( $clicks, $uses );
		$this->assertDoesNotMatchRegularExpression( '/(?<![\w.])create\(\s*\)/', $code, 'no create() without a context' );
	}

	public function test_3_only_the_signin_actions_are_named_in_the_login_script(): void {
		$source = (string) file_get_contents( MAGICAUTH_DIR . 'assets/js/magicauth-passkeys-login.js' );
		$this->assertStringContainsString( "mediation: 'conditional'", $source, 'autofill uses conditional get()' );
		$this->assertStringContainsString( 'credentials.get(', $source );
		$this->assertDoesNotMatchRegularExpression( '/[\'"]magicauth_passkey_(?!error[\'"])/', $source, 'action names come from the config' );
	}

	/* ----------------------------------------------------------------- 4 */

	public function test_4_signin_strings_never_mention_creation(): void {
		$strings = SignInEndpoints::strings();
		$this->assertSame( [ 'L1', 'L2', 'L3', 'L3b', 'L4', 'L5', 'L6', 'L7', 'L8', 'L9', 'L10', 'L11' ], array_keys( $strings ) );
		foreach ( $strings as $id => $text ) {
			$this->assertNotSame( '', $text, $id );
			$this->assertDoesNotMatchRegularExpression( '/\b(create|add)\b/i', $text, $id );
		}
	}

	public function test_4_signin_strings_never_mention_creation_in_nl(): void {
		$en = SignInEndpoints::strings();
		magicauth_test_load_translations( 'nl_NL', self::NL_L10N );
		switch_to_locale( 'nl_NL' );
		try {
			$nl     = SignInEndpoints::strings();
			$config = self::login_config_json();
		} finally {
			restore_previous_locale();
		}

		$this->assertSame( array_keys( $en ), array_keys( $nl ) );
		foreach ( $nl as $id => $text ) {
			$this->assertNotSame( $en[ $id ], $text, $id . ' is translated' );
			$this->assertDoesNotMatchRegularExpression( self::NL_CREATION, $text, $id );
			$this->assertDoesNotMatchRegularExpression( '/toegangssleutel|wachtwoordsleutel/i', $text, $id . ': no gloss on the login form' );
		}
		$this->assertDoesNotMatchRegularExpression( self::NL_CREATION, $config );
		$this->assertStringContainsString( 'Inloggen met een passkey', $config );
		$this->assert_no_offer( $config, 'nl login config' );

		// The same check on the shipped catalogue, independent of the stub.
		$po = Po::keyed( MAGICAUTH_DIR . 'languages/magicauth-nl_NL.po' );
		foreach ( [ 'Sign in with a passkey', 'Waiting for your passkey.', "divider between the email form and the passkey button\4or" ] as $key ) {
			$this->assertDoesNotMatchRegularExpression( self::NL_CREATION, $po[ $key ]['str'][0], $key );
		}
	}
}
