<?php
/**
 * B6 (SPEC 15 step 4, 8.5 item 5, Appendix D): the shortcode and the branded
 * wp-login screen resolve login-form.php and login-shell.php through
 * Mailer::locate_template(), so yourtheme/magicauth/ (child theme first,
 * then parent theme, then the plugin) overrides them, as the login-form
 * docblock claims. Also pins the state resolvers made public (@internal)
 * for Assets (8.11).
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Frontend\LoginScreen;
use MagicAuth\Frontend\Shortcode;
use PHPUnit\Framework\TestCase;

final class TemplateOverrideTest extends TestCase {

	private string $root = '';

	protected function setUp(): void {
		global $magicauth_test_state;
		magicauth_test_reset_state();
		$this->root = sys_get_temp_dir() . '/magicauth theme ' . bin2hex( random_bytes( 6 ) );
		foreach ( [ 'child/magicauth', 'parent/magicauth', 'child/auth-templates' ] as $dir ) {
			mkdir( $this->root . '/' . $dir, 0700, true );
		}
		$magicauth_test_state['stylesheet_directory'] = $this->root . '/child';
		$magicauth_test_state['template_directory']   = $this->root . '/parent';
		$_SERVER['HTTP_HOST']                         = 'example.test';
		$_SERVER['REQUEST_URI']                       = '/login/';
		$_GET                                         = [];
		$_COOKIE                                      = [];
	}

	protected function tearDown(): void {
		$this->remove( $this->root );
		$_GET    = [];
		$_COOKIE = [];
		unset( $_SERVER['HTTP_HOST'], $_SERVER['REQUEST_URI'] );
		magicauth_test_reset_state();
	}

	/* ----------------------------------------------------------- shortcode */

	public function test_shortcode_renders_the_child_theme_login_form(): void {
		$this->override( 'child/magicauth/login-form.php', 'child-form' );

		$html = Shortcode::render( [] );

		$this->assertStringContainsString( 'data-marker="child-form"', $html );
		$this->assertStringContainsString( 'data-state="a"', $html );
		$this->assertMatchesRegularExpression( '#data-action="https?://example\.test/wp-admin/admin-post\.php"#', $html );
		$this->assertStringNotContainsString( 'class="magicauth-card"', $html, 'the plugin form is not rendered as well' );
		$this->assertStringStartsWith( '<div class="magicauth-shell">', $html );
	}

	public function test_shortcode_override_receives_the_current_state(): void {
		$this->override( 'child/magicauth/login-form.php', 'child-form' );

		$_GET = [ 'magicauth_step' => 'code' ];
		$this->assertStringContainsString( 'data-state="b"', Shortcode::render( [] ) );

		$_GET = [ 'magicauth_step' => 'password' ];
		$this->assertStringContainsString( 'data-state="c"', Shortcode::render( [] ) );
	}

	public function test_parent_theme_override_is_used_when_the_child_has_none(): void {
		$this->override( 'parent/magicauth/login-form.php', 'parent-form' );

		$this->assertStringContainsString( 'data-marker="parent-form"', Shortcode::render( [] ) );
	}

	public function test_child_theme_wins_over_the_parent_theme(): void {
		$this->override( 'parent/magicauth/login-form.php', 'parent-form' );
		$this->override( 'child/magicauth/login-form.php', 'child-form' );

		$html = Shortcode::render( [] );
		$this->assertStringContainsString( 'data-marker="child-form"', $html );
		$this->assertStringNotContainsString( 'parent-form', $html );
	}

	public function test_template_path_filter_moves_the_theme_folder(): void {
		$this->override( 'child/magicauth/login-form.php', 'default-folder' );
		$this->override( 'child/auth-templates/login-form.php', 'filtered-folder' );
		add_filter(
			'magicauth_template_path',
			static function (): string {
				return 'auth-templates/';
			}
		);

		$html = Shortcode::render( [] );
		$this->assertStringContainsString( 'data-marker="filtered-folder"', $html );
		$this->assertStringNotContainsString( 'default-folder', $html );
	}

	public function test_locate_template_filter_sees_the_login_form_lookup(): void {
		$seen = [];
		add_filter(
			'magicauth_locate_template',
			static function ( $path, $filename, $candidates ) use ( &$seen ) {
				$seen[] = [ $filename, $candidates ];
				return $path;
			},
			10,
			3
		);

		Shortcode::render( [] );

		$this->assertSame( 'login-form.php', $seen[0][0] ?? null );
		$this->assertSame(
			[
				$this->root . '/child/magicauth/login-form.php',
				$this->root . '/parent/magicauth/login-form.php',
				MAGICAUTH_DIR . 'templates/login-form.php',
			],
			$seen[0][1]
		);
	}

	public function test_shortcode_without_override_renders_the_plugin_form(): void {
		$html = Shortcode::render( [] );

		$this->assertStringContainsString( 'class="magicauth-card"', $html );
		$this->assertStringContainsString( 'id="magicauth-email"', $html );
	}

	public function test_logged_in_notice_ignores_the_form_override(): void {
		$this->override( 'child/magicauth/login-form.php', 'child-form' );
		magicauth_test_register_user( 41, 'in@example.test' );
		magicauth_test_login_as( 41 );

		$html = Shortcode::render( [] );
		$this->assertStringNotContainsString( 'child-form', $html );
		$this->assertStringContainsString( 'magicauth-notice', $html );
	}

	/* -------------------------------------------------------- login screen */

	public function test_login_screen_uses_the_theme_shell_and_form(): void {
		$this->override( 'child/magicauth/login-shell.php', 'child-shell', true );
		$this->override( 'child/magicauth/login-form.php', 'child-form' );

		$html = $this->render_login_screen( 'a' );

		$this->assertStringContainsString( 'data-marker="child-shell"', $html );
		$this->assertStringContainsString( 'data-form-path="' . $this->root . '/child/magicauth/login-form.php"', $html );
		$this->assertStringContainsString( 'data-marker="child-form"', $html );
		$this->assertStringNotContainsString( 'magicauth-shell-vars', $html, 'the plugin shell is not rendered as well' );
	}

	public function test_plugin_shell_includes_the_theme_form(): void {
		$this->override( 'child/magicauth/login-form.php', 'child-form' );

		foreach ( [ 'a', 'b', 'c', 'd', 'e' ] as $state ) {
			$html = $this->render_login_screen( $state );
			$this->assertStringContainsString( '<style id="magicauth-shell-vars">', $html, $state );
			$this->assertStringContainsString( 'data-marker="child-form"', $html, $state );
			$this->assertStringContainsString( 'data-state="' . $state . '"', $html, $state );
			$this->assertStringNotContainsString( 'class="magicauth-card"', $html, $state );
		}
	}

	public function test_theme_shell_with_the_plugin_form(): void {
		$this->override( 'parent/magicauth/login-shell.php', 'parent-shell', true );

		$html = $this->render_login_screen( 'a' );
		$this->assertStringContainsString( 'data-marker="parent-shell"', $html );
		$this->assertStringContainsString( 'data-form-path="' . MAGICAUTH_DIR . 'templates/login-form.php"', $html );
		$this->assertStringContainsString( 'class="magicauth-card"', $html );
	}

	public function test_login_screen_without_override_renders_the_plugin_templates(): void {
		global $magicauth_test_state;
		$html = $this->render_login_screen( 'a' );

		$this->assertStringContainsString( '<style id="magicauth-shell-vars">', $html );
		$this->assertStringContainsString( 'class="magicauth-card"', $html );
		$this->assertSame( [ 'Sign in' ], $magicauth_test_state['login_header_calls'] ?? [] );
	}

	/* ------------------------------------------------------ state resolvers */

	public function test_state_resolvers_are_public_and_internal(): void {
		foreach ( [ [ Shortcode::class, 'current_state' ], [ LoginScreen::class, 'resolve_state' ] ] as $callable ) {
			$ref = new \ReflectionMethod( $callable[0], $callable[1] );
			$this->assertTrue( $ref->isPublic(), $callable[1] );
			$this->assertTrue( $ref->isStatic(), $callable[1] );
			$this->assertStringContainsString( '@internal', (string) $ref->getDocComment(), $callable[1] );
		}
	}

	public function test_shortcode_current_state(): void {
		$cases = [
			''             => 'a',
			'code'         => 'b',
			'password'     => 'c',
			'lostpassword' => 'a', // D and E are wp-login.php only.
			'unknown'      => 'a',
			'CODE'         => 'b', // sanitize_key() lowercases.
		];
		foreach ( $cases as $step => $state ) {
			$_GET = '' === $step ? [] : [ 'magicauth_step' => $step ];
			$this->assertSame( $state, Shortcode::current_state(), (string) $step );
		}
	}

	public function test_login_screen_resolve_state(): void {
		$cases = [
			''             => 'a',
			'code'         => 'b',
			'password'     => 'c',
			'lostpassword' => 'd',
			'reset'        => 'a',
			'unknown'      => 'a',
		];
		foreach ( $cases as $step => $state ) {
			$this->assertSame( $state, LoginScreen::resolve_state( (string) $step ), (string) $step );
		}
	}

	/* ------------------------------------------------------------- helpers */

	/** Writes a theme template that prints its marker, the state and (for a shell) the form path it got. */
	private function override( string $relative, string $marker, bool $shell = false ): void {
		$body = $shell
			? '<div data-marker="' . $marker . '" data-form-path="<?php echo esc_attr( (string) $form_path ); ?>">'
				. '<?php if ( is_readable( (string) $form_path ) ) { include (string) $form_path; } ?></div>'
			: '<p data-marker="' . $marker . '" data-state="<?php echo esc_attr( $state ); ?>"'
				. ' data-action="<?php echo esc_attr( $action_url ); ?>"></p>';
		file_put_contents( $this->root . '/' . $relative, "<?php defined( 'ABSPATH' ) || exit; ?>\n" . $body . "\n" );
	}

	/** LoginScreen's own context and shell render for $state (the branded paths add login_footer() and exit). */
	private function render_login_screen( string $state ): string {
		$build = new \ReflectionMethod( LoginScreen::class, 'build_context' );
		$shell = new \ReflectionMethod( LoginScreen::class, 'render_shell' );
		if ( PHP_VERSION_ID < 80100 ) {
			$build->setAccessible( true );
			$shell->setAccessible( true );
		}
		ob_start();
		try {
			$shell->invoke( null, $build->invoke( null, $state, '' ) );
		} finally {
			$html = (string) ob_get_clean();
		}
		return $html;
	}

	private function remove( string $path ): void {
		if ( '' === $path || ! file_exists( $path ) ) {
			return;
		}
		if ( is_dir( $path ) && ! is_link( $path ) ) {
			foreach ( (array) scandir( $path ) as $entry ) {
				if ( '.' !== $entry && '..' !== $entry ) {
					$this->remove( $path . '/' . $entry );
				}
			}
			rmdir( $path );
			return;
		}
		unlink( $path );
	}
}
