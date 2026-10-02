<?php
/**
 * The account script's prompt and its shared create and step-up paths (SPEC
 * 2.1, 2.3, 3.5, 8.3, 8.6, 8.7, 8.11, 8.12, build step 14): every scenario
 * of js/account-script.js runs the shipped core and account scripts in node
 * against the markup and config the PHP side renders here (the prompt
 * dialog and the management section), with a fake fetch,
 * navigator.credentials and localStorage. Covers the client gate (G1, the
 * shared-device flag, promptfail and haslocal ages, G3), the four choices,
 * create success and every error view, the step-up inside the prompt, the
 * back/forward cache restore, session-time signals and the management Add
 * after the refactor. The inline signals call is run by SignalsTest.
 * Skipped (not passed) without node.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Passkeys\Assets;
use MagicAuth\Passkeys\ManageShortcode;
use MagicAuth\Passkeys\Module;
use MagicAuth\Passkeys\ProfileSection;
use MagicAuth\Passkeys\Prompt;
use MagicAuth\Tests\Support\Ceremony;
use MagicAuth\Tests\Support\SoftAuthenticator;
use PHPUnit\Framework\TestCase;

final class AccountScriptTest extends TestCase {

	private const HARNESS = __DIR__ . '/js/account-script.js';

	/** Scenarios that need another input than the page fixture. */
	private const OWN_INPUT = [ 'inline_signals' ];

	private static function node(): ?string {
		$path = trim( (string) shell_exec( 'command -v node 2>/dev/null' ) );
		return '' !== $path && is_executable( $path ) ? $path : null;
	}

	/** @return array<string,array{string}> */
	public static function scenarios(): array {
		$node = self::node();
		if ( null === $node ) {
			return [ 'node missing' => [ '' ] ];
		}
		$list = (string) shell_exec( escapeshellarg( $node ) . ' ' . escapeshellarg( self::HARNESS ) . ' ' . escapeshellarg( MAGICAUTH_DIR ) . ' --list 2>&1' );
		$out  = [];
		foreach ( array_filter( array_map( 'trim', explode( "\n", $list ) ) ) as $name ) {
			if ( ! in_array( $name, self::OWN_INPUT, true ) ) {
				$out[ $name ] = [ $name ];
			}
		}
		return $out;
	}

	protected function tearDown(): void {
		global $post;
		$post    = null;
		$_COOKIE = [];
		magicauth_test_reset_state();
	}

	/** @dataProvider scenarios */
	public function test_scenario( string $name ): void {
		$node = self::node();
		if ( null === $node || '' === $name ) {
			$this->markTestSkipped( 'node is not installed' );
		}
		$fixture = tempnam( sys_get_temp_dir(), 'magicauth-account-' );
		$this->assertNotFalse( $fixture );
		$json = $fixture . '.json';
		rename( $fixture, $json );
		file_put_contents( $json, (string) wp_json_encode( $this->fixture() ) );
		try {
			$cmd    = escapeshellarg( $node ) . ' ' . escapeshellarg( self::HARNESS ) . ' ' . escapeshellarg( MAGICAUTH_DIR ) . ' ' . escapeshellarg( $name ) . ' ' . escapeshellarg( $json ) . ' 2>&1';
			$output = (string) shell_exec( $cmd );
		} finally {
			unlink( $json );
		}
		$this->assertSame( "ok\n", $output, $name );
	}

	public function test_the_harness_lists_the_scenarios(): void {
		if ( null === self::node() ) {
			$this->markTestSkipped( 'node is not installed' );
		}
		$this->assertGreaterThanOrEqual( 25, count( self::scenarios() ) );
	}

	/**
	 * The prompt as the footer prints it and its account config, the
	 * management section as the shortcode renders it and its config, and the
	 * own wp-admin profile section with its footer dialogs and config.
	 *
	 * @return array{prompt:array{html:string,config:array<string,mixed>},manage:array{html:string,config:array<string,mixed>},profile:array{html:string,config:array<string,mixed>}}
	 */
	private function fixture(): array {
		global $post, $magicauth_test_state;
		Ceremony::site();
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => true ] );
		Module::reset_for_tests();
		$user = Ceremony::user( 7 );
		Ceremony::enrol( new SoftAuthenticator( 'ES256' ), $user );
		Ceremony::sign_in( $user, 'link' );

		Prompt::prepare_front();
		ob_start();
		Prompt::render_footer();
		$prompt = [
			'html'   => (string) ob_get_clean(),
			'config' => self::config(),
		];
		$this->assertStringContainsString( 'data-magicauth-pk-prompt', $prompt['html'] );

		Assets::reset_for_tests();
		unset( $magicauth_test_state['inline_scripts'] );
		$post                            = new \WP_Post( '[magicauth_passkeys]' );
		$magicauth_test_state['queried'] = [
			'id'   => 50,
			'type' => 'page',
			'post' => $post,
		];
		$manage = [
			'html'   => ManageShortcode::render(),
			'config' => self::config(),
		];

		Assets::reset_for_tests();
		ProfileSection::reset_for_tests();
		unset( $magicauth_test_state['inline_scripts'] );
		$post = null;
		Assets::enqueue_admin( 'profile.php' );
		ob_start();
		ProfileSection::render( $user );
		echo '<p>between the profile form and the footer</p>';
		ProfileSection::render_dialogs();
		$profile = [
			'html'   => (string) ob_get_clean(),
			'config' => self::config(),
		];
		return [
			'prompt'  => $prompt,
			'manage'  => $manage,
			'profile' => $profile,
		];
	}

	/** @return array<string,mixed> */
	private static function config(): array {
		global $magicauth_test_state;
		$inline = $magicauth_test_state['inline_scripts'][ Assets::ACCOUNT_HANDLE ] ?? [];
		self::assertCount( 1, $inline );
		self::assertSame( 1, preg_match( '/^window\.magicauthPasskeysConfig = (.*);$/s', $inline[0][0], $m ) );
		return (array) json_decode( $m[1], true );
	}
}
