<?php
/**
 * Passkey settings (SPEC 4.7, 9.5, build step 10): Settings::sanitize() for
 * the six new keys (enabling refused with the precise S8 reason in the 4.5
 * precedence, the management page check, S9, the clamps), the settings
 * fields, and the read-only S6 diagnostics with S6b, S9 and the S8 reason.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Admin\Settings;
use MagicAuth\Passkeys\Module;
use MagicAuth\Tests\Support\Ceremony;
use PHPUnit\Framework\TestCase;

final class SettingsTest extends TestCase {

	private const S8 = 'Passkeys cannot be turned on: ';

	private const S9 = 'Users without wp-admin access cannot manage their passkeys until you choose a management page.';

	protected function setUp(): void {
		Ceremony::site();
	}

	protected function tearDown(): void {
		magicauth_test_reset_state();
	}

	/** @return array<int,array{setting:string,code:string,message:string,type:string}> */
	private static function errors(): array {
		global $magicauth_test_state;
		return $magicauth_test_state['settings_errors'] ?? [];
	}

	/** @return array<int,string> */
	private static function error_codes(): array {
		return array_column( self::errors(), 'code' );
	}

	private static function page( int $id, string $status = 'publish', string $type = 'page', string $title = 'Account' ): void {
		global $magicauth_test_state;
		$magicauth_test_state['posts'][ $id ] = [
			'status' => $status,
			'type'   => $type,
			'title'  => $title,
		];
	}

	/**
	 * @param array<string,mixed> $input
	 * @return array<string,mixed>
	 */
	private static function save( array $input ): array {
		return Settings::sanitize( $input );
	}

	/* --------------------------------------------------------- enabling */

	public function test_enabling_on_an_available_site_is_stored(): void {
		self::page( 12 );
		$out = self::save(
			[
				'passkeys_enabled'        => '1',
				'passkeys_manage_page_id' => '12',
			]
		);
		$this->assertTrue( $out['passkeys_enabled'] );
		$this->assertSame( [], self::errors() );
	}

	/** @return array<string,array{0:\Closure,1:string,2:string}> */
	public static function unavailable_sites(): array {
		return [
			'S8c no OpenSSL'             => [
				static function (): void {
					Module::set_openssl_for_tests( false );
				},
				'magicauth_pk_no_openssl',
				'the PHP OpenSSL extension is missing.',
			],
			'S8a IP host'                => [
				static function (): void {
					global $magicauth_test_state;
					$magicauth_test_state['home'] = 'https://203.0.113.9';
				},
				'magicauth_pk_ip_host',
				'the site address is an IP address.',
			],
			'S8d plain http'             => [
				static function (): void {
					global $magicauth_test_state;
					$magicauth_test_state['home']   = 'http://academy.example.com';
					$magicauth_test_state['is_ssl'] = false;
				},
				'magicauth_pk_not_https',
				'the site is not served over HTTPS.',
			],
			'S8b site address differs'   => [
				static function (): void {
					global $magicauth_test_state;
					$magicauth_test_state['siteurl'] = 'https://wp.academy.example.com';
				},
				'magicauth_pk_origin_mismatch',
				'the home and site addresses differ (scheme, host or port).',
			],
			'S8g invalid RP ID'          => [
				static function (): void {
					global $magicauth_test_state;
					$magicauth_test_state['home'] = 'https://academy_site.example';
				},
				'magicauth_pk_rp_id_invalid',
				'MAGICAUTH_PASSKEY_RP_ID is not a valid suffix of the site host.',
			],
			'S8e subfolder'              => [
				static function (): void {
					global $magicauth_test_state;
					$magicauth_test_state['home'] = 'https://academy.example.com/blog';
				},
				'magicauth_pk_shared_host',
				'another WordPress site shares this address (subfolder install or subdirectory multisite).',
			],
			'S8f schema'                 => [
				static function (): void {
					update_option( 'magicauth_db_version', 1 );
				},
				'magicauth_pk_schema',
				'the database tables are missing. Reload this page to retry the upgrade.',
			],
			'S8a before S8d (E19 case)'  => [
				static function (): void {
					global $magicauth_test_state;
					$magicauth_test_state['home']   = 'http://127.0.0.1:9402';
					$magicauth_test_state['is_ssl'] = false;
					update_option( 'magicauth_db_version', 1 );
				},
				'magicauth_pk_ip_host',
				'the site address is an IP address.',
			],
			'S8c before everything else' => [
				static function (): void {
					global $magicauth_test_state;
					Module::set_openssl_for_tests( false );
					$magicauth_test_state['home']   = 'http://127.0.0.1/blog';
					$magicauth_test_state['is_ssl'] = false;
					update_option( 'magicauth_db_version', 0 );
				},
				'magicauth_pk_no_openssl',
				'the PHP OpenSSL extension is missing.',
			],
		];
	}

	/** @dataProvider unavailable_sites */
	public function test_enabling_is_refused_with_the_first_reason( \Closure $break, string $code, string $reason ): void {
		$break();
		$available = Module::available();
		$this->assertInstanceOf( \WP_Error::class, $available );
		$this->assertSame( $code, $available->get_error_code() );

		$out = self::save( [ 'passkeys_enabled' => '1' ] );

		$this->assertFalse( $out['passkeys_enabled'], 'stored off' );
		$this->assertSame( [ 'magicauth_passkeys_unavailable' ], self::error_codes(), 'one error, no S9 for a refused switch' );
		$this->assertSame(
			[
				'setting' => 'magicauth_settings',
				'code'    => 'magicauth_passkeys_unavailable',
				'message' => self::S8 . $reason,
				'type'    => 'error',
			],
			self::errors()[0]
		);
	}

	/** Turning it off never asks available(): a broken site can always switch the module off. */
	public function test_disabling_needs_no_availability(): void {
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => true ] );
		Module::set_openssl_for_tests( false );

		$out = self::save( [ 'passkeys_enabled' => '0' ] );

		$this->assertFalse( $out['passkeys_enabled'] );
		$this->assertSame( [], self::errors() );
	}

	/** @return array<string,array{0:array<string,mixed>,1:bool}> */
	public static function toggle_inputs(): array {
		return [
			'checkbox'          => [ [ 'passkeys_enabled' => '1' ], true ],
			'hidden zero'       => [ [ 'passkeys_enabled' => '0' ], false ],
			'absent'            => [ [], false ],
			'empty'             => [ [ 'passkeys_enabled' => '' ], false ],
		];
	}

	/**
	 * Hidden 0 plus checkbox, as the other toggles (Settings.php field_replace_default()).
	 *
	 * @dataProvider toggle_inputs
	 * @param array<string,mixed> $input
	 */
	public function test_toggle_input_shapes( array $input, bool $expected ): void {
		self::page( 12 );
		$out = self::save( $input + [ 'passkeys_manage_page_id' => '12' ] );
		$this->assertSame( $expected, $out['passkeys_enabled'] );

		$prompt = [];
		foreach ( $input as $value ) {
			$prompt['passkeys_prompt'] = $value;
		}
		$this->assertSame( $expected, self::save( $prompt )['passkeys_prompt'] );
	}

	/* ------------------------------------------------ management page, S9 */

	public function test_published_page_is_kept(): void {
		self::page( 12 );
		$out = self::save( [ 'passkeys_manage_page_id' => '12' ] );
		$this->assertSame( 12, $out['passkeys_manage_page_id'] );
		$this->assertSame( [], self::errors() );
	}

	/** @return array<string,array{0:mixed}> */
	public static function bad_pages(): array {
		return [
			'draft'   => [ 'draft' ],
			'private' => [ 'private' ],
			'post'    => [ 'post' ],
			'missing' => [ 'missing' ],
		];
	}

	/** @dataProvider bad_pages */
	public function test_anything_but_a_published_page_becomes_0_with_a_warning( string $kind ): void {
		if ( 'post' === $kind ) {
			self::page( 12, 'publish', 'post' );
		} elseif ( 'missing' !== $kind ) {
			self::page( 12, $kind );
		}
		$out = self::save( [ 'passkeys_manage_page_id' => '12' ] );

		$this->assertSame( 0, $out['passkeys_manage_page_id'] );
		$this->assertSame( [ 'magicauth_passkeys_page' ], self::error_codes() );
		$this->assertSame( 'warning', self::errors()[0]['type'] );
	}

	public function test_page_input_shapes(): void {
		foreach ( [ [ '0', 0 ], [ 'abc', 0 ], [ [ 12 ], 0 ], [ '', 0 ] ] as [ $input, $expected ] ) {
			$this->assertSame( $expected, self::save( [ 'passkeys_manage_page_id' => $input ] )['passkeys_manage_page_id'] );
		}
		$this->assertSame( [], self::errors(), 'choosing no page is not an error' );
	}

	public function test_s9_when_enabled_without_a_page(): void {
		$out = self::save(
			[
				'passkeys_enabled'        => '1',
				'passkeys_manage_page_id' => '0',
			]
		);

		$this->assertTrue( $out['passkeys_enabled'], 'kept: S9 is a warning, not a refusal' );
		$this->assertSame( 0, $out['passkeys_manage_page_id'] );
		$this->assertSame( [ 'magicauth_passkeys_no_page' ], self::error_codes() );
		$this->assertSame( self::S9, self::errors()[0]['message'] );
		$this->assertSame( 'warning', self::errors()[0]['type'] );
	}

	public function test_no_s9_when_a_page_is_kept_from_the_stored_settings(): void {
		self::page( 12 );
		update_option( 'magicauth_settings', [ 'passkeys_manage_page_id' => 12 ] );
		$this->assertSame( 12, self::save( [ 'passkeys_enabled' => '1' ] )['passkeys_manage_page_id'] );
		$this->assertSame( [], self::errors() );
	}

	public function test_no_s9_while_disabled(): void {
		self::save( [ 'passkeys_manage_page_id' => '0' ] );
		$this->assertSame( [], self::errors() );
	}

	public function test_invalid_page_while_enabling_gives_both_warnings(): void {
		self::page( 12, 'draft' );
		self::save(
			[
				'passkeys_enabled'        => '1',
				'passkeys_manage_page_id' => '12',
			]
		);
		$this->assertSame( [ 'magicauth_passkeys_page', 'magicauth_passkeys_no_page' ], self::error_codes() );
	}

	/* ----------------------------------------------------------- numbers */

	/** @return array<string,array{0:mixed,1:int}> */
	public static function reverify_days(): array {
		return [
			'zero'     => [ '0', 0 ],
			'one'      => [ '1', 1 ],
			'max'      => [ '730', 730 ],
			'over'     => [ '731', 730 ],
			'huge'     => [ '99999999', 730 ],
			'negative' => [ '-5', 5 ],
			'text'     => [ 'abc', 0 ],
			'array'    => [ [ 3 ], 0 ],
		];
	}

	/**
	 * @dataProvider reverify_days
	 * @param mixed $input
	 */
	public function test_email_reverify_days_clamped( $input, int $expected ): void {
		$this->assertSame( $expected, self::save( [ 'passkeys_email_reverify_days' => $input ] )['passkeys_email_reverify_days'] );
	}

	/** @return array<string,array{0:string,1:mixed,2:int}> */
	public static function throttle_values(): array {
		return [
			'window zero'  => [ 'per_ip_passkey_window_min', '0', 1 ],
			'window max'   => [ 'per_ip_passkey_window_min', '1440', 1440 ],
			'window over'  => [ 'per_ip_passkey_window_min', '5000', 1440 ],
			'max zero'     => [ 'per_ip_passkey_max', '0', 1 ],
			'max max'      => [ 'per_ip_passkey_max', '1000', 1000 ],
			'max over'     => [ 'per_ip_passkey_max', '1001', 1000 ],
			'max typical'  => [ 'per_ip_passkey_max', '30', 30 ],
		];
	}

	/**
	 * @dataProvider throttle_values
	 * @param mixed $input
	 */
	public function test_passkey_throttle_fields_clamped( string $key, $input, int $expected ): void {
		update_option(
			'magicauth_settings',
			[
				'throttle' => [
					'per_ip_max'                => 10,
					'per_ip_passkey_window_min' => 15,
					'per_ip_passkey_max'        => 30,
				],
			]
		);
		$out = self::save( [ 'throttle' => [ $key => $input ] ] );

		$this->assertSame( $expected, $out['throttle'][ $key ] );
		$this->assertSame( 10, $out['throttle']['per_ip_max'], 'other throttle keys kept' );
	}

	public function test_unsubmitted_values_keep_their_stored_value(): void {
		update_option(
			'magicauth_settings',
			[
				'passkeys_manage_page_id'      => 12,
				'passkeys_email_reverify_days' => 180,
			]
		);
		$out = self::save( [] );
		$this->assertSame( 12, $out['passkeys_manage_page_id'] );
		$this->assertSame( 180, $out['passkeys_email_reverify_days'] );
	}

	/* ------------------------------------------------------ fields, S6 */

	private static function capture( callable $render ): string {
		ob_start();
		$render();
		return (string) ob_get_clean();
	}

	public function test_toggle_fields_use_hidden_zero_and_checkbox(): void {
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => true ] );
		$html = self::capture( [ Settings::class, 'field_passkeys_enabled' ] );
		$this->assertStringContainsString( '<input type="hidden" name="magicauth_settings[passkeys_enabled]" value="0">', $html );
		$this->assertStringContainsString( 'name="magicauth_settings[passkeys_enabled]" value="1"  checked=\'checked\'', $html );
		$this->assertStringContainsString( 'Enable passkeys', $html );

		$html = self::capture( [ Settings::class, 'field_passkeys_prompt' ] );
		$this->assertStringContainsString( 'name="magicauth_settings[passkeys_prompt]" value="1"  checked=\'checked\'', $html, 'prompt defaults on' );
		$this->assertStringContainsString( 'Offer a passkey after email sign-in', $html );
	}

	public function test_page_select_and_days_fields(): void {
		self::page( 12 );
		self::page( 13, 'draft', 'page', 'Draft' );
		update_option( 'magicauth_settings', [ 'passkeys_manage_page_id' => 12 ] );

		$html = self::capture( [ Settings::class, 'field_passkeys_manage_page' ] );
		$this->assertStringContainsString( "name='magicauth_settings[passkeys_manage_page_id]'", $html );
		$this->assertStringContainsString( '<option value="0">Choose a page</option>', $html );
		$this->assertStringContainsString( 'value="12" selected=\'selected\'>Account</option>', $html );
		$this->assertStringNotContainsString( 'Draft', $html );

		$html = self::capture( [ Settings::class, 'field_passkeys_email_reverify_days' ] );
		$this->assertStringContainsString( 'name="magicauth_settings[passkeys_email_reverify_days]" value="0" min="0" max="730"', $html );
	}

	public function test_page_field_without_published_pages_submits_0(): void {
		self::page( 13, 'draft', 'page', 'Draft' );
		$html = self::capture( [ Settings::class, 'field_passkeys_manage_page' ] );
		$this->assertStringNotContainsString( '<select', $html );
		$this->assertStringContainsString( '<input type="hidden" name="magicauth_settings[passkeys_manage_page_id]" value="0">', $html );
		$this->assertStringContainsString( 'No published pages yet.', $html );
	}

	public function test_throttle_field_lists_the_two_passkey_rows(): void {
		$html = self::capture( [ Settings::class, 'field_throttle' ] );
		$this->assertStringContainsString( 'Per-IP passkey window (minutes)', $html );
		$this->assertStringContainsString( 'name="magicauth_settings[throttle][per_ip_passkey_window_min]" value="15" min="1" max="1440"', $html );
		$this->assertStringContainsString( 'Per-IP failed passkey sign-ins', $html );
		$this->assertStringContainsString( 'name="magicauth_settings[throttle][per_ip_passkey_max]" value="30" min="1" max="1000"', $html );
	}

	public function test_diagnostics_on_an_available_site(): void {
		$html = self::capture( [ Settings::class, 'render_passkeys_diagnostics' ] );

		foreach ( [ 'Relying party ID', 'Allowed origin', 'Ed25519 support', 'Passkeys stored', 'Database version' ] as $label ) {
			$this->assertStringContainsString( $label, $html );
		}
		$this->assertStringContainsString( '<code>academy.example.com</code>', $html );
		$this->assertStringContainsString( '<code>https://academy.example.com</code>', $html );
		$this->assertStringContainsString( '<code>' . ( in_array( -8, Module::supported_algs(), true ) ? 'Yes' : 'No' ) . '</code>', $html );
		$this->assertStringContainsString( '<code>0</code>', $html, 'passkeys stored' );
		$this->assertStringContainsString( '<code>2</code>', $html, 'database version' );
		$this->assertStringNotContainsString( 'MAGICAUTH_PASSKEY_RP_ID', $html, 'no S6b without the constant' );
		$this->assertStringNotContainsString( self::S9, $html );
		$this->assertStringNotContainsString( self::S8, $html );
	}

	public function test_diagnostics_count_stored_passkeys_and_survive_a_missing_table(): void {
		global $wpdb;
		Ceremony::enrol( new \MagicAuth\Tests\Support\SoftAuthenticator(), Ceremony::user( 30 ) );
		$this->assertStringContainsString( '<code>1</code>', self::capture( [ Settings::class, 'render_passkeys_diagnostics' ] ) );

		$wpdb->show_errors( true );
		$wpdb->fail_next_query( 'SELECT COUNT(*) FROM wp_magicauth_passkeys' );
		$html = self::capture( [ Settings::class, 'render_passkeys_diagnostics' ] );
		$wpdb->show_errors( false );
		$this->assertStringNotContainsString( 'WordPress database error', $html );
		$this->assertMatchesRegularExpression( '#Passkeys stored</span>\s*<p class="magicauth-row__help"><code>-</code>#', $html );
	}

	public function test_diagnostics_repeat_s9_while_enabled_without_a_page(): void {
		update_option( 'magicauth_settings', [ 'passkeys_enabled' => true ] );
		$this->assertStringContainsString( self::S9, self::capture( [ Settings::class, 'render_passkeys_diagnostics' ] ) );
	}

	public function test_diagnostics_show_the_s8_reason(): void {
		update_option( 'magicauth_db_version', 1 );
		$html = self::capture( [ Settings::class, 'render_passkeys_diagnostics' ] );
		$this->assertStringContainsString( self::S8 . 'the database tables are missing. Reload this page to retry the upgrade.', $html );
		$this->assertStringContainsString( '<code>1</code>', $html );
	}

	/**
	 * S6b: the RP ID set by the constant differs from the host.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_diagnostics_note_s6b_for_the_constant(): void {
		define( 'MAGICAUTH_PASSKEY_RP_ID', 'example.com' );
		Ceremony::site();
		$html = self::capture( [ Settings::class, 'render_passkeys_diagnostics' ] );
		$this->assertStringContainsString( '<code>example.com</code>', $html );
		$this->assertStringContainsString( 'Differs from the site host: set by MAGICAUTH_PASSKEY_RP_ID.', $html );
	}

	/** The section sits between Security and Diagnostics (4.7). */
	public function test_section_order_on_the_page(): void {
		$src      = (string) file_get_contents( MAGICAUTH_DIR . 'includes/Admin/Settings.php' );
		$security = strpos( $src, '<?php self::render_section_security(); ?>' );
		$passkeys = strpos( $src, '<?php self::render_section_passkeys(); ?>' );
		$diag     = strpos( $src, '<?php self::render_section_diagnostics(); ?>' );
		$this->assertIsInt( $security );
		$this->assertIsInt( $passkeys );
		$this->assertIsInt( $diag );
		$this->assertTrue( $security < $passkeys && $passkeys < $diag );

		$render = new \ReflectionMethod( Settings::class, 'render_section_passkeys' );
		if ( PHP_VERSION_ID < 80100 ) {
			$render->setAccessible( true );
		}
		$html = self::capture( static fn() => $render->invoke( null ) );
		$this->assertStringContainsString( '<h2>Passkeys</h2>', $html );
		$this->assertStringContainsString( 'Let people sign in with a passkey after they have signed in once with email. Email sign-in always stays available.', $html );
		$this->assertStringContainsString( 'data-magicauth-passkeys-diagnostics', $html );
	}
}
