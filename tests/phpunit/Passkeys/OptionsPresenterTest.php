<?php
/**
 * Passkeys\Options (SPEC 7.2, W8), Presenter (6.5 Item, 8.8, 4.8) and Aaguids
 * (4.8): the JSON MagicAuth builds instead of the library, the list item, and
 * names.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Passkeys\Aaguids;
use MagicAuth\Passkeys\Base64Url;
use MagicAuth\Passkeys\ChallengeStore;
use MagicAuth\Passkeys\Clock;
use MagicAuth\Passkeys\CredentialStore;
use MagicAuth\Passkeys\Module;
use MagicAuth\Passkeys\Options;
use MagicAuth\Passkeys\Presenter;
use MagicAuth\Tests\Support\Ceremony;
use MagicAuth\Tests\Support\SoftAuthenticator;
use PHPUnit\Framework\TestCase;

final class OptionsPresenterTest extends TestCase {

	protected function setUp(): void {
		Ceremony::site();
	}

	protected function tearDown(): void {
		magicauth_test_reset_state();
	}

	/* ------------------------------------------------------------------ Options::creation() */

	public function test_creation_options(): void {
		$user      = Ceremony::user( 7 );
		$handle    = Base64Url::encode( random_bytes( 64 ) );
		$challenge = random_bytes( 32 );
		$options   = Options::creation( $user, $handle, $challenge, [ -7, -8, -257 ], [] );

		$this->assertSame(
			[
				'rp'                     => [
					'id'   => Ceremony::RP,
					'name' => Ceremony::RP,
				],
				'user'                   => [
					'id'          => $handle,
					'name'        => 'learner7@example.test',
					'displayName' => 'Learner 7',
				],
				'challenge'              => Base64Url::encode( $challenge ),
				'pubKeyCredParams'       => [
					[
						'type' => 'public-key',
						'alg'  => -7,
					],
					[
						'type' => 'public-key',
						'alg'  => -8,
					],
					[
						'type' => 'public-key',
						'alg'  => -257,
					],
				],
				'timeout'                => 300000,
				'excludeCredentials'     => [],
				'authenticatorSelection' => [
					'residentKey'        => 'required',
					'requireResidentKey' => true,
					'userVerification'   => 'required',
				],
				'attestation'            => 'none',
				'extensions'             => [ 'credProps' => true ],
			],
			$options
		);
		$json = (string) wp_json_encode( $options );
		$this->assertStringContainsString( '"excludeCredentials":[]', $json );
		$this->assertStringContainsString( '"extensions":{"credProps":true}', $json );
		foreach ( [ 'authenticatorAttachment', 'hints', 'attestationFormats', 'exts' ] as $absent ) {
			$this->assertStringNotContainsString( $absent, $json );
		}
	}

	public function test_pub_key_cred_params_follow_the_algs(): void {
		$options = Options::creation( Ceremony::user( 7 ), 'aGFuZGxl', random_bytes( 32 ), Module::supported_algs(), [] );
		$this->assertSame( Module::supported_algs(), array_column( $options['pubKeyCredParams'], 'alg' ) );
		$options = Options::creation( Ceremony::user( 7 ), 'aGFuZGxl', random_bytes( 32 ), [ -7, -257 ], [] );
		$this->assertSame( [ -7, -257 ], array_column( $options['pubKeyCredParams'], 'alg' ) );
	}

	/** @return array<string,array{string,string}> */
	public static function display_names(): array {
		return [
			'plain'              => [ 'Anna de Vries', 'Anna de Vries' ],
			'markup'             => [ '<b>Anna</b><script>x()</script>', 'Anna' ],
			'bidi override'      => [ "Anna\u{202E}seirV", 'AnnaseirV' ],
			'isolates'           => [ "\u{2066}Anna\u{2069}", 'Anna' ],
			'C0 and C1 controls' => [ "An\x00na\x1b\u{0085}", 'Anna' ],
			'equal to the email' => [ 'Learner7@Example.test', '' ],
			'empty'              => [ '', '' ],
			'invalid UTF-8'      => [ "Anna\xff", '' ],
			'129 bytes ASCII'    => [ str_repeat( 'a', 129 ), str_repeat( 'a', 128 ) ],
			'cut on a boundary'  => [ str_repeat( 'a', 127 ) . 'é', str_repeat( 'a', 127 ) ],
		];
	}

	/** @dataProvider display_names */
	public function test_display_name( string $raw, string $expected ): void {
		$user               = Ceremony::user( 7 );
		$user->display_name = $raw;
		$this->assertSame( $expected, Options::display_name( $user ) );
		$this->assertLessThanOrEqual( 128, strlen( Options::display_name( $user ) ) );
		$this->assertTrue( mb_check_encoding( Options::display_name( $user ), 'UTF-8' ) );
	}

	/** excludeCredentials: every credential for this RP ID, blocked included; transports omitted when none. */
	public function test_exclude_credentials(): void {
		global $wpdb;
		$user = Ceremony::user( 7 );
		$a    = new SoftAuthenticator( 'ES256', [ 'transports' => [ 'internal', 'hybrid' ] ] );
		$b    = new SoftAuthenticator( 'ES256', [ 'transports' => [] ] );
		$c    = new SoftAuthenticator( 'ES256' );
		Ceremony::enrol( $a, $user );
		Ceremony::enrol( $b, $user );
		$blocked = Ceremony::enrol( $c, $user );
		$wpdb->query( $wpdb->prepare( 'UPDATE ' . CredentialStore::table() . ' SET counter_anomaly_at = %s WHERE id = %d', '2026-09-01 00:00:00', $blocked ) );

		$issued = Ceremony::register_options( $user );
		$this->assertSame(
			[
				[
					'type'       => 'public-key',
					'id'         => Base64Url::encode( $a->credentialId() ),
					'transports' => [ 'internal', 'hybrid' ],
				],
				[
					'type' => 'public-key',
					'id'   => Base64Url::encode( $b->credentialId() ),
				],
				[
					'type'       => 'public-key',
					'id'         => Base64Url::encode( $c->credentialId() ),
					'transports' => [ 'internal', 'hybrid' ],
				],
			],
			$issued['options']['excludeCredentials']
		);
	}

	/* ------------------------------------------------------------------ Options::request() */

	public function test_request_options(): void {
		$challenge = random_bytes( 32 );
		$this->assertSame(
			[
				'challenge'        => Base64Url::encode( $challenge ),
				'rpId'             => Ceremony::RP,
				'allowCredentials' => [],
				'userVerification' => 'required',
				'timeout'          => 300000,
			],
			Options::request( $challenge )
		);
	}

	public function test_request_allow_list_skips_blocked_credentials(): void {
		$rows = [
			(object) [
				'credential_id'      => 'AAAAAAAAAAAAAAAAAAAAAA',
				'transports'         => 'usb',
				'counter_anomaly_at' => null,
			],
			(object) [
				'credential_id'      => 'BBBBBBBBBBBBBBBBBBBBBA',
				'transports'         => '',
				'counter_anomaly_at' => '2026-09-01 00:00:00',
			],
			(object) [
				'credential_id'      => 'CCCCCCCCCCCCCCCCCCCCCA',
				'transports'         => '',
				'counter_anomaly_at' => null,
			],
			'not a row',
		];
		$this->assertSame(
			[
				[
					'type'       => 'public-key',
					'id'         => 'AAAAAAAAAAAAAAAAAAAAAA',
					'transports' => [ 'usb' ],
				],
				[
					'type' => 'public-key',
					'id'   => 'CCCCCCCCCCCCCCCCCCCCCA',
				],
			],
			Options::request( random_bytes( 32 ), $rows )['allowCredentials']
		);
	}

	/** Invariant 9: every browser ceremony's challenge TTL is at least its timeout plus 60 s. */
	public function test_ttl_covers_the_timeout(): void {
		foreach ( [ 'signin', 'register', 'reauth' ] as $ceremony ) {
			$this->assertGreaterThanOrEqual( Options::TIMEOUT_MS / 1000 + 60, ChallengeStore::TTL[ $ceremony ], $ceremony );
		}
	}

	/* ------------------------------------------------------------------ Presenter::item() */

	public function test_item(): void {
		Clock::set_for_tests( (int) strtotime( '2026-09-21 12:00:00 UTC' ) );
		update_option( 'date_format', 'j F Y' );
		$row = (object) [
			'id'                 => '12',
			'name'               => 'Work laptop',
			'credential_hash'    => str_repeat( '0', 60 ) . '9f3a',
			'credential_id'      => 'Y3JlZGVudGlhbA',
			'rp_id'              => Ceremony::RP,
			'aaguid'             => 'EA9B8D66-4D01-1D21-3CE4-B6B48CB575D4',
			'backup_eligible'    => '1',
			'backup_state'       => '1',
			'created_at'         => '2026-09-10 08:30:00',
			'last_used_at'       => '2026-09-20 22:15:00',
			'counter_anomaly_at' => null,
		];

		$item = Presenter::item( $row, true );
		$this->assertSame(
			[
				'id'              => 12,
				'name'            => 'Work laptop',
				'label'           => 'Passkey ending in 9F3A',
				'provider'        => 'Google Password Manager',
				'synced'          => true,
				'sync_possible'   => true,
				'device_bound'    => false,
				'created'         => '2026-09-10T08:30:00Z',
				'created_label'   => 'Added on ' . wp_date( 'j F Y', (int) strtotime( '2026-09-10 08:30:00 UTC' ) ),
				'last_used'       => '2026-09-20T22:15:00Z',
				'last_used_label' => 'Last used on ' . wp_date( 'j F Y', (int) strtotime( '2026-09-20 22:15:00 UTC' ) ),
				'usable_here'     => true,
				'blocked'         => false,
				'is_new'          => true,
				'credential_id'   => 'Y3JlZGVudGlhbA',
			],
			$item
		);
		$this->assertArrayNotHasKey( 'credential_id', Presenter::item( $row ), 'admin responses omit it' );
	}

	public function test_item_states(): void {
		Clock::set_for_tests( (int) strtotime( '2026-09-24 08:30:00 UTC' ) );
		$row = (object) [
			'id'                 => 3,
			'name'               => 'Key',
			'credential_hash'    => str_repeat( 'a', 64 ),
			'rp_id'              => 'old.example.com',
			'aaguid'             => Aaguids::ZERO,
			'backup_eligible'    => '0',
			'backup_state'       => '0',
			'created_at'         => '2026-09-10 08:30:00',
			'last_used_at'       => null,
			'counter_anomaly_at' => '2026-09-11 00:00:00',
		];
		$item = Presenter::item( $row );
		$this->assertNull( $item['provider'] );
		$this->assertFalse( $item['synced'] );
		$this->assertFalse( $item['sync_possible'] );
		$this->assertTrue( $item['device_bound'] );
		$this->assertNull( $item['last_used'] );
		$this->assertNull( $item['last_used_label'] );
		$this->assertFalse( $item['usable_here'], 'other RP ID (M11)' );
		$this->assertTrue( $item['blocked'] );
		$this->assertFalse( $item['is_new'], 'exactly 14 days old' );

		Clock::set_for_tests( (int) strtotime( '2026-09-24 08:29:59 UTC' ) );
		$this->assertTrue( Presenter::item( $row )['is_new'] );
	}

	/* ------------------------------------------------------------------ names */

	/** @return array<string,array{string,string}> */
	public static function names(): array {
		return [
			'plain'          => [ 'Phone', 'Phone' ],
			'tags'           => [ '<b>Phone</b>', 'Phone' ],
			'lone <'         => [ 'a < b', 'a &lt; b' ],
			'line breaks'    => [ "Work\nlaptop\t2", 'Work laptop 2' ],
			'bidi'           => [ "\u{202E}enohp", 'enohp' ],
			'LRM and RLM'    => [ "a\u{200E}b\u{200F}c", 'abc' ],
			'C1'             => [ "a\u{0080}b\u{009F}c", 'abc' ],
			'64 characters'  => [ str_repeat( 'é', 70 ), str_repeat( 'é', 64 ) ],
			'invalid UTF-8'  => [ "Phone\xc3\x28", '' ],
			'only spaces'    => [ '     ', '' ],
			'emoji, utf8mb4' => [ "\u{1F511} Key", "\u{1F511} Key" ],
			'percent codes'  => [ 'Key%20one', 'Keyone' ],
		];
	}

	/** @dataProvider names */
	public function test_sanitize_name( string $raw, string $expected ): void {
		$this->assertSame( $expected, Presenter::sanitize_name( $raw ) );
	}

	public function test_sanitize_name_without_utf8mb4(): void {
		global $wpdb;
		$wpdb->charset = 'utf8';
		try {
			$this->assertSame( 'Key', Presenter::sanitize_name( "\u{1F511} Key" ) );
			$this->assertSame( 'Clé', Presenter::sanitize_name( 'Clé' ), 'BMP characters stay' );
		} finally {
			$wpdb->charset = 'utf8mb4';
		}
	}

	public function test_default_name(): void {
		$this->assertSame( 'Passkey', Presenter::default_name( Aaguids::ZERO, '', '', [] ) );
		$this->assertSame( 'Passkey on Android', Presenter::default_name( Aaguids::ZERO, '', 'Mozilla/5.0 (Linux; Android 15; Pixel 9)', [] ) );
		$this->assertSame( 'Passkey on Linux', Presenter::default_name( Aaguids::ZERO, '', 'Mozilla/5.0 (X11; Linux x86_64)', [] ) );
		$this->assertSame( 'Passkey on ChromeOS', Presenter::default_name( Aaguids::ZERO, '', 'Mozilla/5.0 (X11; CrOS x86_64 14541.0.0)', [] ) );
		$this->assertSame( 'Passkey on iPhone', Presenter::default_name( Aaguids::ZERO, '', 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)', [] ) );
		$this->assertSame( 'Passkey on Mac', Presenter::default_name( Aaguids::ZERO, '', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', [] ) );
		foreach ( Presenter::PLATFORMS as $platform ) {
			$this->assertSame( "Passkey on {$platform}", Presenter::default_name( Aaguids::ZERO, $platform, 'Mozilla/5.0 (Windows NT 10.0)', [] ) );
		}
		$this->assertSame( 'Windows Hello', Presenter::default_name( '08987058-cadc-4b81-b6e1-30de50dcbe96', 'Mac', '', [] ), 'provider wins' );
	}

	public function test_default_name_is_de_duplicated(): void {
		$this->assertSame( 'Passkey (2)', Presenter::default_name( Aaguids::ZERO, '', '', [ 'passkey' ] ) );
		$this->assertSame( 'Passkey (4)', Presenter::default_name( Aaguids::ZERO, '', '', [ 'Passkey', 'Passkey (2)', 'PASSKEY (3)' ] ) );
		$this->assertSame( 'Passkey', Presenter::default_name( Aaguids::ZERO, '', '', [ 'Passkey (2)' ] ) );
	}

	/* ------------------------------------------------------------------ Aaguids */

	public function test_aaguid_names(): void {
		$this->assertSame( 'Google Password Manager', Aaguids::name( 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4' ) );
		$this->assertSame( 'Samsung Pass', Aaguids::name( '53414D53-554E-4700-0000-000000000000' ) );
		$this->assertSame( 'Windows Hello', Aaguids::name( '6028b017-b1d4-4c02-b4b3-afcdafc96bb2' ) );
		$this->assertNull( Aaguids::name( Aaguids::ZERO ) );
		$this->assertNull( Aaguids::name( 'not-a-uuid' ) );
		$this->assertNull( Aaguids::name( '' ) );
	}

	public function test_aaguid_uuid(): void {
		$this->assertSame( 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4', Aaguids::uuid( (string) hex2bin( 'EA9B8D664D011D213CE4B6B48CB575D4' ) ) );
		$this->assertSame( Aaguids::ZERO, Aaguids::uuid( str_repeat( "\0", 16 ) ) );
		$this->assertSame( '', Aaguids::uuid( str_repeat( "\0", 15 ) ) );
	}

	/** D-23: no copied list; every entry carries the hand-entry source comment. */
	public function test_aaguid_file_is_hand_entered(): void {
		$source = (string) file_get_contents( MAGICAUTH_DIR . 'includes/Passkeys/Aaguids.php' );
		$this->assertStringContainsString( 'passkeydeveloper/passkey-authenticator-aaguids', $source );
		$this->assertStringContainsString( 'entered by hand', $source );
		$this->assertStringNotContainsString( 'icon_dark', $source );
		$this->assertStringNotContainsString( 'data:image', $source );
	}
}
