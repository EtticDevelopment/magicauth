<?php
/**
 * Review r1-crypto-01 (S8e): MAGICAUTH_PASSKEY_RP_ID widened to the parent domain
 * on a subdomain multisite makes every subsite share one rp.id while the user
 * handle meta is network-wide and the credential table is per site, the exact
 * collision S8e exists to refuse (SPEC 4.5 "Why S8e"). available() must refuse.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Passkeys\CredentialStore;
use MagicAuth\Passkeys\Module;
use MagicAuth\Passkeys\RelyingParty;
use PHPUnit\Framework\TestCase;
use WP_Error;

final class MultisiteRpIdTest extends TestCase {

	protected function setUp(): void {
		global $magicauth_test_state;
		magicauth_test_reset_state();
		$magicauth_test_state['home']   = 'https://academy.example.com';
		$magicauth_test_state['is_ssl'] = true;
		update_option( 'magicauth_db_version', 2 );
	}

	protected function tearDown(): void {
		magicauth_test_reset_state();
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_parent_domain_rp_id_on_subdomain_network_is_refused(): void {
		global $magicauth_test_state;
		define( 'MAGICAUTH_PASSKEY_RP_ID', 'example.com' );

		// Single site: the operator override stays allowed (SPEC 7.1).
		$this->assertTrue( Module::available(), 'single site with the constant' );

		// Subdomain network: example.com, academy.example.com, shop.example.com.
		$magicauth_test_state['multisite']         = true;
		$magicauth_test_state['subdomain_install'] = true;
		$magicauth_test_state['sites']             = [
			[
				'domain' => 'example.com',
				'path'   => '/',
			],
			[
				'domain' => 'academy.example.com',
				'path'   => '/',
			],
			[
				'domain' => 'shop.example.com',
				'path'   => '/',
			],
		];

		// Preconditions of the collision: one rp.id for every subsite, a
		// network-wide handle meta key and a per-site credential table.
		$this->assertSame( 'example.com', RelyingParty::id() );
		$this->assertNotSame( RelyingParty::host(), RelyingParty::id() );
		$this->assertSame( 'magicauth_passkey_user_handle', CredentialStore::HANDLE_META );

		$result = Module::available();
		$this->assertInstanceOf( WP_Error::class, $result, 'available() accepts a parent-domain RP ID shared by every subsite of the network' );
		$this->assertSame( 'magicauth_pk_shared_host', $result->get_error_code() );

		// A network with only this site still refuses: a later subsite gets the same rp.id.
		$magicauth_test_state['sites'] = [ $magicauth_test_state['sites'][1] ];
		$result                        = Module::available();
		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'magicauth_pk_shared_host', $result->get_error_code() );
	}

	/**
	 * The constant set to the site host itself widens nothing: a subdomain
	 * network stays available.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_constant_equal_to_the_host_on_a_network_is_available(): void {
		global $magicauth_test_state;
		define( 'MAGICAUTH_PASSKEY_RP_ID', 'academy.example.com' );

		$magicauth_test_state['multisite']         = true;
		$magicauth_test_state['subdomain_install'] = true;
		$magicauth_test_state['sites']             = [
			[
				'domain' => 'example.com',
				'path'   => '/',
			],
			[
				'domain' => 'academy.example.com',
				'path'   => '/',
			],
		];

		$this->assertSame( RelyingParty::host(), RelyingParty::id() );
		$this->assertTrue( Module::available() );
	}
}
