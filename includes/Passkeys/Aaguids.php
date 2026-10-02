<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Passkeys;

defined( 'ABSPATH' ) || exit;

/**
 * Offline AAGUID-to-provider-name map (SPEC 4.8). Names only, entered by hand:
 * the community list (passkeydeveloper/passkey-authenticator-aaguids) has no
 * licence, so nothing is copied from it. Each entry names its source. The
 * AAGUID is self-asserted under attestation none: a label, never a gate.
 * Provider names are product names and are not translated.
 */
final class Aaguids {

	/** All-zero AAGUID (iCloud Keychain and others): no name. */
	public const ZERO = '00000000-0000-0000-0000-000000000000';

	/**
	 * Fact: "this AAGUID is reported by this provider", read on 2026-10-01 from
	 * https://github.com/passkeydeveloper/passkey-authenticator-aaguids
	 * (aaguid.json) and entered by hand (SPEC 4.8 table).
	 */
	private const NAMES = [
		'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4' => 'Google Password Manager',
		'adce0002-35bc-c60a-648b-0b25f1f05503' => 'Chrome on Mac',
		'08987058-cadc-4b81-b6e1-30de50dcbe96' => 'Windows Hello',
		'9ddd1817-af5a-4672-a2b9-3e3dd95000a9' => 'Windows Hello',
		'6028b017-b1d4-4c02-b4b3-afcdafc96bb2' => 'Windows Hello',
		'd3452668-01fd-4c12-926c-83a4204853aa' => 'Microsoft Password Manager',
		'771b48fd-d3d4-4f74-9232-fc157ab0507a' => 'Edge on Mac',
		'dd4ec289-e01d-41c9-bb89-70fa845d4bf2' => 'iCloud Keychain (Managed)',
		'bada5566-a7aa-401f-bd96-45619a55120d' => '1Password',
		'd548826e-79b4-db40-a3d8-11116f7e8349' => 'Bitwarden',
		'b78a0a55-6ef8-d246-a042-ba0f6d55050c' => 'LastPass',
		'531126d6-e717-415c-9320-3d9aa6981239' => 'Dashlane',
		'50726f74-6f6e-5061-7373-50726f746f6e' => 'Proton Pass',
		'53414d53-554e-4700-0000-000000000000' => 'Samsung Pass',
	];

	/**
	 * Provider name, or null for an unknown or all-zero AAGUID.
	 *
	 * @param string $aaguid_uuid UUID text, any case.
	 */
	public static function name( string $aaguid_uuid ): ?string {
		return self::NAMES[ strtolower( $aaguid_uuid ) ] ?? null;
	}

	/**
	 * Lower-case UUID text of a 16-byte AAGUID; '' for any other length.
	 *
	 * @param string $raw AAGUID bytes from the attested credential data.
	 */
	public static function uuid( string $raw ): string {
		if ( 16 !== strlen( $raw ) ) {
			return '';
		}
		$hex = bin2hex( $raw );
		return substr( $hex, 0, 8 ) . '-' . substr( $hex, 8, 4 ) . '-' . substr( $hex, 12, 4 ) . '-'
			. substr( $hex, 16, 4 ) . '-' . substr( $hex, 20, 12 );
	}
}
