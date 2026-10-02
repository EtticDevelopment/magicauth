<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Passkeys;

defined( 'ABSPATH' ) || exit;

use WP_User;

/**
 * PublicKeyCredentialCreationOptionsJSON and RequestOptionsJSON built by
 * MagicAuth (SPEC 7.2, W8). The library's getCreateArgs()/getGetArgs() are
 * never used: they add a bogus extension, hard-code transports and reuse the
 * instance challenge.
 */
final class Options {

	/** Client timeout in milliseconds; challenge TTLs are at least this plus 60 s (5.2). */
	public const TIMEOUT_MS = 300000;

	/** displayName byte cap. */
	private const DISPLAY_NAME_BYTES = 128;

	/**
	 * Creation options (7.2): resident key and UV required, attestation none,
	 * no authenticatorAttachment, hints or attestationFormats.
	 *
	 * @param WP_User          $user          Signed-in user (never anyone else, D-2).
	 * @param string           $handle        base64url user handle, as stored in the register challenge row.
	 * @param string           $challenge_raw 32-byte challenge from ChallengeStore::issue().
	 * @param array<int,int>   $algs          Module::supported_algs(), as stored in the row.
	 * @param array<int,mixed> $exclude       The user's credential rows for the current RP ID, blocked included.
	 * @return array<string,mixed>
	 */
	public static function creation( WP_User $user, string $handle, string $challenge_raw, array $algs, array $exclude ): array {
		$rp_id  = RelyingParty::id();
		$params = [];
		foreach ( $algs as $alg ) {
			$params[] = [
				'type' => 'public-key',
				'alg'  => (int) $alg,
			];
		}

		return [
			'rp'                     => [
				'id'   => $rp_id,
				'name' => $rp_id,
			],
			'user'                   => [
				'id'          => $handle,
				'name'        => (string) $user->user_email,
				'displayName' => self::display_name( $user ),
			],
			'challenge'              => Base64Url::encode( $challenge_raw ),
			'pubKeyCredParams'       => $params,
			'timeout'                => self::TIMEOUT_MS,
			'excludeCredentials'     => self::descriptors( $exclude, true ),
			'authenticatorSelection' => [
				'residentKey'        => 'required',
				'requireResidentKey' => true,
				'userVerification'   => 'required',
			],
			'attestation'            => 'none',
			'extensions'             => [ 'credProps' => true ],
		];
	}

	/**
	 * Request options (7.2). $allow is [] at sign-in (usernameless, no
	 * enumeration) and the user's usable credentials for passkey step-up;
	 * blocked rows are never offered.
	 *
	 * @param string           $challenge_raw 32-byte challenge.
	 * @param array<int,mixed> $allow         Credential rows.
	 * @return array<string,mixed>
	 */
	public static function request( string $challenge_raw, array $allow = [] ): array {
		return [
			'challenge'        => Base64Url::encode( $challenge_raw ),
			'rpId'             => RelyingParty::id(),
			'allowCredentials' => self::descriptors( $allow, false ),
			'userVerification' => 'required',
			'timeout'          => self::TIMEOUT_MS,
		];
	}

	/**
	 * displayName: tags stripped, C0/C1 controls and bidi overrides removed,
	 * at most 128 bytes cut on a UTF-8 boundary; '' when empty or equal to the
	 * email address.
	 */
	public static function display_name( WP_User $user ): string {
		$name = wp_check_invalid_utf8( (string) $user->display_name );
		$name = wp_strip_all_tags( $name );
		$name = (string) preg_replace( '/[\x{0000}-\x{001F}\x{007F}-\x{009F}\x{202A}-\x{202E}\x{2066}-\x{2069}]/u', '', $name );
		$name = trim( $name );
		if ( strlen( $name ) > self::DISPLAY_NAME_BYTES ) {
			$len = self::DISPLAY_NAME_BYTES;
			// Back off to the lead byte of a character the cut would split (mb_strcut without ext-mbstring).
			while ( $len > 0 && 0x80 === ( ord( $name[ $len ] ) & 0xC0 ) ) {
				--$len;
			}
			$name = substr( $name, 0, $len );
		}
		if ( '' === $name || strtolower( $name ) === strtolower( (string) $user->user_email ) ) {
			return '';
		}
		return $name;
	}

	/**
	 * PublicKeyCredentialDescriptorJSON list; transports omitted when none
	 * were stored.
	 *
	 * @param array<int,mixed> $rows            Credential rows.
	 * @param bool             $include_blocked Keep rows with a counter anomaly (excludeCredentials).
	 * @return array<int,array<string,mixed>>
	 */
	private static function descriptors( array $rows, bool $include_blocked ): array {
		$out = [];
		foreach ( $rows as $row ) {
			if ( ! is_object( $row ) || ! isset( $row->credential_id ) || '' === (string) $row->credential_id ) {
				continue;
			}
			if ( ! $include_blocked && null !== ( $row->counter_anomaly_at ?? null ) ) {
				continue;
			}
			$item = [
				'type' => 'public-key',
				'id'   => (string) $row->credential_id,
			];
			$transports = '' !== (string) ( $row->transports ?? '' ) ? explode( ',', (string) $row->transports ) : [];
			if ( [] !== $transports ) {
				$item['transports'] = $transports;
			}
			$out[] = $item;
		}
		return $out;
	}
}
