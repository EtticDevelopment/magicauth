<?php
/**
 * @package MagicAuth
 */

declare( strict_types=1 );

namespace MagicAuth\Passkeys;

defined( 'ABSPATH' ) || exit;

/**
 * Credential row to list item (SPEC 6.5 Item), shared by the PHP render and
 * the JSON responses; passkey names (8.8) and default names (4.8).
 */
final class Presenter {

	/** Platform values of the register POST hint and M29 (4.8), never translated. */
	public const PLATFORMS = [ 'Windows', 'Mac', 'iPhone', 'iPad', 'Android', 'ChromeOS', 'Linux' ];

	/** Badge M13 for this long after creation. */
	private const NEW_FOR = 14 * DAY_IN_SECONDS;

	private const NAME_MAX = 64;

	/**
	 * Fixed User-Agent substrings, checked in this order (Android before
	 * Linux, iPad and iPhone before Mac). iPadOS Safari sends a desktop
	 * Macintosh UA; the client hint covers it.
	 */
	private const UA_PLATFORMS = [
		'iPad'      => 'iPad',
		'iPhone'    => 'iPhone',
		'Android'   => 'Android',
		'CrOS'      => 'ChromeOS',
		'Windows'   => 'Windows',
		'Macintosh' => 'Mac',
		'Mac OS X'  => 'Mac',
		'Linux'     => 'Linux',
	];

	/**
	 * Item for one credential row. credential_id only for the owner (signals);
	 * admin responses omit it.
	 *
	 * @param object $row   Credential row.
	 * @param bool   $owner Response goes to the credential's owner.
	 * @return array<string,mixed>
	 */
	public static function item( object $row, bool $owner = false ): array {
		$created   = self::timestamp( $row->created_at ?? null );
		$last_used = self::timestamp( $row->last_used_at ?? null );
		$be        = ! empty( $row->backup_eligible );
		$bs        = ! empty( $row->backup_state );
		$hash      = (string) ( $row->credential_hash ?? '' );

		$item = [
			'id'              => (int) ( $row->id ?? 0 ),
			'name'            => (string) ( $row->name ?? '' ),
			/* translators: %s: last 4 characters of the passkey's identifier, for example 9F3A. */
			'label'           => sprintf( __( 'Passkey ending in %s', 'magicauth' ), strtoupper( substr( $hash, -4 ) ) ),
			'provider'        => Aaguids::name( (string) ( $row->aaguid ?? '' ) ),
			'synced'          => $bs,
			'sync_possible'   => $be,
			'device_bound'    => ! $be,
			'created'         => null !== $created ? gmdate( 'Y-m-d\TH:i:s\Z', $created ) : '',
			/* translators: %s: date the passkey was added. */
			'created_label'   => null !== $created ? sprintf( __( 'Added on %s', 'magicauth' ), self::date( $created ) ) : '',
			'last_used'       => null !== $last_used ? gmdate( 'Y-m-d\TH:i:s\Z', $last_used ) : null,
			/* translators: %s: date the passkey was last used to sign in. */
			'last_used_label' => null !== $last_used ? sprintf( __( 'Last used on %s', 'magicauth' ), self::date( $last_used ) ) : null,
			'usable_here'     => '' !== RelyingParty::id() && (string) ( $row->rp_id ?? '' ) === RelyingParty::id(),
			'blocked'         => null !== ( $row->counter_anomaly_at ?? null ),
			'is_new'          => null !== $created && Clock::now() - $created < self::NEW_FOR,
		];
		if ( $owner ) {
			$item['credential_id'] = (string) ( $row->credential_id ?? '' );
		}
		return $item;
	}

	/**
	 * Passkey name (8.8): valid UTF-8, sanitize_text_field(), no C0/C1
	 * controls or bidi marks and overrides, no characters above U+FFFF unless
	 * the database charset is utf8mb4, at most 64 characters, trimmed.
	 *
	 * @param string $raw Name as typed (unslashed).
	 */
	public static function sanitize_name( string $raw ): string {
		global $wpdb;

		$name = wp_check_invalid_utf8( $raw );
		$name = sanitize_text_field( $name );
		$name = (string) preg_replace( '/[\x{0000}-\x{001F}\x{007F}-\x{009F}\x{200E}\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}]/u', '', $name );
		if ( ! isset( $wpdb->charset ) || 'utf8mb4' !== $wpdb->charset ) {
			$name = (string) preg_replace( '/[\x{10000}-\x{10FFFF}]/u', '', $name );
		}
		$name = mb_substr( $name, 0, self::NAME_MAX, 'UTF-8' );
		return trim( $name );
	}

	/**
	 * Case-insensitive key for comparing passkey names. ext-mbstring is
	 * optional in WordPress (compat.php has no mb_strtolower), so without it
	 * only ASCII letters fold (locale-independent); every name comparison uses
	 * this one key.
	 *
	 * @param string $name Passkey name.
	 */
	public static function name_key( string $name ): string {
		if ( function_exists( 'mb_strtolower' ) ) {
			return mb_strtolower( $name, 'UTF-8' );
		}
		return strtr( $name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz' );
	}

	/**
	 * Default name at registration (4.8): the provider name when the AAGUID is
	 * known; else "Passkey on <platform>" from the client hint (one of
	 * PLATFORMS exactly) or the User-Agent; else "Passkey". De-duplicated
	 * against $existing with " (2)", " (3)" and so on (case-insensitive).
	 * Hint and UA label the passkey only; they gate nothing and are not stored.
	 *
	 * @param string            $aaguid     Lower-case UUID text.
	 * @param string            $platform   Client hint, ignored unless one of PLATFORMS.
	 * @param string            $user_agent HTTP_USER_AGENT.
	 * @param array<int,string> $existing   The user's passkey names.
	 */
	public static function default_name( string $aaguid, string $platform, string $user_agent, array $existing ): string {
		$base = Aaguids::name( $aaguid );
		if ( null === $base ) {
			$found = self::platform( $platform, $user_agent );
			/* translators: %s: platform name, not translated (Windows, Mac, iPhone, iPad, Android, ChromeOS, Linux). */
			$base = null !== $found ? sprintf( __( 'Passkey on %s', 'magicauth' ), $found ) : __( 'Passkey', 'magicauth' );
		}
		$base = self::sanitize_name( $base );

		$taken = [];
		foreach ( $existing as $name ) {
			$taken[ self::name_key( (string) $name ) ] = true;
		}
		$name = $base;
		$n    = 2;
		while ( isset( $taken[ self::name_key( $name ) ] ) ) {
			$suffix = ' (' . $n . ')';
			$name   = mb_substr( $base, 0, self::NAME_MAX - mb_strlen( $suffix, 'UTF-8' ), 'UTF-8' ) . $suffix;
			++$n;
		}
		return $name;
	}

	/**
	 * Platform label from the hint, else the User-Agent, else null.
	 *
	 * @param string $hint       Client hint.
	 * @param string $user_agent HTTP_USER_AGENT.
	 */
	private static function platform( string $hint, string $user_agent ): ?string {
		if ( in_array( $hint, self::PLATFORMS, true ) ) {
			return $hint;
		}
		foreach ( self::UA_PLATFORMS as $needle => $label ) {
			if ( false !== strpos( $user_agent, $needle ) ) {
				return $label;
			}
		}
		return null;
	}

	/**
	 * Unix time of a UTC datetime column, or null.
	 *
	 * @param mixed $value Column value.
	 */
	private static function timestamp( $value ): ?int {
		if ( ! is_string( $value ) || 1 !== preg_match( '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $value ) ) {
			return null;
		}
		$time = strtotime( $value . ' UTC' );
		return false === $time ? null : $time;
	}

	private static function date( int $timestamp ): string {
		$format = get_option( 'date_format' );
		return (string) wp_date( is_string( $format ) && '' !== $format ? $format : 'Y-m-d', $timestamp );
	}
}
