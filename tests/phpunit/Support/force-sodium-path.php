<?php
/**
 * Forces the vendored library onto its sodium Ed25519 branch on PHP 8.4+,
 * where OpenSSL has Ed25519 and the library would take the OpenSSL branch.
 * The library calls defined() unqualified inside its namespaces, so PHP
 * resolves a namespaced defined() first. Load in a separate process, before
 * any library class. Test support only; never shipped.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\ThirdParty\Passkeys {

	/** @param string $name */
	function defined( $name ): bool {
		return 'OPENSSL_KEYTYPE_ED25519' === $name ? false : \defined( $name );
	}
}

namespace MagicAuth\ThirdParty\Passkeys\Attestation {

	/** @param string $name */
	function defined( $name ): bool {
		return 'OPENSSL_KEYTYPE_ED25519' === $name ? false : \defined( $name );
	}
}
