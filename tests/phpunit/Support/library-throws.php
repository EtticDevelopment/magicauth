<?php
/**
 * Makes the vendored library throw from inside processCreate() and
 * processGet(): the library calls defined() unqualified in its namespaces
 * (signature verification, Ed25519 self attestation), so PHP resolves a
 * namespaced defined() first. Throws $GLOBALS['magicauth_library_throw'] when
 * it holds a Throwable, else behaves as \defined(). Proves the wrapper's
 * catch ( \Throwable ) (W9) for exception classes the patched library no
 * longer raises on its own (TypeError, SodiumException). Load in a separate
 * process, before any library class. Test support only; never shipped.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\ThirdParty\Passkeys {

	/** @param string $name */
	function defined( $name ): bool {
		$throw = $GLOBALS['magicauth_library_throw'] ?? null;
		if ( $throw instanceof \Throwable ) {
			throw $throw;
		}
		return \defined( $name );
	}
}

namespace MagicAuth\ThirdParty\Passkeys\Attestation {

	/** @param string $name */
	function defined( $name ): bool {
		$throw = $GLOBALS['magicauth_library_throw'] ?? null;
		if ( $throw instanceof \Throwable ) {
			throw $throw;
		}
		return \defined( $name );
	}
}
