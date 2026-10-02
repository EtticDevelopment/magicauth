<?php
/**
 * E26 helper: reads a JSON object { name: html } on stdin and prints { name: normalised }
 * using the golden-fixture normaliser of build step 1 (tests/phpunit/Support/Normalise.php).
 * Test-only; never shipped.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

require dirname( __DIR__, 2 ) . '/phpunit/Support/Normalise.php';

$magicauth_e2e_in  = json_decode( (string) stream_get_contents( STDIN ), true );
$magicauth_e2e_out = [];
foreach ( is_array( $magicauth_e2e_in ) ? $magicauth_e2e_in : [] as $magicauth_e2e_name => $magicauth_e2e_html ) {
	$magicauth_e2e_out[ $magicauth_e2e_name ] = \MagicAuth\Tests\Support\Normalise::html( (string) $magicauth_e2e_html );
}
echo json_encode( $magicauth_e2e_out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode
