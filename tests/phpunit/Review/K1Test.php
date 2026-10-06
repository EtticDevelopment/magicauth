<?php
/**
 * K1: the remove dialog's close event is queued as a task. When the dialog
 * is cancelled and reopened for a removal before that event runs (Esc then
 * Enter queued together), the late close handler clears the new pending
 * removal and Confirm does nothing. Runs the shipped account script in the
 * node harness of AccountScriptTest (which queues close like browsers do)
 * with one extra scenario injected into a temporary copy of the harness.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Review;

use MagicAuth\Tests\Passkeys\AccountScriptTest;
use PHPUnit\Framework\TestCase;

final class K1Test extends TestCase {

	private const HARNESS = __DIR__ . '/../Passkeys/js/account-script.js';

	private const SCENARIO = <<<'JS'
	async k1_late_close_keeps_a_reopened_removal() {
		const t = setup( { page: 'manage', responder: () => ( { status: 200, body: { success: true, data: { passkeys: [] } } } ) } );
		await flush();
		const dlg = t.q( '[data-magicauth-pk-remove-dialog]' );
		const btn = t.q( '[data-magicauth-pk-remove]' );
		assert.ok( dlg && btn, 'remove dialog and a Remove button rendered' );
		btn.click();
		assert.ok( dlg.open, 'opened' );
		dlg.querySelector( '[data-magicauth-pk-remove-cancel]' ).click(); // close event now queued
		btn.click(); // reopened before the queued close event runs
		assert.ok( dlg.open, 'reopened' );
		await flush(); // the late close event fires here
		assert.ok( dlg.open, 'dialog still open for the second removal' );
		const before = t.fetches.length;
		dlg.querySelector( '[data-magicauth-pk-remove-confirm]' ).click();
		await flush();
		assert.ok( t.fetches.length > before, 'Confirm on the reopened dialog sends the removal' );
	},

JS;

	protected function tearDown(): void {
		global $post;
		$post    = null;
		$_COOKIE = [];
		magicauth_test_reset_state();
	}

	public function test_late_close_event_does_not_clear_a_reopened_removal(): void {
		$node = trim( (string) shell_exec( 'command -v node 2>/dev/null' ) );
		if ( '' === $node ) {
			$this->markTestSkipped( 'node is not installed' );
		}
		$source = (string) file_get_contents( self::HARNESS );
		$this->assertSame( 1, substr_count( $source, "const scenarios = {\n" ) );
		$patched = str_replace( "const scenarios = {\n", "const scenarios = {\n" . self::SCENARIO, $source );

		$fixture = new \ReflectionMethod( AccountScriptTest::class, 'fixture' );
		if ( PHP_VERSION_ID < 80100 ) {
			$fixture->setAccessible( true ); // Needed on 8.0 only; deprecated in 8.5.
		}
		$data = $fixture->invoke( new AccountScriptTest( 'k1' ) );

		$base = (string) tempnam( sys_get_temp_dir(), 'magicauth-k1-' );
		$js   = $base . '.js';
		$json = $base . '.json';
		file_put_contents( $js, $patched );
		file_put_contents( $json, (string) wp_json_encode( $data ) );
		try {
			$cmd    = escapeshellarg( $node ) . ' ' . escapeshellarg( $js ) . ' ' . escapeshellarg( MAGICAUTH_DIR ) . ' k1_late_close_keeps_a_reopened_removal ' . escapeshellarg( $json ) . ' 2>&1';
			$output = (string) shell_exec( $cmd );
		} finally {
			@unlink( $js );
			@unlink( $json );
			@unlink( $base );
		}
		$this->assertSame( "ok\n", $output );
	}
}
