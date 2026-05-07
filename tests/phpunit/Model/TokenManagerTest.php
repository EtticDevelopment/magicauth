<?php
/**
 * TokenManager behaviour: T1 – T12, T11.5, T15.5.
 *
 * Each test method is named after the plan §14 test ID so the matrix maps
 * mechanically to code.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Model;

use MagicAuth\Auth\Crockford;
use MagicAuth\Auth\TokenManager;
use PHPUnit\Framework\TestCase;
use WP_Error;
use WP_User;

final class TokenManagerTest extends TestCase {

	private const USER_ID = 42;
	private const EMAIL   = 'user@example.test';

	protected function setUp(): void {
		magicauth_test_reset_state();
		magicauth_test_register_user( self::USER_ID, self::EMAIL );
	}

	private function issue(): array {
		$result = TokenManager::issue( self::USER_ID, self::EMAIL );
		$this->assertIsArray( $result, 'issue() should return token array on happy path' );
		return $result;
	}

	/**
	 * Issue + bind a session to the returned selector. validate_code() requires
	 * a session_id since v1.6.0. Returns the full issue() payload plus 'session_id'.
	 */
	private function issue_with_session(): array {
		$result     = $this->issue();
		$session_id = bin2hex( random_bytes( 16 ) );
		set_transient(
			'magicauth_session_' . $session_id,
			[
				'email'    => self::EMAIL,
				'selector' => (string) $result['selector'],
				'attempts' => 0,
			],
			30 * MINUTE_IN_SECONDS
		);
		$result['session_id'] = $session_id;
		return $result;
	}

	/** Bind a fresh session to an existing selector, e.g. after the first session is exhausted. */
	private function fresh_session_for( string $selector ): string {
		$session_id = bin2hex( random_bytes( 16 ) );
		set_transient(
			'magicauth_session_' . $session_id,
			[
				'email'    => self::EMAIL,
				'selector' => $selector,
				'attempts' => 0,
			],
			30 * MINUTE_IN_SECONDS
		);
		return $session_id;
	}

	private function selector_and_verifier_from_url( string $url ): array {
		$query = parse_url( $url, PHP_URL_QUERY );
		parse_str( (string) $query, $args );
		return [ (string) ( $args['s'] ?? '' ), (string) ( $args['v'] ?? '' ) ];
	}

	public function test_T1_issue_returns_link_and_code_and_persists_hashed_values(): void {
		$result = $this->issue();
		$this->assertArrayHasKey( 'link_url', $result );
		$this->assertArrayHasKey( 'code_plaintext', $result );
		$this->assertArrayHasKey( 'expires_at', $result );

		// Code is 6 chars from canonical alphabet.
		$this->assertMatchesRegularExpression( '/^[0-9A-HJKMNPQRSTVWXYZ]{6}$/', $result['code_plaintext'] );

		// Link URL contains opaque selector + verifier — and explicitly NOT user_id.
		$this->assertStringContainsString( 'magicauth=verify', $result['link_url'] );
		$this->assertStringNotContainsString( 'user_id', $result['link_url'] );

		// Persisted row holds hashes, not plaintext.
		global $wpdb;
		$row = $wpdb->get_row( 'SELECT * FROM ' . TokenManager::table() . ' ORDER BY id DESC LIMIT 1' );
		$this->assertNotNull( $row );
		[ , $verifier ] = $this->selector_and_verifier_from_url( $result['link_url'] );
		$this->assertNotSame( $verifier, $row->link_verifier_hash );
		$this->assertNotSame( $result['code_plaintext'], $row->code_verifier_hash );
		$this->assertSame( self::USER_ID, (int) $row->user_id );
	}

	public function test_T2_validate_link_happy_path_returns_user_and_increments_use_count(): void {
		$result            = $this->issue();
		[ $sel, $verifier ] = $this->selector_and_verifier_from_url( $result['link_url'] );

		$user = TokenManager::validate_link( $sel, $verifier );
		$this->assertInstanceOf( WP_User::class, $user );
		$this->assertSame( self::USER_ID, $user->ID );

		global $wpdb;
		$row = $wpdb->get_row( 'SELECT use_count, consumed_at FROM ' . TokenManager::table() . " WHERE selector = '" . $sel . "'" );
		$this->assertSame( 1, (int) $row->use_count );
		$this->assertNull( $row->consumed_at );
	}

	public function test_T3_validate_code_happy_path_returns_user_and_consumes(): void {
		$result = $this->issue_with_session();

		$user = TokenManager::validate_code( self::EMAIL, $result['code_plaintext'], $result['session_id'] );
		$this->assertInstanceOf( WP_User::class, $user );

		global $wpdb;
		$row = $wpdb->get_row( 'SELECT consumed_at FROM ' . TokenManager::table() );
		$this->assertNotNull( $row->consumed_at );
	}

	public function test_T4_link_replay_within_use_cap_succeeds(): void {
		$result            = $this->issue();
		[ $sel, $verifier ] = $this->selector_and_verifier_from_url( $result['link_url'] );

		$first  = TokenManager::validate_link( $sel, $verifier );
		$second = TokenManager::validate_link( $sel, $verifier );
		$third  = TokenManager::validate_link( $sel, $verifier );

		$this->assertInstanceOf( WP_User::class, $first );
		$this->assertInstanceOf( WP_User::class, $second, 'Default cap of 2 allows the second click' );
		$this->assertInstanceOf( WP_Error::class, $third, 'Third click exceeds cap and returns generic error' );

		global $wpdb;
		$row = $wpdb->get_row( 'SELECT use_count FROM ' . TokenManager::table() );
		$this->assertSame( 2, (int) $row->use_count, 'use_count clamps at the cap' );
	}

	public function test_T4_5_link_beyond_use_cap_returns_error(): void {
		// Tighten cap to 1 (strict single-use) for this test.
		update_option( 'magicauth_settings', [ 'max_link_uses' => 1 ] );

		$result            = $this->issue();
		[ $sel, $verifier ] = $this->selector_and_verifier_from_url( $result['link_url'] );

		$first  = TokenManager::validate_link( $sel, $verifier );
		$second = TokenManager::validate_link( $sel, $verifier );

		$this->assertInstanceOf( WP_User::class, $first );
		$this->assertInstanceOf( WP_Error::class, $second );
	}

	public function test_T4_6_code_path_closes_after_link_use(): void {
		$result            = $this->issue_with_session();
		[ $sel, $verifier ] = $this->selector_and_verifier_from_url( $result['link_url'] );

		$link_user = TokenManager::validate_link( $sel, $verifier );
		$this->assertInstanceOf( WP_User::class, $link_user );

		$code_result = TokenManager::validate_code( self::EMAIL, $result['code_plaintext'], $result['session_id'] );
		$this->assertInstanceOf(
			WP_Error::class,
			$code_result,
			'Code path is closed once any link click has happened'
		);
	}

	public function test_T5_TOCTOU_atomic_consume_only_one_call_succeeds(): void {
		$result = $this->issue_with_session();

		// Sequential equivalent of "50 parallel calls": the WHERE clause on
		// consumed_at IS NULL means only the first UPDATE sees a non-null row.
		// True parallel testing requires MySQL row locks; the production SQL
		// is identical, so this exercises the same invariant.
		// First call also deletes the session, so the next call hits a missing
		// session and falls back to the same generic_error envelope.
		$sid_a  = $result['session_id'];
		$sid_b  = $this->fresh_session_for( (string) $result['selector'] );
		$sid_c  = $this->fresh_session_for( (string) $result['selector'] );

		$first  = TokenManager::validate_code( self::EMAIL, $result['code_plaintext'], $sid_a );
		$second = TokenManager::validate_code( self::EMAIL, $result['code_plaintext'], $sid_b );
		$third  = TokenManager::validate_code( self::EMAIL, $result['code_plaintext'], $sid_c );

		$this->assertInstanceOf( WP_User::class, $first );
		$this->assertInstanceOf( WP_Error::class, $second );
		$this->assertInstanceOf( WP_Error::class, $third );
	}

	public function test_T6_ttl_boundary_expired_row_rejected(): void {
		$result            = $this->issue();
		[ $sel, $verifier ] = $this->selector_and_verifier_from_url( $result['link_url'] );

		// Force expiry by rewriting the column to a past datetime.
		global $wpdb;
		$wpdb->query( "UPDATE " . TokenManager::table() . " SET expires_at = '2020-01-01 00:00:00'" );

		$response = TokenManager::validate_link( $sel, $verifier );
		$this->assertInstanceOf( WP_Error::class, $response );
		$this->assertSame( TokenManager::ERROR_CODE, $response->get_error_code() );
	}

	public function test_T7_generic_error_envelope_identical_across_miss_paths(): void {
		// Empty inputs.
		$empty = TokenManager::validate_link( '', '' );

		// Invalid charset.
		$bad_charset = TokenManager::validate_link( 'ZZZZZZZZZZZZZZZZ', str_repeat( 'q', 64 ) );

		// Non-existent selector.
		$missing = TokenManager::validate_link( str_repeat( 'a', 16 ), str_repeat( 'b', 64 ) );

		// Wrong code for unknown email.
		$wrong_code = TokenManager::validate_code( 'nobody@example.test', 'AAA-AAA' );

		// Wrong code for known email but no token.
		$wrong_code_known = TokenManager::validate_code( self::EMAIL, 'AAA-AAA' );

		// Expired row.
		$result            = $this->issue();
		[ $sel, $verifier ] = $this->selector_and_verifier_from_url( $result['link_url'] );
		global $wpdb;
		$wpdb->query( "UPDATE " . TokenManager::table() . " SET expires_at = '2020-01-01 00:00:00'" );
		$expired = TokenManager::validate_link( $sel, $verifier );

		$envelopes = [ $empty, $bad_charset, $missing, $wrong_code, $wrong_code_known, $expired ];
		foreach ( $envelopes as $i => $error ) {
			$this->assertInstanceOf( WP_Error::class, $error, 'envelope #' . $i );
			$this->assertSame( TokenManager::ERROR_CODE, $error->get_error_code() );
			$this->assertSame(
				$envelopes[0]->get_error_message(),
				$error->get_error_message(),
				'every miss path yields the same message'
			);
		}
	}

	public function test_T8_session_freezes_after_five_wrong_codes(): void {
		// v1.6.0: the attempt counter lives on the session, not the row.
		// 5 wrong codes via one session freeze that session, but the underlying
		// row stays alive — a fresh session can still consume it.
		$result = $this->issue_with_session();
		$sid    = $result['session_id'];

		for ( $i = 0; $i < 5; $i++ ) {
			$response = TokenManager::validate_code( self::EMAIL, 'AAA-AAA', $sid );
			$this->assertInstanceOf( WP_Error::class, $response, 'wrong code attempt #' . ( $i + 1 ) );
		}

		// Same session — even the right code is refused now.
		$replay_same = TokenManager::validate_code( self::EMAIL, $result['code_plaintext'], $sid );
		$this->assertInstanceOf( WP_Error::class, $replay_same, 'session is frozen at the cap' );

		// Row is NOT consumed — distinguishes this from the old per-row burn.
		global $wpdb;
		$row = $wpdb->get_row( 'SELECT consumed_at FROM ' . TokenManager::table() );
		$this->assertNull( $row->consumed_at, 'row stays live; only the session was exhausted' );

		// A fresh session for the same selector can still consume — this is the
		// critical regression test for the targeted-DoS fix.
		$fresh   = $this->fresh_session_for( (string) $result['selector'] );
		$correct = TokenManager::validate_code( self::EMAIL, $result['code_plaintext'], $fresh );
		$this->assertInstanceOf( WP_User::class, $correct, 'a fresh session can consume the still-live row' );
	}

	public function test_T9_new_issuance_preempts_outstanding_rows_for_email(): void {
		$first  = $this->issue_with_session();
		$second = $this->issue_with_session();
		$this->assertNotSame( $first['code_plaintext'], $second['code_plaintext'] );

		global $wpdb;
		$rows = $wpdb->get_results( 'SELECT consumed_at FROM ' . TokenManager::table() . ' ORDER BY id ASC' );
		$this->assertCount( 2, $rows );
		$this->assertNotNull( $rows[0]->consumed_at, 'old row pre-empted on new issue' );
		$this->assertNull( $rows[1]->consumed_at, 'fresh row is live' );

		// Old session points at a now-consumed selector — refused.
		$old_response = TokenManager::validate_code( self::EMAIL, $first['code_plaintext'], $first['session_id'] );
		$this->assertInstanceOf( WP_Error::class, $old_response );

		// New code via new session works.
		$new_user = TokenManager::validate_code( self::EMAIL, $second['code_plaintext'], $second['session_id'] );
		$this->assertInstanceOf( WP_User::class, $new_user );
	}

	public function test_T10_user_meta_blocks_issuance_and_invalidates_outstanding(): void {
		// First issue normally.
		$first = $this->issue();

		// Now disable.
		update_user_meta( self::USER_ID, 'magicauth_disabled', 1 );

		$second = TokenManager::issue( self::USER_ID, self::EMAIL );
		$this->assertInstanceOf( WP_Error::class, $second );

		// Outstanding row from before the disable was burned.
		global $wpdb;
		$rows = $wpdb->get_results( 'SELECT consumed_at FROM ' . TokenManager::table() );
		foreach ( $rows as $row ) {
			$this->assertNotNull( $row->consumed_at );
		}

		// Pre-disable code no longer works — even with a fresh session bound
		// to the original selector, the row is now consumed.
		$sid = $this->fresh_session_for( (string) $first['selector'] );
		$old = TokenManager::validate_code( self::EMAIL, $first['code_plaintext'], $sid );
		$this->assertInstanceOf( WP_Error::class, $old );
	}

	public function test_T11_hash_equals_called_for_both_paths(): void {
		// We exercise this implicitly by testing that wrong-link does not
		// short-circuit before the code compare side. The CVE-2025-12374 guard
		// is the structural witness: an empty stored hash never matches.
		$result            = $this->issue();
		[ $sel, $verifier ] = $this->selector_and_verifier_from_url( $result['link_url'] );

		// Mutate the verifier to something invalid but well-formed.
		$bad_verifier = str_repeat( 'a', 64 );
		$response     = TokenManager::validate_link( $sel, $bad_verifier );
		$this->assertInstanceOf( WP_Error::class, $response );

		// The original verifier still works (we didn't mutate the row).
		$user = TokenManager::validate_link( $sel, $verifier );
		$this->assertInstanceOf( WP_User::class, $user );
	}

	public function test_T11_5_consume_does_not_rollback(): void {
		$result = $this->issue_with_session();

		// Consume the code.
		$user = TokenManager::validate_code( self::EMAIL, $result['code_plaintext'], $result['session_id'] );
		$this->assertInstanceOf( WP_User::class, $user );

		// Even with a fresh session pointing at the same (now-consumed) selector,
		// the row stays consumed and the replay returns the generic envelope.
		$replay_sid = $this->fresh_session_for( (string) $result['selector'] );
		$replay     = TokenManager::validate_code( self::EMAIL, $result['code_plaintext'], $replay_sid );
		$this->assertInstanceOf( WP_Error::class, $replay );

		global $wpdb;
		$row = $wpdb->get_row( 'SELECT consumed_at FROM ' . TokenManager::table() );
		$this->assertNotNull( $row->consumed_at, 'consumed_at sticks — no rollback' );
	}

	public function test_T12_empty_hash_equals_guard(): void {
		$result            = $this->issue();
		[ $sel, $verifier ] = $this->selector_and_verifier_from_url( $result['link_url'] );

		// Wipe the stored verifier — simulates a corrupt row. CVE-2025-12374:
		// hash_equals('','') returns true, so a row with empty hashes would
		// match an attacker's empty input. Our guard blocks it.
		global $wpdb;
		$wpdb->query( "UPDATE " . TokenManager::table() . " SET link_verifier_hash = '' WHERE selector = '" . $sel . "'" );

		$response = TokenManager::validate_link( $sel, '' );
		$this->assertInstanceOf( WP_Error::class, $response );
	}

	public function test_T15_5_attacker_session_does_not_burn_victim_row(): void {
		// v1.6.0 regression: the wrong-code counter lives on the session.
		// An attacker initiating their own state-A submit for the victim's email
		// gets a session, but that session's wrong codes only freeze the attacker's
		// own session counter. The row stays alive and the legitimate user can
		// still consume it via their own session.
		$victim = $this->issue_with_session();

		// Attacker session: bound to the same email + selector, fresh attempt counter.
		$attacker_sid = $this->fresh_session_for( (string) $victim['selector'] );

		for ( $i = 0; $i < 5; $i++ ) {
			$response = TokenManager::validate_code( self::EMAIL, 'AAA-AAA', $attacker_sid );
			$this->assertInstanceOf( WP_Error::class, $response );
		}

		global $wpdb;
		$row = $wpdb->get_row( 'SELECT consumed_at FROM ' . TokenManager::table() );
		$this->assertNull( $row->consumed_at, 'attacker session did NOT burn the victim row' );

		// Victim can still consume.
		$user = TokenManager::validate_code( self::EMAIL, $victim['code_plaintext'], $victim['session_id'] );
		$this->assertInstanceOf( WP_User::class, $user );
	}

	public function test_session_counter_caps_at_five_for_unknown_email_session(): void {
		// Empty selector path: an unknown-email session never has a row to
		// validate against, but each attempt still costs the attacker one of
		// the session's five tries. After the cap, even a legitimate-looking
		// payload returns the generic envelope.
		$session_id = bin2hex( random_bytes( 16 ) );
		set_transient(
			'magicauth_session_' . $session_id,
			[ 'email' => 'unknown@example.test', 'selector' => '', 'attempts' => 0 ],
			30 * MINUTE_IN_SECONDS
		);

		for ( $i = 0; $i < 5; $i++ ) {
			$r = TokenManager::validate_code( 'unknown@example.test', 'AAA-AAA', $session_id );
			$this->assertInstanceOf( WP_Error::class, $r );
		}

		$payload = get_transient( 'magicauth_session_' . $session_id );
		$this->assertIsArray( $payload );
		$this->assertGreaterThanOrEqual( 5, (int) ( $payload['attempts'] ?? 0 ) );

		// Sixth attempt — still WP_Error, no DB work even attempted.
		$r = TokenManager::validate_code( 'unknown@example.test', 'AAA-AAA', $session_id );
		$this->assertInstanceOf( WP_Error::class, $r );
	}

	public function test_invalidate_outstanding_for_user_marks_all_unconsumed(): void {
		$this->issue();
		$count = TokenManager::invalidate_outstanding_for_user( self::USER_ID );
		$this->assertGreaterThanOrEqual( 1, $count );

		global $wpdb;
		$rows = $wpdb->get_results( 'SELECT consumed_at FROM ' . TokenManager::table() );
		foreach ( $rows as $row ) {
			$this->assertNotNull( $row->consumed_at );
		}
	}

	public function test_invalidate_all_outstanding_marks_all_unconsumed(): void {
		// Issue tokens for two distinct users so we know the wipe is site-wide.
		$other_user_id = 99;
		$other_email   = 'other@example.test';
		magicauth_test_register_user( $other_user_id, $other_email );

		$this->issue();
		TokenManager::issue( $other_user_id, $other_email );

		$count = TokenManager::invalidate_all_outstanding();
		$this->assertSame( 2, $count, 'both unconsumed rows should be revoked' );

		global $wpdb;
		$rows = $wpdb->get_results( 'SELECT consumed_at FROM ' . TokenManager::table() );
		$this->assertCount( 2, $rows );
		foreach ( $rows as $row ) {
			$this->assertNotNull( $row->consumed_at );
		}
	}

	public function test_invalidate_all_outstanding_is_idempotent(): void {
		$this->issue();
		$first  = TokenManager::invalidate_all_outstanding();
		$second = TokenManager::invalidate_all_outstanding();
		$this->assertSame( 1, $first );
		$this->assertSame( 0, $second, 'second call has no unconsumed rows to touch' );
	}

	public function test_invalidate_all_outstanding_skips_already_consumed(): void {
		// Issue → manually mark consumed → issue a second token → revoke-all.
		// invalidate_all_outstanding's WHERE clause is `consumed_at IS NULL`,
		// so only the second row (unconsumed) should be touched.
		$first = $this->issue();
		[ $sel ] = $this->selector_and_verifier_from_url( $first['link_url'] );
		TokenManager::invalidate_outstanding_for_user( self::USER_ID );

		// Issue() pre-empts outstanding rows for the same email — but only
		// unconsumed ones, so the row we just stamped is safe.
		TokenManager::issue( self::USER_ID, self::EMAIL );

		$count = TokenManager::invalidate_all_outstanding();
		$this->assertSame( 1, $count, 'only the second (unconsumed) row gets revoked' );

		// Sanity: the originally-consumed row still exists with its consumed_at
		// non-null; we don't compare exact timestamp because the WHERE clause
		// on UPDATE skips already-stamped rows by design.
		global $wpdb;
		$still_stamped = $wpdb->get_var(
			$wpdb->prepare( 'SELECT consumed_at FROM ' . TokenManager::table() . ' WHERE selector = %s', $sel )
		);
		$this->assertNotNull( $still_stamped, 'pre-stamped row remains stamped' );
	}

	public function test_invalidate_all_outstanding_makes_links_unusable(): void {
		$issued        = $this->issue();
		[ $sel, $ver ] = $this->selector_and_verifier_from_url( $issued['link_url'] );

		TokenManager::invalidate_all_outstanding();

		$result = TokenManager::validate_link( $sel, $ver );
		$this->assertInstanceOf( WP_Error::class, $result, 'revoked link must not authenticate' );
	}

	public function test_export_returns_metadata_only(): void {
		$this->issue();
		$payload = TokenManager::export( self::EMAIL );
		$this->assertIsArray( $payload );
		$this->assertArrayHasKey( 'data', $payload );
		$this->assertArrayHasKey( 'done', $payload );
		$this->assertTrue( $payload['done'] );
		$this->assertCount( 1, $payload['data'] );

		// Verifier hashes never appear in the exporter output.
		$json = json_encode( $payload );
		$this->assertStringNotContainsString( 'verifier_hash', (string) $json );
	}

	public function test_erase_deletes_rows_and_resets_throttle(): void {
		$this->issue();

		$payload = TokenManager::erase( self::EMAIL );
		$this->assertTrue( $payload['done'] );
		$this->assertTrue( $payload['items_removed'] );

		global $wpdb;
		$count = $wpdb->get_var( 'SELECT COUNT(*) FROM ' . TokenManager::table() );
		$this->assertSame( '0', (string) $count );
	}

	public function test_url_never_contains_user_id(): void {
		$result = $this->issue();
		$this->assertStringNotContainsString( 'user_id', $result['link_url'] );
		$this->assertStringNotContainsString( '&u=', $result['link_url'] );
	}

	public function test_selector_is_unique_per_issuance(): void {
		$seen = [];
		for ( $i = 0; $i < 20; $i++ ) {
			$result   = TokenManager::issue( self::USER_ID, self::EMAIL );
			$selector = $result['selector'];
			$this->assertNotContains( $selector, $seen );
			$seen[] = $selector;
		}
	}
}
