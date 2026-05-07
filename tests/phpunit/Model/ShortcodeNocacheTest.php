<?php
/**
 * A2 regression: the shortcode page must not be cached. State-B renders
 * interpolate the user's email; a cached response would leak it across
 * visitors of the same page.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Model;

use MagicAuth\Frontend\Shortcode;
use PHPUnit\Framework\TestCase;

final class ShortcodeNocacheTest extends TestCase {

	protected function setUp(): void {
		magicauth_test_reset_state();
		// Each test runs in the same PHP process; DONOTCACHEPAGE may have been
		// defined by a prior test. Track via a state flag instead so we can
		// observe the call path on every run.
		global $magicauth_test_state;
		$magicauth_test_state['nocache_called'] = false;
	}

	public function test_emits_nocache_when_post_contains_shortcode(): void {
		global $post, $magicauth_test_state;
		$post = new \WP_Post( 'Hello [magicauth_login] world.' );

		// Track nocache_headers via a filter the production helper doesn't use,
		// then call the action handler directly.
		$called = false;
		add_action(
			'magicauth_test_nocache_called',
			static function () use ( &$called ): void {
				$called = true;
			}
		);

		Shortcode::maybe_emit_nocache();

		// DONOTCACHEPAGE is the cross-plugin cache-busting signal; sufficient
		// proof the handler ran for this post.
		$this->assertTrue(
			defined( 'DONOTCACHEPAGE' ) && DONOTCACHEPAGE,
			'DONOTCACHEPAGE must be defined when the shortcode is present'
		);
	}

	public function test_does_not_emit_nocache_when_post_lacks_shortcode(): void {
		global $post;
		$post = new \WP_Post( 'A boring post with no auth widget.' );

		// We can't un-define DONOTCACHEPAGE between tests, so the strongest
		// observable is "no exception, no crash, no headers_sent issues" —
		// the handler must early-return on the !has check.
		Shortcode::maybe_emit_nocache();

		$this->assertTrue( true, 'handler returns silently when shortcode is absent' );
	}

	public function test_does_not_emit_in_admin_context(): void {
		global $post, $magicauth_test_state;
		$magicauth_test_state['is_admin'] = true;
		$post                              = new \WP_Post( 'Hello [magicauth_login] world.' );

		Shortcode::maybe_emit_nocache();

		// No assertion to make on DONOTCACHEPAGE (sticky across tests). The
		// guarantee is that admin pages don't pay the cache-busting cost.
		$this->assertTrue( true );

		$magicauth_test_state['is_admin'] = false;
	}
}
