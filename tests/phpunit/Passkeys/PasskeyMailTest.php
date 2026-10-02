<?php
/**
 * T-MAIL 1, 1b, 3 and the en_US half of 6 for the two emails of build step
 * 11 (SPEC 10.1 to 10.3, invariants 12 and 13): the passkey-added notice and
 * the step-up confirmation code. Own dispatchers, filters by prefix, $type on
 * the shared filters, recipient locale, no links, no user-supplied text, no
 * creation wording. Build step 13 adds T-MAIL 4, 5 and their part of 6: the
 * passkeys-removed and passkey-blocked notices (10.4, 10.5). Build step 15
 * adds the nl_NL half of T-MAIL-6: the msgstr values of those emails and
 * the emails rendered in nl_NL with the shipped translations.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Email\Mailer;
use MagicAuth\Passkeys\CredentialStore;
use MagicAuth\Tests\Support\Ceremony;
use MagicAuth\Tests\Support\Po;
use MagicAuth\Tests\Support\SoftAuthenticator;
use PHPUnit\Framework\TestCase;
use WP_User;

final class PasskeyMailTest extends TestCase {

	/** T-MAIL-6: creation wording (en_US). */
	private const CREATION = '/\b(create|creating|add (a|an|another|it|one|new))\b/i';

	/** T-MAIL-6: creation wording (nl_NL); past participles such as "toegevoegd" do not match. */
	private const NL_CREATION = '/\b(toevoegen|aanmaken|maak|voeg)\b/i';

	/** The added, removed and blocked emails (10.2, 10.4, 10.5). */
	private const NOTICE_TEMPLATES = [
		'templates/email-passkey-added.php',
		'templates/email-passkey-added-plain.php',
		'templates/email-passkeys-removed.php',
		'templates/email-passkeys-removed-plain.php',
		'templates/email-passkey-blocked.php',
		'templates/email-passkey-blocked-plain.php',
	];


	private WP_User $user;

	protected function setUp(): void {
		Ceremony::site();
		$this->user = Ceremony::user( 7 );
		update_option( 'magicauth_settings', [ 'company_name' => 'Example Academy' ] );
	}

	protected function tearDown(): void {
		magicauth_test_reset_state();
	}

	/* ------------------------------------------------------------- helpers */

	/** @param array<string,mixed> $opts SoftAuthenticator options. */
	private function enrol( array $opts = [], string $name = '' ): int {
		$auth   = new SoftAuthenticator( 'ES256', $opts );
		$record = \MagicAuth\Passkeys\Verifier::verify_registration( Ceremony::registration( $auth, $this->user ), $this->user, Ceremony::SESSION, $name );
		$this->assertIsArray( $record );
		$id = \MagicAuth\Passkeys\Verifier::store_registration( $record );
		$this->assertIsInt( $id );
		return $id;
	}

	/** @return array{to:mixed,subject:string,message:string,headers:mixed,alt_body:string} */
	private static function last_mail(): array {
		global $magicauth_test_state;
		$mails = $magicauth_test_state['mail'] ?? [];
		self::assertNotEmpty( $mails, 'a mail was sent' );
		return end( $mails );
	}

	private static function hash_suffix( int $id ): string {
		global $wpdb;
		return strtoupper( substr( (string) $wpdb->get_var( $wpdb->prepare( 'SELECT credential_hash FROM ' . CredentialStore::table() . ' WHERE id = %d', $id ) ), -4 ) );
	}

	/** Visible text of an HTML body, one line per block. */
	private static function text( string $html ): string {
		$html = (string) preg_replace( '#<(title|head)\b.*?</\1>#is', '', $html );
		return trim( (string) preg_replace( '/\s*\n\s*/', "\n", html_entity_decode( strip_tags( $html ), ENT_QUOTES, 'UTF-8' ) ) );
	}

	private function assert_no_links( string $body, string $label ): void {
		$this->assertStringNotContainsStringIgnoringCase( 'http', $body, $label );
		$this->assertStringNotContainsStringIgnoringCase( 'href', $body, $label );
		$this->assertStringNotContainsStringIgnoringCase( 'www.', $body, $label );
	}

	/* ------------------------------------------------------------- 1: passkey added */

	public function test_1_passkey_added_email(): void {
		global $magicauth_test_state;
		$id = $this->enrol( [ 'be' => false, 'bs' => false ] );

		$this->assertTrue( Mailer::send_passkey_added( 7, $id ) );

		$mail = self::last_mail();
		$this->assertSame( 'learner7@example.test', $mail['to'] );
		$this->assertSame( 'A passkey was added to your Example Academy account', $mail['subject'] );
		$label = 'Passkey ending in ' . self::hash_suffix( $id );
		foreach ( [ 'html' => self::text( $mail['message'] ), 'plain' => $mail['alt_body'] ] as $part => $body ) {
			$this->assertStringContainsString( 'A passkey was added', $body, $part );
			$this->assertStringContainsString( "Hello,\n", $body, $part );
			$this->assertStringNotContainsString( 'Learner 7', $body, $part . ': no display name (invariant 12)' );
			$this->assertStringContainsString( 'Passkey: ' . $label, $body, $part );
			$this->assertStringContainsString( 'Stored in: Unknown provider. This device only', $body, $part );
			$this->assertStringContainsString( 'A passkey was added to your account at Example Academy on ', $body, $part );
			$this->assertStringContainsString( '(UTC)', $body, $part );
			$this->assertStringContainsString( 'If you added this passkey, you do not need to do anything.', $body, $part );
			$this->assertStringContainsString( 'open your passkey settings, remove the passkey ending in ' . self::hash_suffix( $id ), $body, $part . ': E8b without a location' );
		}
		$this->assert_no_links( $mail['message'], 'html' );
		$this->assert_no_links( $mail['alt_body'], 'plain' );
		$this->assertContains( 'Content-Type: text/html; charset=UTF-8', $mail['headers'] );
		$this->assertSame( [ 'en_US' ], $magicauth_test_state['locale_switches'] ?? [] );
		$this->assertSame( 1, $magicauth_test_state['locale_restores'] ?? 0 );
	}

	public function test_1_added_email_is_sent_in_the_recipients_locale(): void {
		global $magicauth_test_state;
		$this->user->locale = 'nl_NL';
		$this->assertTrue( Mailer::send_passkey_added( 7, $this->enrol() ) );
		$this->assertSame( [ 'nl_NL' ], $magicauth_test_state['locale_switches'] );
		$this->assertSame( 1, $magicauth_test_state['locale_restores'] );
	}

	public function test_1_never_the_passkey_name(): void {
		$id   = $this->enrol( [], 'evil.example call 0800 123' );
		$this->assertTrue( Mailer::send_passkey_added( 7, $id ) );
		$mail = self::last_mail();
		foreach ( [ $mail['subject'], $mail['message'], $mail['alt_body'] ] as $body ) {
			$this->assertStringNotContainsString( 'evil.example', $body );
			$this->assertStringNotContainsString( '0800', $body );
		}
	}

	/** Invariant 12 and D-35 over 10.2 E3: the display name is user-editable, so no body carries it. */
	public function test_1_never_the_display_name(): void {
		$this->user->display_name = 'evil.example call 0800 123';
		$this->assertTrue( Mailer::send_passkey_added( 7, $this->enrol() ) );
		$mail = self::last_mail();
		foreach ( [ 'subject' => $mail['subject'], 'html' => $mail['message'], 'plain' => $mail['alt_body'] ] as $part => $body ) {
			$this->assertStringNotContainsString( 'evil.example', $body, $part );
			$this->assertStringNotContainsString( '0800 123', $body, $part );
			$this->assertStringNotContainsString( 'call 0800', $body, $part );
		}
		$this->assertStringContainsString( "Hello,\n", self::text( $mail['message'] ) );
		$this->assertStringContainsString( "Hello,\n", $mail['alt_body'] );
	}

	/** @return array<string,array{bool,bool,string}> */
	public static function sync_labels(): array {
		return [
			'synced'             => [ true, true, 'Synced across your devices' ],
			'eligible, unsynced' => [ true, false, 'Can be synced, not synced yet' ],
			'device-bound'       => [ false, false, 'This device only' ],
		];
	}

	/** @dataProvider sync_labels */
	public function test_1_sync_label( bool $be, bool $bs, string $label ): void {
		Mailer::send_passkey_added( 7, $this->enrol( [ 'be' => $be, 'bs' => $bs ] ) );
		$this->assertStringContainsString( 'Stored in: Unknown provider. ' . $label, self::last_mail()['alt_body'] );
	}

	public function test_1_known_provider_is_reported_by_the_device(): void {
		global $wpdb;
		$id = $this->enrol();
		$wpdb->query( $wpdb->prepare( 'UPDATE ' . CredentialStore::table() . ' SET aaguid = %s WHERE id = %d', 'bada5566-a7aa-401f-bd96-45619a55120d', $id ) );
		Mailer::send_passkey_added( 7, $id );
		$this->assertStringContainsString( 'Stored in: 1Password (reported by the device).', self::last_mail()['alt_body'] );
		unset( $wpdb );
	}

	/** 1b: with a management page, the body names its path as plain text. */
	public function test_1b_management_page_path_without_a_link(): void {
		global $magicauth_test_state;
		$magicauth_test_state['posts'][42] = [
			'status'    => 'publish',
			'type'      => 'page',
			'permalink' => Ceremony::ORIGIN . '/account/',
			'title'     => 'Account',
		];
		update_option( 'magicauth_settings', [ 'company_name' => 'Example Academy', 'passkeys_manage_page_id' => 42 ] );
		$id = $this->enrol();

		Mailer::send_passkey_added( 7, $id );

		$mail = self::last_mail();
		foreach ( [ self::text( $mail['message'] ), $mail['alt_body'] ] as $body ) {
			$this->assertStringContainsString( 'go to Account (/account/), remove the passkey ending in ' . self::hash_suffix( $id ), $body );
		}
		$this->assert_no_links( $mail['message'], 'html' );
		$this->assert_no_links( $mail['alt_body'], 'plain' );
	}

	public function test_1_filters_by_prefix_and_type_on_the_shared_filters(): void {
		$seen = [];
		add_filter(
			'magicauth_passkey_added_template_args',
			static function ( $args, $user ) use ( &$seen ) {
				$seen['args'] = $user instanceof WP_User;
				$args['company_name'] = 'Filtered Co';
				return $args;
			},
			10,
			2
		);
		add_filter(
			'magicauth_passkey_added_subject',
			static function ( $subject, $user, $args ) use ( &$seen ) {
				$seen['subject'] = $args['company_name'];
				return 'Custom subject';
			},
			10,
			3
		);
		add_filter( 'magicauth_passkey_added_html', static fn( $html ) => $html . '<!-- html filter -->' );
		add_filter( 'magicauth_passkey_added_plaintext', static fn( $text ) => $text . 'plain filter' );
		add_filter(
			'magicauth_email_from',
			static function ( $from, $user = null, $type = '' ) use ( &$seen ) {
				$seen['from'] = $type;
				return $from;
			},
			10,
			3
		);
		add_filter(
			'magicauth_email_headers',
			static function ( $headers, $user = null, $type = '' ) use ( &$seen ) {
				$seen['headers'] = $type;
				return $headers;
			},
			10,
			3
		);

		Mailer::send_passkey_added( 7, $this->enrol() );

		$mail = self::last_mail();
		$this->assertSame( 'Custom subject', $mail['subject'] );
		$this->assertStringContainsString( '<!-- html filter -->', $mail['message'] );
		$this->assertStringContainsString( 'plain filter', $mail['alt_body'] );
		$this->assertStringContainsString( 'Filtered Co', $mail['alt_body'] );
		$this->assertSame(
			[
				'args'    => true,
				'subject' => 'Filtered Co',
				'from'    => 'passkey_added',
				'headers' => 'passkey_added',
			],
			$seen
		);
	}

	public function test_1_send_filter_short_circuits(): void {
		global $magicauth_test_state;
		add_filter( 'magicauth_passkey_added_send', static fn() => false );
		$this->assertFalse( Mailer::send_passkey_added( 7, $this->enrol() ) );
		$this->assertSame( [], $magicauth_test_state['mail'] ?? [] );
	}

	public function test_1_unknown_row_or_user_sends_nothing(): void {
		global $magicauth_test_state;
		$id    = $this->enrol();
		$other = Ceremony::user( 8 );
		$this->assertFalse( Mailer::send_passkey_added( 8, $id ), 'another user\'s row' );
		$this->assertFalse( Mailer::send_passkey_added( 7, $id + 99 ) );
		$this->assertFalse( Mailer::send_passkey_added( 999, $id ) );
		$this->assertSame( [], $magicauth_test_state['mail'] ?? [] );
		unset( $other );
	}

	public function test_1_alt_body_handler_is_removed_after_the_send(): void {
		global $magicauth_test_state;
		Mailer::send_passkey_added( 7, $this->enrol() );
		$this->assertEmpty( $magicauth_test_state['actions']['phpmailer_init'] ?? [] );
	}

	/* ------------------------------------------------------------- 3: confirmation code */

	public function test_3_confirm_code_email(): void {
		global $magicauth_test_state;
		$this->assertTrue( Mailer::send_confirm_code( 7, 'ABC2EF' ) );

		$mail = self::last_mail();
		$this->assertSame( 'Your confirmation code for Example Academy', $mail['subject'] );
		$this->assertStringNotContainsString( 'ABC', $mail['subject'], 'code not in the subject' );
		foreach ( [ 'html' => self::text( $mail['message'] ), 'plain' => $mail['alt_body'] ] as $part => $body ) {
			$this->assertStringContainsString( 'Use this code to confirm it is you: ABC-2EF', $body, $part );
			$this->assertStringContainsString( 'The code is valid for 10 minutes. You asked for it to add a passkey to your account.', $body, $part );
			$this->assertStringContainsString( 'Never share this code. Nobody from Example Academy will ask you for it.', $body, $part );
			$this->assertStringContainsString( 'If you did not ask for this code, someone may be signed in to your account. Contact your administrator.', $body, $part );
		}
		$this->assert_no_links( $mail['message'], 'html' );
		$this->assert_no_links( $mail['alt_body'], 'plain' );
		$this->assertSame( [ 'en_US' ], $magicauth_test_state['locale_switches'] ?? [] );
	}

	public function test_3_confirm_code_filters_and_type(): void {
		$types = [];
		add_filter(
			'magicauth_email_from',
			static function ( $from, $user = null, $type = '' ) use ( &$types ) {
				$types[] = $type;
				return $from;
			},
			10,
			3
		);
		add_filter( 'magicauth_confirm_code_subject', static fn() => 'Subject from the filter' );
		Mailer::send_confirm_code( 7, 'ABC2EF' );
		$this->assertSame( [ 'confirm_code' ], $types );
		$this->assertSame( 'Subject from the filter', self::last_mail()['subject'] );
	}

	public function test_3_confirm_code_send_filter_short_circuits(): void {
		global $magicauth_test_state;
		add_filter( 'magicauth_confirm_code_send', static fn() => true );
		$this->assertTrue( Mailer::send_confirm_code( 7, 'ABC2EF' ) );
		$this->assertSame( [], $magicauth_test_state['mail'] ?? [] );
	}

	/* ------------------------------------------------------------- 6: creation wording (en_US) */

	public function test_6_added_email_has_no_creation_wording(): void {
		global $magicauth_test_state;
		foreach ( [ [ false, false ], [ true, false ], [ true, true ] ] as $flags ) {
			Mailer::send_passkey_added( 7, $this->enrol( [ 'be' => $flags[0], 'bs' => $flags[1] ] ) );
		}
		$magicauth_test_state['posts'][42] = [
			'status'    => 'publish',
			'type'      => 'page',
			'permalink' => Ceremony::ORIGIN . '/account/',
			'title'     => 'Account',
		];
		update_option( 'magicauth_settings', [ 'company_name' => 'Example Academy', 'passkeys_manage_page_id' => 42 ] );
		Mailer::send_passkey_added( 7, $this->enrol() );

		$this->assertCount( 4, $magicauth_test_state['mail'] );
		foreach ( $magicauth_test_state['mail'] as $mail ) {
			foreach ( [ $mail['subject'], self::text( $mail['message'] ), $mail['message'], $mail['alt_body'] ] as $body ) {
				$this->assertDoesNotMatchRegularExpression( self::CREATION, $body );
			}
		}
	}

	public function test_6_confirm_code_only_e11_mentions_a_passkey(): void {
		Mailer::send_confirm_code( 7, 'ABC2EF' );
		$mail = self::last_mail();
		$this->assertStringNotContainsStringIgnoringCase( 'passkey', $mail['subject'] );
		foreach ( [ 'html' => self::text( $mail['message'] ), 'plain' => $mail['alt_body'] ] as $part => $body ) {
			$lines = array_values(
				array_filter(
					explode( "\n", $body ),
					static fn( string $line ): bool => false !== stripos( $line, 'passkey' )
				)
			);
			$this->assertSame( [ 'The code is valid for 10 minutes. You asked for it to add a passkey to your account.' ], array_map( 'trim', $lines ), $part );
		}
	}

	/* ------------------------------------------------------------- 4: passkeys removed */

	/** @return array<string,array{string,string,int,string}> */
	public static function removed_variants(): array {
		return [
			'self, 1'          => [ 'self', 'removed', 1, 'You removed 1 passkey from your account at Example Academy on ' ],
			'self, 3'          => [ 'self', 'removed', 3, 'You removed 3 passkeys from your account at Example Academy on ' ],
			'admin, 1'         => [ 'admin', 'removed', 1, 'An administrator removed 1 passkey from your account at Example Academy on ' ],
			'admin, 3'         => [ 'admin', 'removed', 3, 'An administrator removed 3 passkeys from your account at Example Academy on ' ],
			'email changed, 1' => [ 'system', 'email_changed', 1, 'Your passkeys were removed because the email address of your account changed.' ],
			'email changed, 3' => [ 'system', 'email_changed', 3, 'Your passkeys were removed because the email address of your account changed.' ],
		];
	}

	/** @dataProvider removed_variants */
	public function test_4_passkeys_removed_variants( string $actor, string $reason, int $count, string $line ): void {
		global $magicauth_test_state;
		$this->assertTrue( Mailer::send_passkeys_removed( 7, $count, $actor, $reason, [] ) );
		$mail = self::last_mail();
		$this->assertSame( 'learner7@example.test', $mail['to'] );
		$this->assertSame( 1 === $count ? '1 passkey was removed from your Example Academy account' : '3 passkeys were removed from your Example Academy account', $mail['subject'] );
		foreach ( [ 'html' => self::text( $mail['message'] ), 'plain' => $mail['alt_body'] ] as $part => $body ) {
			$this->assertStringContainsString( $line, $body, $part );
			$this->assertStringContainsString( 1 === $count ? 'A passkey was removed' : 'Passkeys were removed', $body, $part );
			$this->assertStringContainsString( 'Hello,', $body, $part );
			$this->assertStringContainsString( 'You can still sign in with your email.', $body, $part );
			$this->assertStringContainsString( 'If you did not expect this, someone else may have access to your account. Sign in with your email, open your passkey settings and choose "Sign out on all other devices". Then contact your administrator.', $body, $part );
			$this->assertStringNotContainsString( 'Learner 7', $body, $part );
		}
		$this->assert_no_links( $mail['message'], 'html' );
		$this->assert_no_links( $mail['alt_body'], 'plain' );
		$this->assertSame( [ 'en_US' ], $magicauth_test_state['locale_switches'] ?? [] );
		$this->assertSame( 1, (int) ( $magicauth_test_state['locale_restores'] ?? 0 ), 'locale restored' );
	}

	public function test_4_both_addresses_on_an_email_change_one_mail_each(): void {
		global $magicauth_test_state;
		$this->assertTrue( Mailer::send_passkeys_removed( 7, 2, 'system', 'email_changed', [ 'old@example.test', 'learner7@example.test', 'OLD@example.test', 'not an address' ] ) );
		$mails = $magicauth_test_state['mail'];
		$this->assertSame( [ 'old@example.test', 'learner7@example.test' ], array_column( $mails, 'to' ), 'distinct valid addresses, one mail each' );
		foreach ( $mails as $mail ) {
			$this->assertStringNotContainsString( 'old@', $mail['alt_body'] . $mail['message'] );
			$this->assertStringNotContainsString( 'learner7@', $mail['alt_body'] . $mail['message'] );
		}
	}

	public function test_4_management_location_without_a_link(): void {
		global $magicauth_test_state;
		$magicauth_test_state['posts'][42] = [
			'status'    => 'publish',
			'type'      => 'page',
			'permalink' => Ceremony::ORIGIN . '/account/',
			'title'     => 'Account',
		];
		update_option( 'magicauth_settings', [ 'company_name' => 'Example Academy', 'passkeys_manage_page_id' => 42 ] );
		Mailer::send_passkeys_removed( 7, 1, 'self', 'removed', [] );
		$mail = self::last_mail();
		foreach ( [ self::text( $mail['message'] ), $mail['alt_body'] ] as $body ) {
			$this->assertStringContainsString( 'Sign in with your email, go to Account (/account/) and choose "Sign out on all other devices".', $body );
		}
		$this->assert_no_links( $mail['message'], 'html' );
	}

	public function test_4_filters_by_prefix_and_type(): void {
		$seen = [];
		add_filter(
			'magicauth_passkeys_removed_template_args',
			static function ( $args ) use ( &$seen ) {
				$seen[] = [ 'args', $args['count'], $args['actor'], $args['reason'] ];
				return $args;
			}
		);
		add_filter(
			'magicauth_email_headers',
			static function ( $headers, $user = null, $type = '' ) use ( &$seen ) {
				$seen[] = [ 'type', $type ];
				return $headers;
			},
			10,
			3
		);
		add_filter( 'magicauth_passkeys_removed_subject', static fn() => 'Filtered' );
		Mailer::send_passkeys_removed( 7, 2, 'admin', 'removed', [] );
		$this->assertSame( [ [ 'args', 2, 'admin', 'removed' ], [ 'type', 'passkeys_removed' ] ], $seen );
		$this->assertSame( 'Filtered', self::last_mail()['subject'] );
	}

	public function test_4_send_filter_short_circuits_and_bad_input_sends_nothing(): void {
		global $magicauth_test_state;
		$this->assertFalse( Mailer::send_passkeys_removed( 7, 0, 'self', 'removed', [] ), 'nothing removed' );
		$this->assertFalse( Mailer::send_passkeys_removed( 999, 1, 'self', 'removed', [] ), 'unknown user' );
		$this->assertFalse( Mailer::send_passkeys_removed( 7, 1, 'self', 'removed', [ 'nope' ] ), 'no valid address' );
		add_filter( 'magicauth_passkeys_removed_send', static fn() => true );
		$this->assertTrue( Mailer::send_passkeys_removed( 7, 1, 'self', 'removed', [] ) );
		$this->assertSame( [], $magicauth_test_state['mail'] ?? [] );
	}

	public function test_4_unknown_actor_and_reason_fall_back_to_neutral_wording(): void {
		Mailer::send_passkeys_removed( 7, 1, 'hacker<b>', 'whatever', [] );
		$body = self::last_mail()['alt_body'];
		$this->assertStringNotContainsString( 'hacker', $body );
		$this->assertStringContainsString( 'You removed 1 passkey', $body, 'system actor with reason removed reads as the account' );
	}

	/* ------------------------------------------------------------- 5: passkey blocked */

	public function test_5_passkey_blocked_email(): void {
		global $wpdb, $magicauth_test_state;
		$id = $this->enrol( [ 'be' => false, 'bs' => false ], 'evil.example call 0800 123' );
		$wpdb->query( $wpdb->prepare( 'UPDATE ' . CredentialStore::table() . ' SET counter_anomaly_at = %s WHERE id = %d', '2026-09-30 09:00:00', $id ) );

		$this->assertTrue( Mailer::send_passkey_blocked( 7, $id ) );
		$mail = self::last_mail();
		$this->assertSame( 'learner7@example.test', $mail['to'] );
		$this->assertSame( 'A passkey on your Example Academy account was blocked', $mail['subject'] );
		$label = 'Passkey ending in ' . self::hash_suffix( $id );
		foreach ( [ 'html' => self::text( $mail['message'] ), 'plain' => $mail['alt_body'] ] as $part => $body ) {
			$this->assertStringContainsString( 'A passkey was blocked', $body, $part );
			$this->assertStringContainsString( 'A passkey on your account (' . $label . ') was blocked at ', $body, $part );
			$this->assertStringContainsString( 'because it may have been copied.', $body, $part );
			$this->assertStringContainsString( 'It cannot be used to sign in any more. You can still sign in with your email.', $body, $part );
			$this->assertStringContainsString( 'Sign in with your email, open your passkey settings, remove the blocked passkey and choose "Sign out on all other devices".', $body, $part );
			$this->assertStringNotContainsString( 'evil.example', $body, $part );
			$this->assertStringNotContainsString( '0800', $body, $part );
		}
		$this->assertStringNotContainsString( 'evil.example', $mail['subject'] );
		$this->assert_no_links( $mail['message'], 'html' );
		$this->assert_no_links( $mail['alt_body'], 'plain' );
		$this->assertSame( [ 'en_US' ], $magicauth_test_state['locale_switches'] ?? [] );
	}

	public function test_5_blocked_filters_and_unknown_rows(): void {
		global $magicauth_test_state;
		$types = [];
		add_filter(
			'magicauth_email_from',
			static function ( $from, $user = null, $type = '' ) use ( &$types ) {
				$types[] = $type;
				return $from;
			},
			10,
			3
		);
		$id = $this->enrol();
		Ceremony::user( 8 );
		$this->assertFalse( Mailer::send_passkey_blocked( 8, $id ), 'another user\'s row' );
		$this->assertFalse( Mailer::send_passkey_blocked( 7, 99999 ), 'unknown row' );
		$this->assertFalse( Mailer::send_passkey_blocked( 999, $id ), 'unknown user' );
		$this->assertSame( [], $magicauth_test_state['mail'] ?? [] );
		$this->assertTrue( Mailer::send_passkey_blocked( 7, $id ) );
		$this->assertSame( [ 'passkey_blocked' ], $types );
		add_filter( 'magicauth_passkey_blocked_send', static fn() => false );
		$this->assertFalse( Mailer::send_passkey_blocked( 7, $id ) );
		$this->assertCount( 1, $magicauth_test_state['mail'] );
	}

	/* ------------------------------------------------------------- 6: removed and blocked */

	public function test_6_removed_and_blocked_emails_have_no_creation_wording(): void {
		global $wpdb, $magicauth_test_state;
		foreach ( self::removed_variants() as [ $actor, $reason, $count ] ) {
			Mailer::send_passkeys_removed( 7, $count, $actor, $reason, [] );
		}
		$magicauth_test_state['posts'][42] = [
			'status'    => 'publish',
			'type'      => 'page',
			'permalink' => Ceremony::ORIGIN . '/account/',
			'title'     => 'Account',
		];
		update_option( 'magicauth_settings', [ 'company_name' => 'Example Academy', 'passkeys_manage_page_id' => 42 ] );
		Mailer::send_passkeys_removed( 7, 2, 'admin', 'removed', [] );
		$id = $this->enrol( [ 'be' => false, 'bs' => false ] );
		$wpdb->query( $wpdb->prepare( 'UPDATE ' . CredentialStore::table() . ' SET counter_anomaly_at = %s WHERE id = %d', '2026-09-30 09:00:00', $id ) );
		Mailer::send_passkey_blocked( 7, $id );
		update_option( 'magicauth_settings', [ 'company_name' => 'Example Academy' ] );
		Mailer::send_passkey_blocked( 7, $id );

		$this->assertCount( 9, $magicauth_test_state['mail'] );
		foreach ( $magicauth_test_state['mail'] as $mail ) {
			foreach ( [ $mail['subject'], self::text( $mail['message'] ), $mail['message'], $mail['alt_body'] ] as $body ) {
				$this->assertDoesNotMatchRegularExpression( self::CREATION, $body );
			}
		}
	}

	/* ------------------------------------------------------------- 6: nl_NL */

	public function test_6_nl_msgstr_of_the_notices_has_no_creation_wording(): void {
		$po     = Po::entries( MAGICAUTH_DIR . 'languages/magicauth-nl_NL.po' );
		$msgids = [];
		foreach ( self::NOTICE_TEMPLATES as $template ) {
			foreach ( Po::referenced_from( $po, $template ) as $entry ) {
				$msgids[ $entry['id'] ] = true;
			}
			foreach ( Po::source_msgids( MAGICAUTH_DIR . $template ) as $msgid ) {
				$msgids[ $msgid ] = true;
			}
		}
		// Subjects, labels and provider text the dispatchers build.
		foreach ( Po::method_msgids( Mailer::class, [ 'send_passkey_added', 'send_passkeys_removed', 'send_passkey_blocked', 'build_security_args', 'build_passkey_added_args' ] ) as $msgid ) {
			$msgids[ $msgid ] = true;
		}
		$this->assertGreaterThan( 25, count( $msgids ) );

		$checked = 0;
		foreach ( $po as $entry ) {
			if ( ! isset( $msgids[ $entry['id'] ] ) && ! isset( $msgids[ (string) $entry['plural'] ] ) ) {
				continue;
			}
			foreach ( $entry['str'] as $str ) {
				$this->assertNotSame( '', $str, 'translated: ' . $entry['id'] );
				$this->assertDoesNotMatchRegularExpression( self::NL_CREATION, $str, $entry['id'] );
			}
			++$checked;
		}
		$this->assertGreaterThan( 25, $checked );
	}

	public function test_6_notices_rendered_in_nl_have_no_creation_wording(): void {
		global $wpdb, $magicauth_test_state;
		$this->user->locale = 'nl_NL';
		magicauth_test_load_translations( 'nl_NL', MAGICAUTH_DIR . 'languages/magicauth-nl_NL.l10n.php' );

		$added = [];
		foreach ( [ [ false, false ], [ true, false ], [ true, true ] ] as $flags ) {
			$added[] = $this->enrol( [ 'be' => $flags[0], 'bs' => $flags[1] ] );
			Mailer::send_passkey_added( 7, end( $added ) );
		}
		foreach ( self::removed_variants() as [ $actor, $reason, $count ] ) {
			Mailer::send_passkeys_removed( 7, $count, $actor, $reason, [] );
		}
		$wpdb->query( $wpdb->prepare( 'UPDATE ' . CredentialStore::table() . ' SET counter_anomaly_at = %s WHERE id = %d', '2026-09-30 09:00:00', $added[0] ) );
		Mailer::send_passkey_blocked( 7, $added[0] );

		// Again with a management page (E8, E18, E22 name it).
		$magicauth_test_state['posts'][42] = [
			'status'    => 'publish',
			'type'      => 'page',
			'permalink' => Ceremony::ORIGIN . '/account/',
			'title'     => 'Account',
		];
		update_option( 'magicauth_settings', [ 'company_name' => 'Example Academy', 'passkeys_manage_page_id' => 42 ] );
		Mailer::send_passkey_added( 7, $added[1] );
		Mailer::send_passkeys_removed( 7, 2, 'admin', 'removed', [] );
		Mailer::send_passkey_blocked( 7, $added[0] );

		$mails = $magicauth_test_state['mail'];
		$this->assertCount( 13, $mails );
		foreach ( $mails as $i => $mail ) {
			foreach ( [ $mail['subject'], self::text( $mail['message'] ), $mail['message'], $mail['alt_body'] ] as $body ) {
				$this->assertDoesNotMatchRegularExpression( self::NL_CREATION, $body, 'mail ' . $i );
				$this->assertDoesNotMatchRegularExpression( self::CREATION, $body, 'mail ' . $i );
			}
			$this->assertStringContainsString( 'Hallo,', $mail['alt_body'], 'rendered in Dutch: mail ' . $i );
		}
		$this->assertSame( 'Er is een passkey toegevoegd aan je Example Academy-account', $mails[0]['subject'] );

		// Q2: the added email glosses the term once, in E4; the others do not.
		$gloss = 'een passkey (toegangssleutel of wachtwoordsleutel)';
		foreach ( $mails as $i => $mail ) {
			$is_added = in_array( $i, [ 0, 1, 2, 10 ], true );
			foreach ( [ self::text( $mail['message'] ), $mail['alt_body'] ] as $body ) {
				$this->assertSame( $is_added ? 1 : 0, substr_count( $body, $gloss ), 'mail ' . $i );
			}
		}
		$this->assertStringContainsString( 'Er is ' . $gloss . ' toegevoegd aan je account bij Example Academy op ', $mails[0]['alt_body'] );
	}
}
