<?php
/**
 * SPEC 9 and build step 15: the shipped catalogues. The .pot carries every
 * msgid in the source; nl_NL translates all of them (only the plugin header
 * metadata stays untranslated, as in 1.0.4) without fuzzy entries, keeps
 * every placeholder, and uses the loanword "passkey" with its first-use gloss
 * in P2, M2 and the passkey-added email (D-40, Q2); de_DE and es_ES carry
 * the new msgids untranslated. The .l10n.php files and the admin script's
 * JSON match their .po files.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Passkeys;

use MagicAuth\Tests\Support\Po;
use PHPUnit\Framework\TestCase;

final class I18nTest extends TestCase {

	private const LANGUAGES = MAGICAUTH_DIR . 'languages/';

	private const GLOSS = 'een passkey (toegangssleutel of wachtwoordsleutel)';

	/** P2, M2 and E4: the only msgids whose nl_NL text carries the gloss (9, D-40). */
	private const GLOSSED = [
		'Create a passkey on this device. Next time you can sign in with your fingerprint, face or screen lock instead of an email code.',
		'A passkey lets you sign in with your fingerprint, face or screen lock instead of an email code. You can always sign in with your email as well.',
		'A passkey was added to your account at %1$s on %2$s (%3$s).',
	];

	private const ADMIN_JS = 'assets/js/magicauth-admin.js';

	private static function pot(): string {
		return self::LANGUAGES . 'magicauth.pot';
	}

	private static function po( string $locale ): string {
		return self::LANGUAGES . 'magicauth-' . $locale . '.po';
	}

	/** Plugin header metadata (name, URIs, author): left untranslated, as in 1.0.4. */
	private static function is_header_meta( array $entry ): bool {
		return 1 === preg_match( '/ of the plugin$/m', $entry['extracted'] );
	}

	/** @return array<int,string> Source files make-pot scans (SPEC 9). */
	private static function source_files(): array {
		$files = [ MAGICAUTH_DIR . 'magicauth.php' ];
		$it    = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( MAGICAUTH_DIR . 'includes', \FilesystemIterator::SKIP_DOTS ) );
		foreach ( $it as $file ) {
			$path = (string) $file;
			if ( str_ends_with( $path, '.php' ) && false === strpos( $path, '/ThirdParty/' ) ) {
				$files[] = $path;
			}
		}
		return array_merge( $files, (array) glob( MAGICAUTH_DIR . 'templates/*.php' ) );
	}

	/** @return array<int,string> sprintf placeholders, sorted. */
	private static function placeholders( string $text ): array {
		preg_match_all( '/%(?:\d+\$)?[sd]/', $text, $m );
		$out = $m[0];
		sort( $out );
		return $out;
	}

	/* ------------------------------------------------------------- catalogue */

	public function test_pot_carries_every_source_msgid(): void {
		$ids = [];
		foreach ( Po::entries( self::pot() ) as $entry ) {
			$ids[ $entry['id'] ] = true;
			if ( null !== $entry['plural'] ) {
				$ids[ $entry['plural'] ] = true;
			}
		}
		$checked = 0;
		foreach ( self::source_files() as $file ) {
			foreach ( Po::source_msgids( $file ) as $msgid ) {
				$this->assertArrayHasKey( $msgid, $ids, 'missing from the .pot: ' . $msgid . ' (' . basename( $file ) . ')' );
				++$checked;
			}
		}
		$this->assertGreaterThan( 350, $checked );
		$this->assertArrayHasKey( 'Passkeys saved in your browser or password manager are not removed by this site. Delete them there.', $ids );
	}

	public function test_nl_translates_every_msgid(): void {
		$nl      = Po::keyed( self::po( 'nl_NL' ) );
		$missing = [];
		$count   = 0;
		foreach ( Po::entries( self::pot() ) as $entry ) {
			if ( self::is_header_meta( $entry ) ) {
				continue;
			}
			$key = Po::key( $entry );
			$this->assertArrayHasKey( $key, $nl, $key );
			$this->assertNotContains( 'fuzzy', $nl[ $key ]['flags'], $key );
			$forms = null !== $entry['plural'] ? 2 : 1;
			$this->assertCount( $forms, $nl[ $key ]['str'], $key );
			foreach ( $nl[ $key ]['str'] as $str ) {
				if ( '' === $str ) {
					$missing[] = $key;
				}
			}
			++$count;
		}
		$this->assertSame( [], $missing, 'untranslated in nl_NL' );
		$this->assertGreaterThan( 380, $count );
	}

	public function test_nl_keeps_every_placeholder(): void {
		foreach ( Po::entries( self::po( 'nl_NL' ) ) as $entry ) {
			if ( [] === array_filter( $entry['str'] ) ) {
				continue;
			}
			$this->assertSame( self::placeholders( $entry['id'] ), self::placeholders( $entry['str'][0] ), $entry['id'] );
			if ( null !== $entry['plural'] ) {
				$this->assertSame( self::placeholders( $entry['plural'] ), self::placeholders( $entry['str'][1] ), $entry['plural'] );
			}
		}
	}

	public function test_de_and_es_carry_every_msgid(): void {
		$pot = array_keys( Po::keyed( self::pot() ) );
		sort( $pot );
		foreach ( [ 'de_DE', 'es_ES' ] as $locale ) {
			$po = array_keys( Po::keyed( self::po( $locale ) ) );
			sort( $po );
			$this->assertSame( $pot, $po, $locale );
			// The new strings fall back to English there (SPEC 9).
			$sign_in = Po::keyed( self::po( $locale ) )['Sign in with a passkey'];
			$this->assertSame( [ '' ], $sign_in['str'], $locale );
		}
		$this->assertSame( $pot, array_values( array_unique( $pot ) ) );
	}

	/** @return array<string,array{string}> */
	public static function locales(): array {
		return [
			'nl_NL' => [ 'nl_NL' ],
			'de_DE' => [ 'de_DE' ],
			'es_ES' => [ 'es_ES' ],
		];
	}

	/** @dataProvider locales */
	public function test_l10n_php_matches_the_po( string $locale ): void {
		$expected = [];
		foreach ( Po::entries( self::po( $locale ) ) as $entry ) {
			if ( [] !== $entry['str'] && '' !== $entry['str'][0] ) {
				$expected[ Po::key( $entry ) ] = implode( "\0", $entry['str'] );
			}
		}
		$php = require self::LANGUAGES . 'magicauth-' . $locale . '.l10n.php';
		$this->assertSame( 'magicauth', $php['domain'] );
		$this->assertSame( $locale, $php['language'] );
		$this->assertSame( 'nplurals=2; plural=(n != 1);', $php['plural-forms'] );
		ksort( $expected );
		$messages = $php['messages'];
		ksort( $messages );
		$this->assertSame( $expected, $messages );
	}

	/** @dataProvider locales */
	public function test_admin_script_json_matches_the_po( string $locale ): void {
		$expected = [];
		foreach ( Po::referenced_from( Po::entries( self::po( $locale ) ), self::ADMIN_JS ) as $entry ) {
			$expected[ $entry['id'] ] = $entry['str'];
		}
		$this->assertNotSame( [], $expected );
		// WordPress looks the file up by md5 of the script path relative to the plugin.
		$json = json_decode( (string) file_get_contents( self::LANGUAGES . 'magicauth-' . $locale . '-' . md5( self::ADMIN_JS ) . '.json' ), true );
		$this->assertSame( self::ADMIN_JS, $json['source'] );
		$messages = $json['locale_data']['messages'];
		unset( $messages[''] );
		ksort( $expected );
		ksort( $messages );
		$this->assertSame( $expected, $messages );
	}

	/* --------------------------------------------------- Q2 term (D-40) */

	public function test_nl_uses_the_loanword_passkey(): void {
		$checked = 0;
		foreach ( Po::entries( self::po( 'nl_NL' ) ) as $entry ) {
			if ( false === stripos( $entry['id'], 'passkey' ) ) {
				continue;
			}
			foreach ( $entry['str'] as $str ) {
				$this->assertStringContainsStringIgnoringCase( 'passkey', $str, $entry['id'] );
			}
			++$checked;
		}
		$this->assertGreaterThan( 80, $checked );
	}

	public function test_nl_glosses_the_term_once_in_p2_m2_and_the_added_email(): void {
		$glossed = [];
		foreach ( Po::entries( self::po( 'nl_NL' ) ) as $entry ) {
			$str = implode( "\n", $entry['str'] );
			if ( 1 !== preg_match( '/toegangssleutel|wachtwoordsleutel/i', $str ) ) {
				continue;
			}
			$glossed[] = $entry['id'];
			$this->assertSame( 1, substr_count( $str, self::GLOSS ), $entry['id'] );
			$this->assertDoesNotMatchRegularExpression( '/toegangssleutel|wachtwoordsleutel/i', str_replace( self::GLOSS, '', $str ), 'only inside the gloss: ' . $entry['id'] );
		}
		sort( $glossed );
		$expected = self::GLOSSED;
		sort( $expected );
		$this->assertSame( $expected, $glossed );
	}
}
