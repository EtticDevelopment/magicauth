<?php
/**
 * Minimal WordPress function shims for model-layer tests.
 *
 * Behaves enough like WP for TokenManager/Throttle/Controller and the passkey
 * module. Anything that touches HTTP, mail, the cache layer, or the
 * option/usermeta tables is stubbed in-process. Where a stub ports core
 * behaviour, the core function it mirrors is named (WordPress 7.0.4 tree).
 *
 * Toggles live in $magicauth_test_state (all optional, reset per test):
 * - home, siteurl (base URLs; scheme, host, port, path), is_ssl, force_ssl_admin
 * - current_user, session_token, doing_ajax, redirect_throws, auth_cookie_throws
 * - multisite, subdomain_install, sites, spammy_users, super_admins
 * - posts[ id ] = [ status, type, permalink ], timezone_string
 * - add_user_meta_race (callable run once between COUNT and INSERT)
 * - get_users_queue (results get_users() returns first, one per call); get_users_calls, read back by tests
 * - cron[ hook ] (wp_schedule_event), cache_deletes (wp_cache_delete calls), read back by tests
 * - passwords[ login ] = [ password, user ID ] (wp_authenticate), reset_keys[ login ] = [ key, user ID ]
 *   (check_password_reset_key); password_resets (reset_password calls), read back by tests
 * - stylesheet_directory, template_directory (theme template overrides); enqueued_styles, enqueued_scripts,
 *   inline_scripts, style_data, login_header_calls, login_footer_calls, read back by tests
 * - settings_errors (add_settings_error calls); cookies and headers (Passkeys\Http seams), read back by tests
 * - locale_switches (switch_to_locale calls), jitter_calls (magicauth_jitter), read back by tests
 * - home_url() and site_url() apply their core filters, so a theme filter can move the site address
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

use MagicAuth\Tests\Stubs\JsonResponseSent;
use MagicAuth\Tests\Stubs\RedirectSent;

global $magicauth_test_state;
$magicauth_test_state = [
	'options'    => [],
	'usermeta'   => [],
	'transients' => [],
	'users'      => [],
	'actions'    => [],
	'filters'    => [],
];

if ( ! function_exists( 'wp_salt' ) ) {
	function wp_salt( string $scheme = 'auth' ): string {
		return 'magicauth-test-salt-' . $scheme;
	}
}

if ( ! function_exists( 'current_time' ) ) {
	function current_time( string $type = 'mysql', $gmt = false ): string {
		unset( $type, $gmt );
		return gmdate( 'Y-m-d H:i:s' );
	}
}

if ( ! function_exists( 'get_option' ) ) {
	function get_option( string $option, $default = false ) {
		global $magicauth_test_state;
		return array_key_exists( $option, $magicauth_test_state['options'] )
			? $magicauth_test_state['options'][ $option ]
			: $default;
	}
}

if ( ! function_exists( 'update_option' ) ) {
	function update_option( string $option, $value, $autoload = null ): bool {
		unset( $autoload );
		global $magicauth_test_state;
		$magicauth_test_state['options'][ $option ] = $value;
		return true;
	}
}

if ( ! function_exists( 'add_option' ) ) {
	function add_option( string $option, $value ): bool {
		global $magicauth_test_state;
		if ( array_key_exists( $option, $magicauth_test_state['options'] ) ) {
			return false;
		}
		$magicauth_test_state['options'][ $option ] = $value;
		return true;
	}
}

if ( ! function_exists( 'delete_option' ) ) {
	/** Also deletes a row written to wp_options by raw SQL (the upgrade lock), as core's DELETE does. */
	function delete_option( string $option ): bool {
		global $magicauth_test_state, $wpdb;
		unset( $magicauth_test_state['options'][ $option ] );
		if ( isset( $wpdb ) ) {
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s", $option ) );
		}
		return true;
	}
}

/*
 * User meta. The first row of a key lives in usermeta[ id ][ key ] (tests read
 * and seed it directly); further rows added by add_user_meta() without
 * $unique live in usermeta_extra[ id ][ key ][]. Return shapes follow core
 * get_metadata(): single -> first value or '', not single -> list of values.
 */

if ( ! function_exists( 'get_user_meta' ) ) {
	function get_user_meta( int $user_id, string $key = '', bool $single = false ) {
		global $magicauth_test_state;
		$meta  = $magicauth_test_state['usermeta'][ $user_id ] ?? [];
		$extra = $magicauth_test_state['usermeta_extra'][ $user_id ] ?? [];
		if ( '' === $key ) {
			$out = [];
			foreach ( $meta as $k => $v ) {
				$out[ $k ] = array_merge( [ $v ], $extra[ $k ] ?? [] );
			}
			return $out;
		}
		if ( ! array_key_exists( $key, $meta ) ) {
			return $single ? '' : [];
		}
		return $single ? $meta[ $key ] : array_merge( [ $meta[ $key ] ], $extra[ $key ] ?? [] );
	}
}

if ( ! function_exists( 'update_user_meta' ) ) {
	function update_user_meta( int $user_id, string $key, $value ): bool {
		global $magicauth_test_state;
		$magicauth_test_state['usermeta'][ $user_id ][ $key ] = $value;
		// Core updates every row of the key when no previous value is given.
		if ( ! empty( $magicauth_test_state['usermeta_extra'][ $user_id ][ $key ] ) ) {
			$magicauth_test_state['usermeta_extra'][ $user_id ][ $key ] = array_fill( 0, count( $magicauth_test_state['usermeta_extra'][ $user_id ][ $key ] ), $value );
		}
		return true;
	}
}

if ( ! function_exists( 'add_user_meta' ) ) {
	/**
	 * Core add_metadata(): with $unique, SELECT COUNT(*) then INSERT, not atomic.
	 * $magicauth_test_state['add_user_meta_race'] runs once between the two.
	 *
	 * @return int|false Meta ID or false.
	 */
	function add_user_meta( int $user_id, string $key, $value, bool $unique = false ) {
		global $magicauth_test_state;
		if ( $unique && array_key_exists( $key, $magicauth_test_state['usermeta'][ $user_id ] ?? [] ) ) {
			return false;
		}
		if ( isset( $magicauth_test_state['add_user_meta_race'] ) && is_callable( $magicauth_test_state['add_user_meta_race'] ) ) {
			$race = $magicauth_test_state['add_user_meta_race'];
			unset( $magicauth_test_state['add_user_meta_race'] );
			$race( $user_id, $key, $value );
		}
		if ( array_key_exists( $key, $magicauth_test_state['usermeta'][ $user_id ] ?? [] ) ) {
			$magicauth_test_state['usermeta_extra'][ $user_id ][ $key ][] = $value;
		} else {
			$magicauth_test_state['usermeta'][ $user_id ][ $key ] = $value;
		}
		$magicauth_test_state['meta_id'] = ( $magicauth_test_state['meta_id'] ?? 0 ) + 1;
		return $magicauth_test_state['meta_id'];
	}
}

if ( ! function_exists( 'delete_user_meta' ) ) {
	function delete_user_meta( int $user_id, string $key, $value = '' ): bool {
		global $magicauth_test_state;
		if ( ! array_key_exists( $key, $magicauth_test_state['usermeta'][ $user_id ] ?? [] ) ) {
			return false;
		}
		if ( '' === $value || null === $value || false === $value ) {
			unset( $magicauth_test_state['usermeta'][ $user_id ][ $key ], $magicauth_test_state['usermeta_extra'][ $user_id ][ $key ] );
			return true;
		}
		$rows = array_merge( [ $magicauth_test_state['usermeta'][ $user_id ][ $key ] ], $magicauth_test_state['usermeta_extra'][ $user_id ][ $key ] ?? [] );
		$keep = array_values( array_filter( $rows, static fn( $row ) => $row != $value ) ); // phpcs:ignore Universal.Operators.StrictComparisons.LooseNotEqual -- core compares meta values as strings.
		if ( count( $keep ) === count( $rows ) ) {
			return false;
		}
		unset( $magicauth_test_state['usermeta'][ $user_id ][ $key ], $magicauth_test_state['usermeta_extra'][ $user_id ][ $key ] );
		if ( [] !== $keep ) {
			$magicauth_test_state['usermeta'][ $user_id ][ $key ] = array_shift( $keep );
			if ( [] !== $keep ) {
				$magicauth_test_state['usermeta_extra'][ $user_id ][ $key ] = $keep;
			}
		}
		return true;
	}
}

if ( ! function_exists( 'delete_metadata' ) ) {
	/** Core delete_metadata() for meta type 'user' only; $delete_all ignores $object_id. */
	function delete_metadata( string $meta_type, int $object_id, string $meta_key, $meta_value = '', bool $delete_all = false ): bool {
		global $magicauth_test_state;
		$magicauth_test_state['delete_metadata_calls'][] = func_get_args();
		if ( 'user' !== $meta_type ) {
			return false;
		}
		if ( ! $delete_all ) {
			return delete_user_meta( $object_id, $meta_key, $meta_value );
		}
		$deleted = false;
		foreach ( array_keys( $magicauth_test_state['usermeta'] ) as $user_id ) {
			$deleted = delete_user_meta( (int) $user_id, $meta_key, $meta_value ) || $deleted;
		}
		return $deleted;
	}
}

if ( ! function_exists( 'get_userdata' ) ) {
	function get_userdata( int $user_id ) {
		global $magicauth_test_state;
		return $magicauth_test_state['users'][ $user_id ] ?? false;
	}
}

if ( ! function_exists( 'get_user_by' ) ) {
	function get_user_by( string $field, $value ) {
		global $magicauth_test_state;
		foreach ( $magicauth_test_state['users'] as $user ) {
			if ( 'email' === $field && strcasecmp( $user->user_email, (string) $value ) === 0 ) {
				return $user;
			}
			if ( 'id' === $field && $user->ID === (int) $value ) {
				return $user;
			}
			if ( 'login' === $field && '' !== $user->user_login && $user->user_login === (string) $value ) {
				return $user;
			}
		}
		return false;
	}
}

if ( ! function_exists( 'get_users' ) ) {
	/**
	 * Subset of core get_users(): meta_key/meta_value/meta_compare, meta_query
	 * (AND of clauses with key, value, compare '=' | '!=' | 'EXISTS' | 'NOT EXISTS'),
	 * include, exclude, number, fields 'ID' (numeric strings, as core) or 'all'.
	 *
	 * @param array<string,mixed> $args
	 * @return array<int,mixed>
	 */
	function get_users( array $args = [] ): array {
		global $magicauth_test_state;
		$magicauth_test_state['get_users_calls'][] = $args;
		if ( ! empty( $magicauth_test_state['get_users_queue'] ) ) {
			return (array) array_shift( $magicauth_test_state['get_users_queue'] );
		}
		$clauses = [];
		if ( isset( $args['meta_key'] ) ) {
			$clauses[] = [
				'key'     => (string) $args['meta_key'],
				'value'   => $args['meta_value'] ?? null,
				'compare' => $args['meta_compare'] ?? ( isset( $args['meta_value'] ) ? '=' : 'EXISTS' ),
			];
		}
		foreach ( (array) ( $args['meta_query'] ?? [] ) as $k => $clause ) {
			if ( 'relation' === $k || ! is_array( $clause ) || ! isset( $clause['key'] ) ) {
				continue;
			}
			$clauses[] = [
				'key'     => (string) $clause['key'],
				'value'   => $clause['value'] ?? null,
				'compare' => $clause['compare'] ?? ( isset( $clause['value'] ) ? '=' : 'EXISTS' ),
			];
		}

		$users = $magicauth_test_state['users'];
		ksort( $users );
		$out = [];
		foreach ( $users as $id => $user ) {
			if ( isset( $args['include'] ) && ! in_array( (int) $id, array_map( 'intval', (array) $args['include'] ), true ) ) {
				continue;
			}
			if ( isset( $args['exclude'] ) && in_array( (int) $id, array_map( 'intval', (array) $args['exclude'] ), true ) ) {
				continue;
			}
			$match = true;
			foreach ( $clauses as $clause ) {
				$values = get_user_meta( (int) $id, $clause['key'] );
				$exists = [] !== $values;
				switch ( strtoupper( (string) $clause['compare'] ) ) {
					case 'EXISTS':
						$ok = $exists;
						break;
					case 'NOT EXISTS':
						$ok = ! $exists;
						break;
					case '!=':
						$ok = $exists && ! in_array( (string) $clause['value'], array_map( 'strval', $values ), true );
						break;
					default:
						$ok = in_array( (string) $clause['value'], array_map( 'strval', $values ), true );
						break;
				}
				if ( ! $ok ) {
					$match = false;
					break;
				}
			}
			if ( $match ) {
				$out[] = $user;
			}
		}
		if ( isset( $args['number'] ) && (int) $args['number'] > 0 ) {
			$out = array_slice( $out, 0, (int) $args['number'] );
		}
		$fields = $args['fields'] ?? 'all';
		if ( 'ID' === $fields || 'ids' === $fields ) {
			return array_map( static fn( $u ) => (string) $u->ID, $out );
		}
		return $out;
	}
}

if ( ! function_exists( 'get_transient' ) ) {
	function get_transient( string $key ) {
		global $magicauth_test_state;
		$entry = $magicauth_test_state['transients'][ $key ] ?? null;
		if ( null === $entry ) {
			return false;
		}
		if ( $entry['expires'] > 0 && $entry['expires'] < time() ) {
			unset( $magicauth_test_state['transients'][ $key ] );
			return false;
		}
		return $entry['value'];
	}
}

if ( ! function_exists( 'set_transient' ) ) {
	function set_transient( string $key, $value, int $ttl = 0 ): bool {
		global $magicauth_test_state, $wpdb;
		$expires = $ttl > 0 ? time() + $ttl : 0;
		$magicauth_test_state['transients'][ $key ] = [
			'value'   => $value,
			'expires' => $expires,
		];
		// Mirror into wp_options so SQL enumeration patterns
		// (`SELECT option_name ... LIKE '_transient_...'`) see the same
		// keys production would. Real WP transients live in wp_options.
		// We mirror BOTH the value row and the timeout row — production WP
		// writes both, and tests querying `_transient_timeout_*` need the
		// timeout row too (otherwise R-1-style TTL assertions silently skip).
		if ( isset( $wpdb ) ) {
			$wpdb->query(
				$wpdb->prepare(
					"INSERT OR REPLACE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')",
					'_transient_' . $key,
					(string) ( is_scalar( $value ) ? $value : serialize( $value ) ) // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize
				)
			);
			if ( $expires > 0 ) {
				$wpdb->query(
					$wpdb->prepare(
						"INSERT OR REPLACE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')",
						'_transient_timeout_' . $key,
						(string) $expires
					)
				);
			}
		}
		return true;
	}
}

if ( ! function_exists( 'delete_transient' ) ) {
	function delete_transient( string $key ): bool {
		global $magicauth_test_state, $wpdb;
		unset( $magicauth_test_state['transients'][ $key ] );
		if ( isset( $wpdb ) ) {
			$wpdb->query(
				$wpdb->prepare(
					"DELETE FROM {$wpdb->options} WHERE option_name = %s OR option_name = %s",
					'_transient_' . $key,
					'_transient_timeout_' . $key
				)
			);
		}
		return true;
	}
}

// Object-cache shims — present so admin_flush_all() can ask wp_using_ext_object_cache
// / wp_cache_supports / wp_cache_delete_multiple without exploding under test.
// All return "no external cache, nothing to do" by default; ThrottleTest can
// override per-call via $magicauth_test_state['ext_object_cache'].
if ( ! function_exists( 'wp_using_ext_object_cache' ) ) {
	function wp_using_ext_object_cache(): bool {
		global $magicauth_test_state;
		return ! empty( $magicauth_test_state['ext_object_cache'] );
	}
}

if ( ! function_exists( 'wp_cache_supports' ) ) {
	function wp_cache_supports( string $feature ): bool {
		global $magicauth_test_state;
		$supports = $magicauth_test_state['ext_cache_supports'] ?? [];
		return ! empty( $supports[ $feature ] );
	}
}

if ( ! function_exists( 'wp_cache_delete' ) ) {
	/**
	 * Records each call in cache_deletes as [ key, group ] and drops the
	 * entry from object_cache. For an options-group transient value row the
	 * next get_transient() reads the database, as in core: the transient's
	 * value is re-read from the wp_options mirror (Throttle's atomic UPDATE).
	 */
	function wp_cache_delete( $key, string $group = '' ): bool {
		global $magicauth_test_state, $wpdb;
		$magicauth_test_state['cache_deletes'][] = [ $key, $group ];
		unset( $magicauth_test_state['object_cache'][ $group ][ (string) $key ] );
		if ( 'options' === $group && is_string( $key ) && 0 === strpos( $key, '_transient_' ) && 0 !== strpos( $key, '_transient_timeout_' ) && isset( $wpdb ) ) {
			$name  = substr( $key, strlen( '_transient_' ) );
			$value = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $key ) );
			if ( null === $value ) {
				unset( $magicauth_test_state['transients'][ $name ] );
			} elseif ( isset( $magicauth_test_state['transients'][ $name ] ) ) {
				$magicauth_test_state['transients'][ $name ]['value'] = $value;
			}
		}
		return true;
	}
}

/*
 * Persistent object cache: $magicauth_test_state['object_cache'][ group ][ key ]
 * = [ value, expires ] (0: none). Only Throttle's passkey buckets use it, and
 * only while ext_object_cache is on. wp_cache_incr() keeps the expiry, as
 * Memcached and Redis do; fail_cache_incr makes the next incr drop the key
 * and return false (an eviction between two calls); cache_incr_broken makes
 * every incr return false and keep the key (a drop-in that cannot increment).
 */

if ( ! function_exists( 'magicauth_test_cache_entry' ) ) {
	/** @return array{0:mixed,1:int}|null Live entry, or null (expired ones are dropped). */
	function magicauth_test_cache_entry( string $key, string $group ): ?array {
		global $magicauth_test_state;
		$entry = $magicauth_test_state['object_cache'][ $group ][ $key ] ?? null;
		if ( null === $entry ) {
			return null;
		}
		if ( $entry[1] > 0 && $entry[1] <= time() ) {
			unset( $magicauth_test_state['object_cache'][ $group ][ $key ] );
			return null;
		}
		return $entry;
	}
}

if ( ! function_exists( 'wp_cache_get' ) ) {
	/** @return mixed|false */
	function wp_cache_get( $key, string $group = '' ) {
		$entry = magicauth_test_cache_entry( (string) $key, $group );
		return null === $entry ? false : $entry[0];
	}
}

if ( ! function_exists( 'wp_cache_add' ) ) {
	function wp_cache_add( $key, $data, string $group = '', int $expire = 0 ): bool {
		global $magicauth_test_state;
		if ( null !== magicauth_test_cache_entry( (string) $key, $group ) ) {
			return false;
		}
		$magicauth_test_state['object_cache'][ $group ][ (string) $key ] = [ $data, $expire > 0 ? time() + $expire : 0 ];
		return true;
	}
}

if ( ! function_exists( 'wp_cache_set' ) ) {
	function wp_cache_set( $key, $data, string $group = '', int $expire = 0 ): bool {
		global $magicauth_test_state;
		$magicauth_test_state['object_cache'][ $group ][ (string) $key ] = [ $data, $expire > 0 ? time() + $expire : 0 ];
		return true;
	}
}

if ( ! function_exists( 'wp_cache_incr' ) ) {
	/** @return int|false */
	function wp_cache_incr( $key, int $offset = 1, string $group = '' ) {
		global $magicauth_test_state;
		if ( ! empty( $magicauth_test_state['cache_incr_broken'] ) ) {
			return false;
		}
		if ( ! empty( $magicauth_test_state['fail_cache_incr'] ) ) {
			$magicauth_test_state['fail_cache_incr'] = false;
			unset( $magicauth_test_state['object_cache'][ $group ][ (string) $key ] );
			return false;
		}
		$entry = magicauth_test_cache_entry( (string) $key, $group );
		if ( null === $entry ) {
			return false;
		}
		$value = max( 0, (int) $entry[0] + $offset );
		$magicauth_test_state['object_cache'][ $group ][ (string) $key ][0] = $value;
		return $value;
	}
}

/*
 * WP-Cron. Events live in $magicauth_test_state['cron'][ hook ] =
 * [ timestamp, recurrence ] (one event per hook; MagicAuth passes no args).
 */

if ( ! function_exists( 'wp_next_scheduled' ) ) {
	/** @return int|false */
	function wp_next_scheduled( string $hook, array $args = [] ) {
		unset( $args );
		global $magicauth_test_state;
		return isset( $magicauth_test_state['cron'][ $hook ] ) ? (int) $magicauth_test_state['cron'][ $hook ][0] : false;
	}
}

if ( ! function_exists( 'wp_schedule_event' ) ) {
	/** Core refuses an unknown recurrence and returns false. */
	function wp_schedule_event( int $timestamp, string $recurrence, string $hook, array $args = [], bool $wp_error = false ): bool {
		unset( $args, $wp_error );
		global $magicauth_test_state;
		if ( ! in_array( $recurrence, [ 'hourly', 'twicedaily', 'daily', 'weekly' ], true ) ) {
			return false;
		}
		$magicauth_test_state['cron'][ $hook ]         = [ $timestamp, $recurrence ];
		$magicauth_test_state['cron_schedule_calls'][] = $hook;
		return true;
	}
}

if ( ! function_exists( 'wp_clear_scheduled_hook' ) ) {
	/** @return int Number of events removed. */
	function wp_clear_scheduled_hook( string $hook, array $args = [], bool $wp_error = false ): int {
		unset( $args, $wp_error );
		global $magicauth_test_state;
		$had = isset( $magicauth_test_state['cron'][ $hook ] );
		unset( $magicauth_test_state['cron'][ $hook ] );
		return $had ? 1 : 0;
	}
}

if ( ! function_exists( 'wp_cache_delete_multiple' ) ) {
	function wp_cache_delete_multiple( array $keys, string $group = '' ): array {
		global $magicauth_test_state;
		$magicauth_test_state['cache_delete_multiple_calls'][] = [ 'keys' => $keys, 'group' => $group ];
		$out = [];
		foreach ( $keys as $key ) {
			$out[ $key ] = true;
		}
		return $out;
	}
}

/*
 * Hooks. Callbacks stay in flat lists ($magicauth_test_state['actions'|'filters'][ $hook ])
 * so tests can inspect them; priority, insertion order and accepted_args live in
 * hook_meta. As in core, actions and filters share one registry when run:
 * do_action() and apply_filters() both see callbacks added by either function,
 * ordered by priority, then insertion. accepted_args slices the arguments.
 */

if ( ! function_exists( 'magicauth_test_hook_add' ) ) {
	function magicauth_test_hook_add( string $registry, string $hook, $callback, int $priority, int $accepted_args ): void {
		global $magicauth_test_state;
		$magicauth_test_state[ $registry ][ $hook ][] = $callback;
		$magicauth_test_state['hook_seq']             = ( $magicauth_test_state['hook_seq'] ?? 0 ) + 1;
		$index = array_key_last( $magicauth_test_state[ $registry ][ $hook ] );
		$magicauth_test_state['hook_meta'][ $registry ][ $hook ][ $index ] = [ $priority, $magicauth_test_state['hook_seq'], $accepted_args ];
	}
}

if ( ! function_exists( 'magicauth_test_hook_entries' ) ) {
	/** @return array<int,array{0:int,1:int,2:int,3:mixed,4:string,5:int}> priority, seq, accepted_args, callback, registry, index */
	function magicauth_test_hook_entries( string $hook ): array {
		global $magicauth_test_state;
		$entries = [];
		foreach ( [ 'filters', 'actions' ] as $registry ) {
			foreach ( $magicauth_test_state[ $registry ][ $hook ] ?? [] as $index => $callback ) {
				$meta      = $magicauth_test_state['hook_meta'][ $registry ][ $hook ][ $index ] ?? [ 10, 0, PHP_INT_MAX ];
				$entries[] = [ $meta[0], $meta[1], $meta[2], $callback, $registry, (int) $index ];
			}
		}
		usort(
			$entries,
			static function ( array $a, array $b ): int {
				return [ $a[0], $a[1] ] <=> [ $b[0], $b[1] ];
			}
		);
		return $entries;
	}
}

if ( ! function_exists( 'magicauth_test_hook_call' ) ) {
	/**
	 * @param array<int,mixed> $args
	 * @return mixed
	 */
	function magicauth_test_hook_call( $callback, int $accepted_args, array $args ) {
		if ( 0 === $accepted_args ) {
			return call_user_func( $callback );
		}
		if ( $accepted_args >= count( $args ) ) {
			return call_user_func_array( $callback, $args );
		}
		return call_user_func_array( $callback, array_slice( $args, 0, $accepted_args ) );
	}
}

if ( ! function_exists( 'magicauth_test_hook_remove' ) ) {
	/** Core remove_filter(): removes the callback at exactly $priority, from either registry. */
	function magicauth_test_hook_remove( string $hook, $callback, int $priority ): bool {
		global $magicauth_test_state;
		$removed = false;
		foreach ( [ 'filters', 'actions' ] as $registry ) {
			if ( ! isset( $magicauth_test_state[ $registry ][ $hook ] ) ) {
				continue;
			}
			$callbacks = [];
			$metas     = [];
			foreach ( $magicauth_test_state[ $registry ][ $hook ] as $index => $cb ) {
				$meta = $magicauth_test_state['hook_meta'][ $registry ][ $hook ][ $index ] ?? [ 10, 0, PHP_INT_MAX ];
				if ( $cb === $callback && $meta[0] === $priority ) {
					$removed = true;
					continue;
				}
				$callbacks[] = $cb;
				$metas[]     = $meta;
			}
			$magicauth_test_state[ $registry ][ $hook ]              = $callbacks;
			$magicauth_test_state['hook_meta'][ $registry ][ $hook ] = $metas;
		}
		return $removed;
	}
}

if ( ! function_exists( 'add_action' ) ) {
	function add_action( string $hook, $callback, int $priority = 10, int $accepted_args = 1 ): bool {
		magicauth_test_hook_add( 'actions', $hook, $callback, $priority, $accepted_args );
		return true;
	}
}

if ( ! function_exists( 'do_action' ) ) {
	function do_action( string $hook, ...$args ): void {
		global $magicauth_test_state;
		$magicauth_test_state['did_actions'][ $hook ] = ( $magicauth_test_state['did_actions'][ $hook ] ?? 0 ) + 1;
		if ( [] === $args ) {
			$args = [ '' ];
		}
		foreach ( magicauth_test_hook_entries( $hook ) as $entry ) {
			magicauth_test_hook_call( $entry[3], $entry[2], $args );
		}
	}
}

if ( ! function_exists( 'did_action' ) ) {
	function did_action( string $hook ): int {
		global $magicauth_test_state;
		return (int) ( $magicauth_test_state['did_actions'][ $hook ] ?? 0 );
	}
}

if ( ! function_exists( 'add_filter' ) ) {
	function add_filter( string $hook, $callback, int $priority = 10, int $accepted_args = 1 ): bool {
		magicauth_test_hook_add( 'filters', $hook, $callback, $priority, $accepted_args );
		return true;
	}
}

if ( ! function_exists( 'apply_filters' ) ) {
	function apply_filters( string $hook, $value, ...$args ) {
		foreach ( magicauth_test_hook_entries( $hook ) as $entry ) {
			$value = magicauth_test_hook_call( $entry[3], $entry[2], array_merge( [ $value ], $args ) );
		}
		return $value;
	}
}

if ( ! function_exists( 'remove_filter' ) ) {
	function remove_filter( string $hook, $callback, int $priority = 10 ): bool {
		return magicauth_test_hook_remove( $hook, $callback, $priority );
	}
}

if ( ! function_exists( 'remove_action' ) ) {
	function remove_action( string $hook, $callback, int $priority = 10 ): bool {
		return magicauth_test_hook_remove( $hook, $callback, $priority );
	}
}

if ( ! function_exists( 'has_filter' ) ) {
	/** Core has_filter(): priority of $callback, or (with no callback) whether any exists. */
	function has_filter( string $hook, $callback = false ) {
		$entries = magicauth_test_hook_entries( $hook );
		if ( false === $callback ) {
			return [] !== $entries;
		}
		foreach ( $entries as $entry ) {
			if ( $entry[3] === $callback ) {
				return $entry[0];
			}
		}
		return false;
	}
}

if ( ! function_exists( 'has_action' ) ) {
	function has_action( string $hook, $callback = false ) {
		return has_filter( $hook, $callback );
	}
}

/*
 * URLs. Bases come from $magicauth_test_state['home'] and ['siteurl']
 * (default https://example.test); schemes follow core set_url_scheme().
 */

if ( ! function_exists( 'is_ssl' ) ) {
	function is_ssl(): bool {
		global $magicauth_test_state;
		return ! empty( $magicauth_test_state['is_ssl'] );
	}
}

if ( ! function_exists( 'force_ssl_admin' ) ) {
	function force_ssl_admin(): bool {
		global $magicauth_test_state;
		return ! empty( $magicauth_test_state['force_ssl_admin'] );
	}
}

if ( ! function_exists( 'set_url_scheme' ) ) {
	/** Core set_url_scheme(). */
	function set_url_scheme( string $url, ?string $scheme = null ): string {
		if ( ! $scheme ) {
			$scheme = is_ssl() ? 'https' : 'http';
		} elseif ( in_array( $scheme, [ 'admin', 'login', 'login_post', 'rpc' ], true ) ) {
			$scheme = is_ssl() || force_ssl_admin() ? 'https' : 'http';
		} elseif ( 'http' !== $scheme && 'https' !== $scheme && 'relative' !== $scheme ) {
			$scheme = is_ssl() ? 'https' : 'http';
		}

		$url = trim( $url );
		if ( 0 === strpos( $url, '//' ) ) {
			$url = 'http:' . $url;
		}

		if ( 'relative' === $scheme ) {
			$url = ltrim( (string) preg_replace( '#^\w+://[^/]*#', '', $url ) );
			if ( '' !== $url && '/' === $url[0] ) {
				$url = '/' . ltrim( $url, "/ \t\n\r\0\x0B" );
			}
		} else {
			$url = (string) preg_replace( '#^\w+://#', $scheme . '://', $url );
		}
		return $url;
	}
}

if ( ! function_exists( 'home_url' ) ) {
	/** Core get_home_url(): keeps the stored scheme unless is_ssl() or an explicit scheme. */
	function home_url( string $path = '', ?string $scheme = null ): string {
		global $magicauth_test_state;
		$url = (string) ( $magicauth_test_state['home'] ?? 'https://example.test' );
		if ( ! in_array( $scheme, [ 'http', 'https', 'relative' ], true ) ) {
			$scheme = is_ssl() ? 'https' : (string) parse_url( $url, PHP_URL_SCHEME ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url
		}
		$orig_scheme = $scheme;
		$url         = set_url_scheme( $url, $scheme );
		if ( '' !== $path ) {
			$url .= '/' . ltrim( $path, '/' );
		}
		return (string) apply_filters( 'home_url', $url, $path, $orig_scheme, null );
	}
}

if ( ! function_exists( 'site_url' ) ) {
	/** Core get_site_url(): the scheme follows the request (set_url_scheme with null). */
	function site_url( string $path = '', ?string $scheme = null ): string {
		global $magicauth_test_state;
		$url = (string) ( $magicauth_test_state['siteurl'] ?? ( $magicauth_test_state['home'] ?? 'https://example.test' ) );
		$url = set_url_scheme( $url, $scheme );
		if ( '' !== $path ) {
			$url .= '/' . ltrim( $path, '/' );
		}
		return (string) apply_filters( 'site_url', $url, $path, $scheme, null );
	}
}

if ( ! function_exists( 'admin_url' ) ) {
	function admin_url( string $path = '', string $scheme = 'admin' ): string {
		$url = site_url( 'wp-admin/', $scheme );
		if ( '' !== $path ) {
			$url .= ltrim( $path, '/' );
		}
		return $url;
	}
}

if ( ! function_exists( 'wp_login_url' ) ) {
	function wp_login_url( string $redirect = '', bool $force_reauth = false ): string {
		$login_url = site_url( 'wp-login.php', 'login' );
		if ( '' !== $redirect ) {
			$login_url = add_query_arg( 'redirect_to', urlencode( $redirect ), $login_url );
		}
		if ( $force_reauth ) {
			$login_url = add_query_arg( 'reauth', '1', $login_url );
		}
		return (string) apply_filters( 'login_url', $login_url, $redirect, $force_reauth );
	}
}

if ( ! function_exists( 'wp_lostpassword_url' ) ) {
	function wp_lostpassword_url( string $redirect = '' ): string {
		$args = [ 'action' => 'lostpassword' ];
		if ( '' !== $redirect ) {
			$args['redirect_to'] = urlencode( $redirect );
		}
		$url = add_query_arg( $args, site_url( 'wp-login.php', 'login' ) );
		return (string) apply_filters( 'lostpassword_url', $url, $redirect );
	}
}

if ( ! function_exists( 'wp_logout_url' ) ) {
	function wp_logout_url( string $redirect = '' ): string {
		$args = [];
		if ( '' !== $redirect ) {
			$args['redirect_to'] = urlencode( $redirect );
		}
		$url = add_query_arg( $args, site_url( 'wp-login.php?action=logout', 'login' ) );
		$url = wp_nonce_url( $url, 'log-out' );
		return (string) apply_filters( 'logout_url', $url, $redirect );
	}
}

if ( ! function_exists( 'urlencode_deep' ) ) {
	function urlencode_deep( $value ) {
		if ( is_array( $value ) ) {
			return array_map( 'urlencode_deep', $value );
		}
		return is_scalar( $value ) ? urlencode( (string) $value ) : $value;
	}
}

if ( ! function_exists( '_http_build_query' ) ) {
	/** Core _http_build_query(). */
	function _http_build_query( $data, $prefix = null, $sep = null, $key = '', $urlencode = true ): string {
		$ret = [];
		foreach ( (array) $data as $k => $v ) {
			if ( $urlencode ) {
				$k = urlencode( (string) $k );
			}
			if ( is_int( $k ) && null !== $prefix ) {
				$k = $prefix . $k;
			}
			if ( ! empty( $key ) ) {
				$k = $key . '%5B' . $k . '%5D';
			}
			if ( null === $v ) {
				continue;
			} elseif ( false === $v ) {
				$v = '0';
			}
			if ( is_array( $v ) || is_object( $v ) ) {
				$ret[] = _http_build_query( $v, '', $sep, $k, $urlencode );
			} elseif ( $urlencode ) {
				$ret[] = $k . '=' . urlencode( (string) $v );
			} else {
				$ret[] = $k . '=' . $v;
			}
		}
		if ( null === $sep ) {
			$sep = ini_get( 'arg_separator.output' );
		}
		return implode( (string) $sep, $ret );
	}
}

if ( ! function_exists( 'build_query' ) ) {
	function build_query( $data ): string {
		return _http_build_query( $data, null, '&', '', false );
	}
}

if ( ! function_exists( 'wp_parse_str' ) ) {
	function wp_parse_str( $input_string, &$result ): void {
		parse_str( (string) $input_string, $result );
		$result = apply_filters( 'wp_parse_str', $result );
	}
}

if ( ! function_exists( 'add_query_arg' ) ) {
	/**
	 * Core add_query_arg(): ( key, value, url ), ( array, url ), or without url
	 * the current REQUEST_URI. Values are not encoded (core leaves that to callers).
	 */
	function add_query_arg( ...$args ): string {
		if ( is_array( $args[0] ) ) {
			$uri = ( count( $args ) < 2 || false === $args[1] ) ? (string) ( $_SERVER['REQUEST_URI'] ?? '' ) : (string) $args[1];
		} else {
			$uri = ( count( $args ) < 3 || false === $args[2] ) ? (string) ( $_SERVER['REQUEST_URI'] ?? '' ) : (string) $args[2];
		}

		$frag = strstr( $uri, '#' );
		if ( false !== $frag && '' !== $frag ) {
			$uri = substr( $uri, 0, -strlen( $frag ) );
		} else {
			$frag = '';
		}

		if ( 0 === stripos( $uri, 'http://' ) ) {
			$protocol = 'http://';
			$uri      = substr( $uri, 7 );
		} elseif ( 0 === stripos( $uri, 'https://' ) ) {
			$protocol = 'https://';
			$uri      = substr( $uri, 8 );
		} else {
			$protocol = '';
		}

		if ( false !== strpos( $uri, '?' ) ) {
			list( $base, $query ) = explode( '?', $uri, 2 );
			$base                .= '?';
		} elseif ( '' !== $protocol || false === strpos( $uri, '=' ) ) {
			$base  = $uri . '?';
			$query = '';
		} else {
			$base  = '';
			$query = $uri;
		}

		wp_parse_str( $query, $qs );
		$qs = urlencode_deep( $qs );
		if ( is_array( $args[0] ) ) {
			foreach ( $args[0] as $k => $v ) {
				$qs[ $k ] = $v;
			}
		} else {
			$qs[ $args[0] ] = $args[1];
		}

		foreach ( $qs as $k => $v ) {
			if ( false === $v ) {
				unset( $qs[ $k ] );
			}
		}

		$ret = build_query( $qs );
		$ret = trim( $ret, '?' );
		$ret = (string) preg_replace( '#=(&|$)#', '$1', $ret );
		$ret = $protocol . $base . $ret . $frag;
		$ret = rtrim( $ret, '?' );
		return str_replace( '?#', '#', $ret );
	}
}

if ( ! function_exists( 'remove_query_arg' ) ) {
	/** Core remove_query_arg(). */
	function remove_query_arg( $key, $query = false ): string {
		if ( is_array( $key ) ) {
			foreach ( $key as $k ) {
				$query = add_query_arg( $k, false, $query );
			}
			return (string) $query;
		}
		return add_query_arg( $key, false, $query );
	}
}

if ( ! function_exists( 'wp_parse_url' ) ) {
	function wp_parse_url( string $url, int $component = -1 ) {
		return $component === -1 ? parse_url( $url ) : parse_url( $url, $component ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url
	}
}

if ( ! function_exists( 'magicauth_test_locale' ) ) {
	/** Locale in effect: the last switch_to_locale() not yet restored, else determine_locale(). */
	function magicauth_test_locale(): string {
		global $magicauth_test_state;
		$stack = (array) ( $magicauth_test_state['locale_stack'] ?? [] );
		return [] !== $stack ? (string) end( $stack ) : determine_locale();
	}
}

if ( ! function_exists( 'magicauth_test_load_translations' ) ) {
	/**
	 * Load a shipped .l10n.php file as the translations of $locale (core's
	 * WP_Translation_File_PHP format: "ctx\4msgid" keys, plural forms joined
	 * by NUL under the singular).
	 */
	function magicauth_test_load_translations( string $locale, string $file ): void {
		global $magicauth_test_state;
		$data = require $file;
		$magicauth_test_state['translations'][ $locale ] = is_array( $data ) && is_array( $data['messages'] ?? null ) ? $data['messages'] : [];
	}
}

if ( ! function_exists( 'magicauth_test_gettext' ) ) {
	/**
	 * Translation of $text in the locale in effect, or null when none is
	 * loaded. Plural: core's nplurals=2 rule (n != 1) picks the form.
	 */
	function magicauth_test_gettext( string $text, string $context = '', ?int $number = null ): ?string {
		global $magicauth_test_state;
		$messages = $magicauth_test_state['translations'][ magicauth_test_locale() ] ?? null;
		if ( ! is_array( $messages ) ) {
			return null;
		}
		$key = '' !== $context ? $context . "\4" . $text : $text;
		if ( ! isset( $messages[ $key ] ) || '' === $messages[ $key ] ) {
			return null;
		}
		$forms = explode( "\0", (string) $messages[ $key ] );
		return null === $number ? $forms[0] : ( $forms[ 1 === $number ? 0 : 1 ] ?? $forms[0] );
	}
}

if ( ! function_exists( '__' ) ) {
	/** Untranslated unless translations of the locale in effect are loaded. */
	function __( string $text, string $domain = '' ): string {
		unset( $domain );
		return magicauth_test_gettext( $text ) ?? $text;
	}
}

if ( ! function_exists( '_n' ) ) {
	/** English plural rule, as core without a translation: singular only for exactly 1. */
	function _n( string $single, string $plural, int $number, string $domain = '' ): string {
		unset( $domain );
		return magicauth_test_gettext( $single, '', $number ) ?? ( 1 === $number ? $single : $plural );
	}
}

if ( ! function_exists( '_x' ) ) {
	/** Context ignored without a translation, as core. */
	function _x( string $text, string $context, string $domain = '' ): string {
		unset( $domain );
		return magicauth_test_gettext( $text, $context ) ?? $text;
	}
}

if ( ! function_exists( 'esc_attr' ) ) {
	function esc_attr( string $text ): string {
		return htmlspecialchars( $text, ENT_QUOTES );
	}
}

if ( ! function_exists( 'get_user_locale' ) ) {
	function get_user_locale( int $user_id = 0 ): string {
		global $magicauth_test_state;
		$user = $magicauth_test_state['users'][ $user_id ] ?? null;
		return $user && isset( $user->locale ) ? (string) $user->locale : 'en_US';
	}
}

if ( ! function_exists( 'get_locale' ) ) {
	function get_locale(): string {
		return 'en_US';
	}
}

if ( ! function_exists( 'determine_locale' ) ) {
	/** Request locale: $magicauth_test_state['locale'] (default en_US). */
	function determine_locale(): string {
		global $magicauth_test_state;
		return (string) ( $magicauth_test_state['locale'] ?? 'en_US' );
	}
}

if ( ! function_exists( 'get_available_languages' ) ) {
	/**
	 * Installed translations: $magicauth_test_state['available_languages']
	 * (default none, so only the built-in en_US exists).
	 *
	 * @return string[]
	 */
	function get_available_languages( $dir = null ): array {
		unset( $dir );
		global $magicauth_test_state;
		return array_values( (array) ( $magicauth_test_state['available_languages'] ?? [] ) );
	}
}

if ( ! function_exists( 'switch_to_locale' ) ) {
	/** Records each switch in locale_switches; the locale is in effect until restored. */
	function switch_to_locale( string $locale ): bool {
		global $magicauth_test_state;
		$magicauth_test_state['locale_switches'][] = $locale;
		$magicauth_test_state['locale_stack'][]    = $locale;
		return true;
	}
}

if ( ! function_exists( 'restore_previous_locale' ) ) {
	/** Counts restores in locale_restores. */
	function restore_previous_locale(): bool {
		global $magicauth_test_state;
		$magicauth_test_state['locale_restores'] = ( $magicauth_test_state['locale_restores'] ?? 0 ) + 1;
		if ( ! empty( $magicauth_test_state['locale_stack'] ) ) {
			array_pop( $magicauth_test_state['locale_stack'] );
		}
		return true;
	}
}

if ( ! function_exists( 'get_bloginfo' ) ) {
	function get_bloginfo( string $key = '' ): string {
		switch ( $key ) {
			case 'name':
				return 'Test Site';
			case 'admin_email':
				return 'admin@example.test';
			default:
				return '';
		}
	}
}

if ( ! function_exists( 'is_rtl' ) ) {
	function is_rtl(): bool {
		return false;
	}
}

if ( ! function_exists( 'is_email' ) ) {
	function is_email( string $email ) {
		return ( filter_var( $email, FILTER_VALIDATE_EMAIL ) !== false ) ? $email : false;
	}
}

if ( ! function_exists( 'sanitize_email' ) ) {
	function sanitize_email( string $email ): string {
		return trim( $email );
	}
}

if ( ! function_exists( 'wp_mail' ) ) {
	/** Records the mail; runs phpmailer_init like core, so the AltBody handler's output is recorded. */
	function wp_mail( $to, $subject, $message, $headers = '' ) {
		global $magicauth_test_state;
		$phpmailer = new class() {
			public string $Body    = ''; // phpcs:ignore WordPress.NamingConventions.ValidVariableName
			public string $AltBody = ''; // phpcs:ignore WordPress.NamingConventions.ValidVariableName
		};
		$phpmailer->Body = (string) $message; // phpcs:ignore WordPress.NamingConventions.ValidVariableName
		do_action( 'phpmailer_init', $phpmailer );
		$magicauth_test_state['mail'][] = [
			'to'       => $to,
			'subject'  => $subject,
			'message'  => $message,
			'headers'  => $headers,
			'alt_body' => $phpmailer->AltBody, // phpcs:ignore WordPress.NamingConventions.ValidVariableName
		];
		return $magicauth_test_state['wp_mail_return'] ?? true;
	}
}

if ( ! function_exists( 'wp_get_current_user' ) ) {
	function wp_get_current_user() {
		global $magicauth_test_state;
		$id = $magicauth_test_state['current_user'] ?? 0;
		return $magicauth_test_state['users'][ $id ] ?? new WP_User( 0, '' );
	}
}

if ( ! function_exists( 'get_current_user_id' ) ) {
	function get_current_user_id(): int {
		return (int) wp_get_current_user()->ID;
	}
}

if ( ! function_exists( 'is_user_logged_in' ) ) {
	function is_user_logged_in(): bool {
		global $magicauth_test_state;
		return ! empty( $magicauth_test_state['current_user'] );
	}
}

if ( ! function_exists( 'magicauth_test_user_can' ) ) {
	/** Capability check on core-built allcaps, with the edit_user meta cap mapped as before. */
	function magicauth_test_user_can( WP_User $user, string $cap, array $args ): bool {
		if ( 0 === $user->ID ) {
			return false;
		}
		$caps = magicauth_test_caps_for_user( $user );
		if ( 'edit_user' === $cap ) {
			$target_id = isset( $args[0] ) ? (int) $args[0] : 0;
			if ( $target_id === $user->ID ) {
				return true;
			}
			return ! empty( $caps['edit_users'] );
		}
		return ! empty( $caps[ $cap ] );
	}
}

if ( ! function_exists( 'current_user_can' ) ) {
	function current_user_can( string $cap, ...$args ) {
		return magicauth_test_user_can( wp_get_current_user(), $cap, $args );
	}
}

if ( ! function_exists( 'user_can' ) ) {
	function user_can( $user, string $cap, ...$args ): bool {
		if ( ! $user instanceof WP_User ) {
			$user = get_userdata( (int) $user );
		}
		return $user instanceof WP_User && magicauth_test_user_can( $user, $cap, $args );
	}
}

if ( ! function_exists( 'is_super_admin' ) ) {
	/** Core is_super_admin(): multisite -> login listed in super_admins; else the delete_users cap. */
	function is_super_admin( $user_id = false ): bool {
		global $magicauth_test_state;
		$user = ( false === $user_id || 0 === (int) $user_id ) ? wp_get_current_user() : get_userdata( (int) $user_id );
		if ( ! $user instanceof WP_User || ! $user->exists() ) {
			return false;
		}
		if ( is_multisite() ) {
			return in_array( $user->user_login, (array) ( $magicauth_test_state['super_admins'] ?? [] ), true );
		}
		return ! empty( magicauth_test_caps_for_user( $user )['delete_users'] );
	}
}

if ( ! function_exists( 'wp_roles' ) ) {
	function wp_roles() {
		global $magicauth_test_state;
		if ( empty( $magicauth_test_state['roles'] ) ) {
			$magicauth_test_state['roles'] = new class() {
				public array $roles = [
					'subscriber'  => [ 'name' => 'Subscriber', 'capabilities' => [ 'read' => true ] ],
					'editor'      => [ 'name' => 'Editor',     'capabilities' => [ 'read' => true, 'edit_posts' => true, 'edit_others_posts' => true ] ],
					'administrator' => [ 'name' => 'Administrator', 'capabilities' => [ 'read' => true, 'edit_posts' => true, 'edit_others_posts' => true, 'edit_users' => true, 'list_users' => true, 'create_users' => true, 'delete_users' => true, 'remove_users' => true, 'manage_options' => true, 'promote_users' => true ] ],
				];

				public function get_role( string $slug ) {
					if ( ! isset( $this->roles[ $slug ] ) ) {
						return null;
					}
					$caps = $this->roles[ $slug ]['capabilities'];
					return new class( $caps ) {
						public array $capabilities;
						public function __construct( array $caps ) { $this->capabilities = $caps; }
					};
				}

				public function is_role( string $slug ): bool {
					return isset( $this->roles[ $slug ] );
				}

				public function get_names(): array {
					$out = [];
					foreach ( $this->roles as $slug => $info ) {
						$out[ $slug ] = $info['name'];
					}
					return $out;
				}
			};
		}
		return $magicauth_test_state['roles'];
	}
}

if ( ! function_exists( 'magicauth_test_caps_for_user' ) ) {
	/** Core-built allcaps (role caps, then role-name keys and direct caps), recomputed per call. */
	function magicauth_test_caps_for_user( WP_User $user ): array {
		return $user->get_role_caps();
	}
}

if ( ! function_exists( 'magicauth_test_login_as' ) ) {
	function magicauth_test_login_as( int $user_id ): void {
		global $magicauth_test_state;
		$magicauth_test_state['current_user'] = $user_id;
	}
}

if ( ! function_exists( 'esc_html' ) ) {
	function esc_html( string $text ): string {
		return htmlspecialchars( $text, ENT_QUOTES );
	}
}

if ( ! function_exists( 'wp_kses' ) ) {
	function wp_kses( string $string, array $allowed_html = [], array $allowed_protocols = [] ): string {
		unset( $allowed_html, $allowed_protocols );
		return $string;
	}
}

if ( ! function_exists( 'esc_html_e' ) ) {
	function esc_html_e( string $text, string $domain = '' ): void {
		echo esc_html( __( $text, $domain ) );
	}
}

if ( ! function_exists( 'esc_html__' ) ) {
	function esc_html__( string $text, string $domain = '' ): string {
		return esc_html( __( $text, $domain ) );
	}
}

if ( ! function_exists( 'esc_attr_e' ) ) {
	function esc_attr_e( string $text, string $domain = '' ): void {
		echo esc_attr( __( $text, $domain ) );
	}
}

if ( ! function_exists( 'esc_url' ) ) {
	/**
	 * Core esc_url() drops a URL whose scheme is outside wp_allowed_protocols()
	 * (javascript:, data:, ...) and returns ''. The stub applies the same
	 * protocol filter through esc_url_raw(); the output encoding stays the
	 * plain htmlspecialchars() the golden renders were recorded with.
	 */
	function esc_url( string $url, ?array $protocols = null ): string {
		if ( '' !== $url && '' === esc_url_raw( $url, $protocols ) ) {
			return '';
		}
		return htmlspecialchars( $url, ENT_QUOTES );
	}
}

if ( ! function_exists( 'esc_url_raw' ) ) {
	/**
	 * Core esc_url_raw() (esc_url() in 'db' context): no entity encoding,
	 * http:// prepended to a scheme-less non-relative URL, '' for a scheme
	 * outside wp_allowed_protocols(). Brackets are not percent-encoded.
	 */
	function esc_url_raw( string $url, ?array $protocols = null ): string {
		if ( '' === $url ) {
			return $url;
		}
		$url = str_replace( ' ', '%20', ltrim( $url ) );
		$url = (string) preg_replace( '|[^a-z0-9-~+_.?#=!&;,/:%@$\|*\'()\[\]\x80-\xff]|i', '', $url );
		if ( '' === $url ) {
			return $url;
		}
		if ( 0 !== stripos( $url, 'mailto:' ) ) {
			do {
				$before = $url;
				$url    = str_ireplace( [ '%0d', '%0a' ], '', $url );
			} while ( $before !== $url );
		}
		$url = str_replace( ';//', '://', $url );
		if ( false === strpos( $url, ':' ) && ! in_array( $url[0], [ '/', '#', '?' ], true ) && ! preg_match( '/^[a-z0-9-]+?\.php/i', $url ) ) {
			$url = ( is_array( $protocols ) && 'https' === reset( $protocols ) ? 'https://' : 'http://' ) . $url;
		}
		if ( '/' !== $url[0] && preg_match( '/^([^:\/?#]+):/', $url, $m ) ) {
			$allowed = $protocols ?? [ 'http', 'https', 'ftp', 'ftps', 'mailto', 'news', 'irc', 'irc6', 'ircs', 'gopher', 'nntp', 'feed', 'telnet', 'mms', 'rtsp', 'sms', 'svn', 'tel', 'fax', 'xmpp', 'webcal', 'urn' ];
			if ( ! in_array( strtolower( $m[1] ), $allowed, true ) ) {
				return '';
			}
		}
		return $url;
	}
}

if ( ! defined( 'EXTR_SKIP' ) ) {
	// EXTR_SKIP is a PHP built-in; this exists only to satisfy stubbing.
	define( 'EXTR_SKIP', 1 );
}

if ( ! function_exists( 'wp_set_auth_cookie' ) ) {
	/**
	 * Core signature. Without $token a session is created through
	 * WP_Session_Tokens::create(), so attach_session_information stamps are
	 * observable in $magicauth_test_state['sessions']. A Throwable in
	 * $magicauth_test_state['auth_cookie_throws'] is thrown first.
	 */
	function wp_set_auth_cookie( int $user_id, bool $remember = false, $secure = '', string $token = '' ): void {
		global $magicauth_test_state;
		if ( isset( $magicauth_test_state['auth_cookie_throws'] ) && $magicauth_test_state['auth_cookie_throws'] instanceof \Throwable ) {
			throw $magicauth_test_state['auth_cookie_throws'];
		}
		$expiration = time() + ( $remember ? 14 * DAY_IN_SECONDS : 2 * DAY_IN_SECONDS );
		if ( '' === $token ) {
			$token = WP_Session_Tokens::get_instance( $user_id )->create( $expiration );
		}
		$magicauth_test_state['auth_cookie_set_for'] = $user_id;
		$magicauth_test_state['auth_cookies'][]      = [
			'user_id'  => $user_id,
			'remember' => $remember,
			'secure'   => $secure,
			'token'    => $token,
		];
	}
}

if ( ! function_exists( 'wp_get_session_token' ) ) {
	function wp_get_session_token(): string {
		global $magicauth_test_state;
		return (string) ( $magicauth_test_state['session_token'] ?? '' );
	}
}

if ( ! function_exists( 'wp_destroy_other_sessions' ) ) {
	function wp_destroy_other_sessions(): void {
		$token = wp_get_session_token();
		if ( '' !== $token ) {
			WP_Session_Tokens::get_instance( get_current_user_id() )->destroy_others( $token );
		}
	}
}

if ( ! function_exists( 'wp_set_current_user' ) ) {
	function wp_set_current_user( int $user_id ) {
		global $magicauth_test_state;
		$magicauth_test_state['current_user'] = $user_id;
		return $magicauth_test_state['users'][ $user_id ] ?? new WP_User( 0, '' );
	}
}

/*
 * Redirects and responses. wp_send_json*() and a failed check_ajax_referer()
 * always throw JsonResponseSent (the real ones exit). wp_safe_redirect() and
 * wp_redirect() record and return true, as the 1.0.5 Controller tests expect;
 * with $magicauth_test_state['redirect_throws'] they throw RedirectSent.
 */

if ( ! function_exists( 'wp_kses_no_null' ) ) {
	function wp_kses_no_null( string $content ): string {
		$content = (string) preg_replace( '/[\x00-\x08\x0B\x0C\x0E-\x1F]/', '', $content );
		return (string) preg_replace( '/\\\\+0+/', '', $content );
	}
}

if ( ! function_exists( '_deep_replace' ) ) {
	function _deep_replace( $search, $subject ): string {
		$subject = (string) $subject;
		$count   = 1;
		while ( $count ) {
			$subject = str_replace( $search, '', $subject, $count );
		}
		return $subject;
	}
}

if ( ! function_exists( 'wp_sanitize_redirect' ) ) {
	/** Core wp_sanitize_redirect(). */
	function wp_sanitize_redirect( string $location ): string {
		$location = str_replace( ' ', '%20', $location );
		$regex    = '/
		(
			(?: [\xC2-\xDF][\x80-\xBF]
			|   \xE0[\xA0-\xBF][\x80-\xBF]
			|   [\xE1-\xEC][\x80-\xBF]{2}
			|   \xED[\x80-\x9F][\x80-\xBF]
			|   [\xEE-\xEF][\x80-\xBF]{2}
			|   \xF0[\x90-\xBF][\x80-\xBF]{2}
			|   [\xF1-\xF3][\x80-\xBF]{3}
			|   \xF4[\x80-\x8F][\x80-\xBF]{2}
		){1,40}
		)/x';
		$location = (string) preg_replace_callback(
			$regex,
			static function ( array $matches ): string {
				return urlencode( $matches[0] );
			},
			$location
		);
		$location = (string) preg_replace( '|[^a-z0-9-~+_.?#=&;,/:%!*\[\]()@]|i', '', $location );
		$location = wp_kses_no_null( $location );
		return _deep_replace( [ '%0d', '%0a', '%0D', '%0A' ], $location );
	}
}

if ( ! function_exists( 'wp_normalize_path' ) ) {
	function wp_normalize_path( string $path ): string {
		$path = str_replace( '\\', '/', $path );
		$path = (string) preg_replace( '|(?<=.)/+|', '/', $path );
		if ( ':' === substr( $path, 1, 1 ) ) {
			$path = ucfirst( $path );
		}
		return $path;
	}
}

if ( ! function_exists( 'wp_validate_redirect' ) ) {
	/** Core wp_validate_redirect() (pluggable.php), including allowed_redirect_hosts. */
	function wp_validate_redirect( string $location, string $default = '' ): string {
		$location = wp_sanitize_redirect( trim( $location, " \t\n\r\0\x08\x0B" ) );
		if ( 0 === strpos( $location, '//' ) ) {
			$location = 'http:' . $location;
		}

		$cut  = strpos( $location, '?' );
		$test = $cut ? substr( $location, 0, $cut ) : $location;
		$lp   = parse_url( $test ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url

		if ( false === $lp ) {
			return $default;
		}
		if ( isset( $lp['scheme'] ) && ! ( 'http' === $lp['scheme'] || 'https' === $lp['scheme'] ) ) {
			return $default;
		}
		if ( ! isset( $lp['host'] ) && ! empty( $lp['path'] ) && '/' !== $lp['path'][0] ) {
			$path = '';
			if ( ! empty( $_SERVER['REQUEST_URI'] ) ) {
				$path = dirname( parse_url( 'http://placeholder' . $_SERVER['REQUEST_URI'], PHP_URL_PATH ) . '?' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url
				$path = wp_normalize_path( $path );
			}
			$location = '/' . ltrim( $path . '/', '/' ) . $location;
		}
		if ( ! isset( $lp['host'] ) && ( isset( $lp['scheme'] ) || isset( $lp['user'] ) || isset( $lp['pass'] ) || isset( $lp['port'] ) ) ) {
			return $default;
		}
		foreach ( [ 'user', 'pass', 'host' ] as $component ) {
			if ( isset( $lp[ $component ] ) && strpbrk( (string) $lp[ $component ], ':/?#@' ) ) {
				return $default;
			}
		}

		$wpp           = parse_url( home_url() ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url
		$allowed_hosts = (array) apply_filters( 'allowed_redirect_hosts', [ $wpp['host'] ], $lp['host'] ?? '' );

		if ( isset( $lp['host'] ) && ( ! in_array( $lp['host'], $allowed_hosts, true ) && strtolower( (string) $wpp['host'] ) !== $lp['host'] ) ) {
			$location = $default;
		}
		return $location;
	}
}

if ( ! function_exists( 'wp_redirect' ) ) {
	function wp_redirect( string $location, int $status = 302, string $x_redirect_by = 'WordPress' ): bool {
		unset( $x_redirect_by );
		global $magicauth_test_state;
		$location = (string) apply_filters( 'wp_redirect', $location, $status );
		$status   = (int) apply_filters( 'wp_redirect_status', $status, $location );
		if ( '' === $location ) {
			return false;
		}
		$location = wp_sanitize_redirect( $location );
		$magicauth_test_state['redirects'][] = [ 'location' => $location, 'status' => $status ];
		if ( ! empty( $magicauth_test_state['redirect_throws'] ) ) {
			throw new RedirectSent( $location, $status );
		}
		return true;
	}
}

if ( ! function_exists( 'wp_safe_redirect' ) ) {
	/** Core: validate against home host (fallback admin_url()), then wp_redirect(). */
	function wp_safe_redirect( string $location, int $status = 302, string $x_redirect_by = 'WordPress' ): bool {
		$fallback = (string) apply_filters( 'wp_safe_redirect_fallback', admin_url(), $status );
		return wp_redirect( wp_validate_redirect( $location, $fallback ), $status, $x_redirect_by );
	}
}

if ( ! function_exists( 'wp_json_encode' ) ) {
	/** @return string|false */
	function wp_json_encode( $value, int $flags = 0, int $depth = 512 ) {
		return json_encode( $value, $flags, $depth ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode
	}
}

if ( ! function_exists( 'wp_doing_ajax' ) ) {
	function wp_doing_ajax(): bool {
		global $magicauth_test_state;
		return (bool) apply_filters( 'wp_doing_ajax', ! empty( $magicauth_test_state['doing_ajax'] ) );
	}
}

if ( ! function_exists( 'wp_send_json' ) ) {
	function wp_send_json( $response, ?int $status_code = null, int $flags = 0 ): void {
		global $magicauth_test_state;
		$body = (string) wp_json_encode( $response, $flags );
		$magicauth_test_state['json_responses'][] = [
			'payload' => $response,
			'status'  => $status_code,
			'body'    => $body,
		];
		throw new JsonResponseSent( $response, $status_code, $body );
	}
}

if ( ! function_exists( 'wp_send_json_success' ) ) {
	function wp_send_json_success( $value = null, ?int $status_code = null, int $flags = 0 ): void {
		$response = [ 'success' => true ];
		if ( isset( $value ) ) {
			$response['data'] = $value;
		}
		wp_send_json( $response, $status_code, $flags );
	}
}

if ( ! function_exists( 'wp_send_json_error' ) ) {
	function wp_send_json_error( $value = null, ?int $status_code = null, int $flags = 0 ): void {
		$response = [ 'success' => false ];
		if ( isset( $value ) ) {
			if ( $value instanceof WP_Error ) {
				$result = [];
				foreach ( $value->errors as $code => $messages ) {
					foreach ( $messages as $message ) {
						$result[] = [ 'code' => $code, 'message' => $message ];
					}
				}
				$response['data'] = $result;
			} else {
				$response['data'] = $value;
			}
		}
		wp_send_json( $response, $status_code, $flags );
	}
}

if ( ! function_exists( 'is_wp_error' ) ) {
	function is_wp_error( $thing ): bool {
		return $thing instanceof WP_Error;
	}
}

if ( ! function_exists( 'absint' ) ) {
	function absint( $maybeint ): int {
		return abs( (int) $maybeint );
	}
}

if ( ! function_exists( 'nocache_headers' ) ) {
	function nocache_headers(): void {
		// no-op; headers can't actually be sent in tests.
	}
}

if ( ! function_exists( 'status_header' ) ) {
	function status_header( int $code ): void {
		unset( $code );
	}
}

if ( ! function_exists( 'sanitize_key' ) ) {
	function sanitize_key( string $key ): string {
		return strtolower( preg_replace( '/[^a-z0-9_\-]/i', '', $key ) ?? '' );
	}
}

if ( ! function_exists( 'wp_check_invalid_utf8' ) ) {
	/** Core wp_check_invalid_utf8() for a UTF-8 blog, without $strip. */
	function wp_check_invalid_utf8( string $text ): string {
		if ( '' === $text ) {
			return '';
		}
		return 1 === preg_match( '/^./us', $text ) ? $text : '';
	}
}

if ( ! function_exists( 'wp_strip_all_tags' ) ) {
	function wp_strip_all_tags( string $text, bool $remove_breaks = false ): string {
		$text = (string) preg_replace( '@<(script|style)[^>]*?>.*?</\\1>@si', '', $text );
		$text = strip_tags( $text );
		if ( $remove_breaks ) {
			$text = (string) preg_replace( '/[\r\n\t ]+/', ' ', $text );
		}
		return trim( $text );
	}
}

if ( ! function_exists( 'wp_pre_kses_less_than' ) ) {
	function wp_pre_kses_less_than( string $content ): string {
		return (string) preg_replace_callback(
			'%<[^>]*?((?=<)|>|$)%',
			static function ( array $matches ): string {
				return false === strpos( $matches[0], '>' ) ? esc_html( $matches[0] ) : $matches[0];
			},
			$content
		);
	}
}

if ( ! function_exists( 'sanitize_text_field' ) ) {
	/** Core _sanitize_text_fields() without $keep_newlines. */
	function sanitize_text_field( $str ): string {
		if ( is_object( $str ) || is_array( $str ) ) {
			return '';
		}
		$filtered = wp_check_invalid_utf8( (string) $str );
		if ( false !== strpos( $filtered, '<' ) ) {
			$filtered = wp_pre_kses_less_than( $filtered );
			$filtered = wp_strip_all_tags( $filtered, false );
			$filtered = str_replace( "<\n", "&lt;\n", $filtered );
		}
		$filtered = (string) preg_replace( '/[\r\n\t ]+/', ' ', $filtered );
		$filtered = trim( $filtered );
		$found    = false;
		while ( preg_match( '/%[a-f0-9]{2}/i', $filtered, $match ) ) {
			$filtered = str_replace( $match[0], '', $filtered );
			$found    = true;
		}
		if ( $found ) {
			$filtered = trim( (string) preg_replace( '/ +/', ' ', $filtered ) );
		}
		return $filtered;
	}
}

if ( ! function_exists( 'wp_unslash' ) ) {
	function wp_unslash( $value ) {
		if ( is_array( $value ) ) {
			return array_map( 'wp_unslash', $value );
		}
		return is_string( $value ) ? stripslashes( $value ) : $value;
	}
}

if ( ! function_exists( 'is_admin' ) ) {
	function is_admin(): bool {
		global $magicauth_test_state;
		return ! empty( $magicauth_test_state['is_admin'] );
	}
}

if ( ! function_exists( 'add_shortcode' ) ) {
	/** Records the callback in shortcodes[ tag ], as core's $shortcode_tags. */
	function add_shortcode( string $tag, callable $callback ): void {
		global $magicauth_test_state;
		$magicauth_test_state['shortcodes'][ $tag ] = $callback;
	}
}

if ( ! function_exists( 'has_shortcode' ) ) {
	function has_shortcode( string $content, string $tag ): bool {
		return false !== strpos( $content, '[' . $tag );
	}
}

if ( ! function_exists( '__return_true' ) ) {
	function __return_true(): bool { // phpcs:ignore WordPress.NamingConventions.ValidFunctionName.FunctionDoubleUnderscore
		return true;
	}
}

if ( ! function_exists( '__return_false' ) ) {
	function __return_false(): bool { // phpcs:ignore WordPress.NamingConventions.ValidFunctionName.FunctionDoubleUnderscore
		return false;
	}
}

/*
 * Main query of a front-end request: queried = [ id, type, post (WP_Post) ];
 * absent means an archive or no singular post.
 */

if ( ! function_exists( 'is_singular' ) ) {
	function is_singular(): bool {
		global $magicauth_test_state;
		return isset( $magicauth_test_state['queried'] );
	}
}

if ( ! function_exists( 'is_page' ) ) {
	function is_page( $page = '' ): bool {
		global $magicauth_test_state;
		$queried = $magicauth_test_state['queried'] ?? null;
		if ( ! is_array( $queried ) || 'page' !== ( $queried['type'] ?? '' ) ) {
			return false;
		}
		return '' === $page || (int) $page === (int) ( $queried['id'] ?? 0 );
	}
}

/*
 * Request conditionals of the prompt's HTML-page check (SPEC 2.1 check 2):
 * each reads $magicauth_test_state['request'][ name ] (default false).
 */
if ( ! function_exists( 'magicauth_test_request_is' ) ) {
	function magicauth_test_request_is( string $name ): bool {
		global $magicauth_test_state;
		return ! empty( $magicauth_test_state['request'][ $name ] );
	}
}

if ( ! function_exists( 'wp_is_json_request' ) ) {
	function wp_is_json_request(): bool {
		return magicauth_test_request_is( 'wp_is_json_request' );
	}
}

if ( ! function_exists( 'is_feed' ) ) {
	function is_feed(): bool {
		return magicauth_test_request_is( 'is_feed' );
	}
}

if ( ! function_exists( 'is_embed' ) ) {
	function is_embed(): bool {
		return magicauth_test_request_is( 'is_embed' );
	}
}

if ( ! function_exists( 'is_customize_preview' ) ) {
	function is_customize_preview(): bool {
		return magicauth_test_request_is( 'is_customize_preview' );
	}
}

if ( ! function_exists( 'is_robots' ) ) {
	function is_robots(): bool {
		return magicauth_test_request_is( 'is_robots' );
	}
}

if ( ! class_exists( 'WP_Screen' ) ) {
	/** Core's screen object as far as MagicAuth reads it. */
	class WP_Screen { // phpcs:ignore Generic.Files.OneObjectStructurePerFile.MultipleFound
		/** @var string */
		public $id = '';
	}
}

if ( ! function_exists( 'get_current_screen' ) ) {
	/** The wp-admin screen: $magicauth_test_state['screen'] (an object with id), else null. */
	function get_current_screen() {
		global $magicauth_test_state;
		return $magicauth_test_state['screen'] ?? null;
	}
}

if ( ! function_exists( 'get_queried_object' ) ) {
	function get_queried_object() {
		global $magicauth_test_state;
		return $magicauth_test_state['queried']['post'] ?? null;
	}
}

if ( ! function_exists( 'wp_update_user' ) ) {
	/**
	 * Core wp_update_user() as far as MagicAuth sees it: user_email and
	 * display_name change on the stored user, then profile_update fires with
	 * ( $user_id, $old_user_data, $userdata ), as wp_insert_user() does.
	 *
	 * @param array<string,mixed> $userdata
	 * @return int|WP_Error
	 */
	function wp_update_user( array $userdata ) {
		$id   = (int) ( $userdata['ID'] ?? 0 );
		$user = get_userdata( $id );
		if ( ! $user instanceof WP_User ) {
			return new WP_Error( 'invalid_user_id', 'Invalid user ID.' );
		}
		$old = clone $user;
		foreach ( [ 'user_email', 'display_name' ] as $key ) {
			if ( isset( $userdata[ $key ] ) ) {
				$user->$key = (string) $userdata[ $key ];
			}
		}
		do_action( 'profile_update', $id, $old, $userdata );
		return $id;
	}
}

if ( ! function_exists( 'get_stylesheet_directory' ) ) {
	/** Active (child) theme directory; stylesheet_directory toggle, default a theme folder that does not exist. */
	function get_stylesheet_directory(): string {
		global $magicauth_test_state;
		return (string) ( $magicauth_test_state['stylesheet_directory'] ?? ABSPATH . 'wp-content/themes/magicauth-test-theme' );
	}
}

if ( ! function_exists( 'get_template_directory' ) ) {
	/** Parent theme directory; template_directory toggle, default the stylesheet directory (no child theme), as core. */
	function get_template_directory(): string {
		global $magicauth_test_state;
		return (string) ( $magicauth_test_state['template_directory'] ?? get_stylesheet_directory() );
	}
}

if ( ! function_exists( 'login_header' ) ) {
	/** wp-login.php's login_header(): records the call (login_header_calls) and prints nothing. */
	function login_header( $title = 'Log In', $message = '', $wp_error = null ): void {
		global $magicauth_test_state;
		unset( $message, $wp_error );
		$magicauth_test_state['login_header_calls'][] = (string) $title;
	}
}

if ( ! function_exists( 'login_footer' ) ) {
	/** wp-login.php's login_footer(): records the call (login_footer_calls) and prints nothing. */
	function login_footer( string $input_id = '' ): void {
		global $magicauth_test_state;
		$magicauth_test_state['login_footer_calls'][] = $input_id;
	}
}

if ( ! function_exists( 'wp_enqueue_style' ) ) {
	/** Records enqueued_styles[ handle ] = [ src, deps, ver, media ]. */
	function wp_enqueue_style( string $handle, string $src = '', array $deps = [], $ver = false, string $media = 'all' ): void {
		global $magicauth_test_state;
		$magicauth_test_state['enqueued_styles'][ $handle ] = [ $src, $deps, $ver, $media ];
	}
}

if ( ! function_exists( 'wp_style_add_data' ) ) {
	/** Records style_data[ handle ][ key ] = value. */
	function wp_style_add_data( string $handle, string $key, $value ): bool {
		global $magicauth_test_state;
		$magicauth_test_state['style_data'][ $handle ][ $key ] = $value;
		return true;
	}
}

if ( ! function_exists( 'wp_enqueue_script' ) ) {
	/** Records enqueued_scripts[ handle ] = [ src, deps, ver, args ]. */
	function wp_enqueue_script( string $handle, string $src = '', array $deps = [], $ver = false, $args = [] ): void {
		global $magicauth_test_state;
		$magicauth_test_state['enqueued_scripts'][ $handle ] = [ $src, $deps, $ver, $args ];
	}
}

if ( ! function_exists( 'wp_add_inline_script' ) ) {
	/** Records inline_scripts[ handle ][] = [ data, position ]. */
	function wp_add_inline_script( string $handle, string $data, string $position = 'after' ): bool {
		global $magicauth_test_state;
		$magicauth_test_state['inline_scripts'][ $handle ][] = [ $data, $position ];
		return true;
	}
}

if ( ! function_exists( 'headers_sent' ) ) {
	function headers_sent(): bool {
		return false;
	}
}

if ( ! class_exists( 'WP_Post' ) ) {
	class WP_Post { // phpcs:ignore WordPress.NamingConventions.ValidClassName.NotSnakeCaseClassName
		public string $post_content = '';
		public function __construct( string $content = '' ) {
			$this->post_content = $content;
		}
	}
}

if ( ! function_exists( 'wp_get_attachment_image_src' ) ) {
	function wp_get_attachment_image_src( int $id, string $size = 'thumbnail' ) {
		unset( $size );
		global $magicauth_test_state;
		$url = $magicauth_test_state['attachments'][ $id ] ?? null;
		if ( null === $url ) {
			return false;
		}
		return [ $url, 32, 32, false ];
	}
}

if ( ! function_exists( 'magicauth_test_register_attachment' ) ) {
	function magicauth_test_register_attachment( int $id, string $url ): void {
		global $magicauth_test_state;
		$magicauth_test_state['attachments'][ $id ] = $url;
	}
}

if ( ! function_exists( 'magicauth_test_register_user' ) ) {
	/**
	 * Test helper: register a stub WP_User in the in-memory user table.
	 */
	function magicauth_test_register_user( int $id, string $email, array $roles = [ 'subscriber' ] ): WP_User {
		global $magicauth_test_state;
		$user                                   = new WP_User( $id, $email, $roles );
		$magicauth_test_state['users'][ $id ] = $user;
		return $user;
	}
}

/*
 * Nonces, bound to their action as core's are: wp_create_nonce( $action )
 * returns 'test-nonce-' plus 10 hex chars derived from the action (survives
 * sanitize_key() like a real nonce), and plain 'test-nonce' when no action is
 * given. wp_verify_nonce() accepts only the value for the same action, or
 * $magicauth_test_state['nonce_accept'] when a test sets it.
 */

if ( ! function_exists( 'wp_verify_nonce' ) ) {
	function wp_verify_nonce( $nonce, $action = -1 ) {
		global $magicauth_test_state;
		$accept = $magicauth_test_state['nonce_accept'] ?? wp_create_nonce( $action );
		return '' !== (string) $nonce && (string) $nonce === (string) $accept ? 1 : false;
	}
}

if ( ! function_exists( 'wp_create_nonce' ) ) {
	function wp_create_nonce( $action = -1 ): string {
		if ( -1 === $action ) {
			return 'test-nonce';
		}
		return 'test-nonce-' . substr( md5( (string) $action ), 0, 10 );
	}
}

if ( ! function_exists( 'wp_nonce_url' ) ) {
	function wp_nonce_url( string $actionurl, $action = -1, string $name = '_wpnonce' ): string {
		$actionurl = str_replace( '&amp;', '&', $actionurl );
		return esc_html( add_query_arg( $name, wp_create_nonce( $action ), $actionurl ) );
	}
}

if ( ! function_exists( 'wp_referer_field' ) ) {
	function wp_referer_field( bool $display = true ): string {
		$request_url = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '';
		$field       = '<input type="hidden" name="_wp_http_referer" value="' . esc_attr( (string) wp_unslash( $request_url ) ) . '" />';
		if ( $display ) {
			echo $field; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}
		return $field;
	}
}

if ( ! function_exists( 'wp_nonce_field' ) ) {
	/** Core wp_nonce_field(), including the referer field. */
	function wp_nonce_field( $action = -1, string $name = '_wpnonce', bool $referer = true, bool $display = true ): string {
		$name        = esc_attr( $name );
		$nonce_field = '<input type="hidden" id="' . $name . '" name="' . $name . '" value="' . wp_create_nonce( $action ) . '" />';
		if ( $referer ) {
			$nonce_field .= wp_referer_field( false );
		}
		if ( $display ) {
			echo $nonce_field; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}
		return $nonce_field;
	}
}

if ( ! function_exists( 'check_ajax_referer' ) ) {
	/** Core check_ajax_referer(); on failure with $stop, throws JsonResponseSent( '-1', 403 ) for wp_die( -1, 403 ). */
	function check_ajax_referer( $action = -1, $query_arg = false, bool $stop = true ) {
		$nonce = '';
		if ( $query_arg && isset( $_REQUEST[ $query_arg ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$nonce = (string) $_REQUEST[ $query_arg ]; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		} elseif ( isset( $_REQUEST['_ajax_nonce'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$nonce = (string) $_REQUEST['_ajax_nonce']; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		} elseif ( isset( $_REQUEST['_wpnonce'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$nonce = (string) $_REQUEST['_wpnonce']; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		}
		$result = wp_verify_nonce( $nonce, $action );
		do_action( 'check_ajax_referer', $action, $result );
		if ( $stop && false === $result ) {
			global $magicauth_test_state;
			$magicauth_test_state['json_responses'][] = [
				'payload' => '-1',
				'status'  => 403,
				'body'    => '-1',
			];
			throw new JsonResponseSent( '-1', 403, '-1' );
		}
		return $result;
	}
}

if ( ! function_exists( 'retrieve_password' ) ) {
	function retrieve_password( $user_login = '' ) {
		unset( $user_login );
		global $magicauth_test_state;
		$magicauth_test_state['retrieve_password_calls'] = ( $magicauth_test_state['retrieve_password_calls'] ?? 0 ) + 1;
		return true;
	}
}

if ( ! function_exists( 'wp_authenticate' ) ) {
	/**
	 * Password check against $magicauth_test_state['passwords'][ login or email ]
	 * = [ password, user ID ]; a miss returns WP_Error as core does.
	 *
	 * @return WP_User|WP_Error
	 */
	function wp_authenticate( $username, $password ) {
		global $magicauth_test_state;
		$entry = $magicauth_test_state['passwords'][ (string) $username ] ?? null;
		if ( is_array( $entry ) && hash_equals( (string) $entry[0], (string) $password ) ) {
			$user = get_userdata( (int) $entry[1] );
			if ( $user instanceof WP_User ) {
				return $user;
			}
		}
		return new WP_Error( 'incorrect_password', 'The password you entered is incorrect.' );
	}
}

if ( ! function_exists( 'check_password_reset_key' ) ) {
	/**
	 * Valid only for $magicauth_test_state['reset_keys'][ login ] = [ key, user ID ].
	 *
	 * @return WP_User|WP_Error
	 */
	function check_password_reset_key( $key, $login ) {
		global $magicauth_test_state;
		$entry = $magicauth_test_state['reset_keys'][ (string) $login ] ?? null;
		if ( is_array( $entry ) && '' !== (string) $key && hash_equals( (string) $entry[0], (string) $key ) ) {
			$user = get_userdata( (int) $entry[1] );
			if ( $user instanceof WP_User ) {
				return $user;
			}
		}
		return new WP_Error( 'invalid_key', 'Your password reset link appears to be invalid.' );
	}
}

if ( ! function_exists( 'reset_password' ) ) {
	/** Records the call; core fires password_reset and after_password_reset around wp_set_password(). */
	function reset_password( $user, $new_pass ): void {
		global $magicauth_test_state;
		do_action( 'password_reset', $user, $new_pass );
		$magicauth_test_state['password_resets'][] = (int) $user->ID;
		do_action( 'after_password_reset', $user, $new_pass );
	}
}

/*
 * Dates, posts, multisite.
 */

if ( ! function_exists( 'wp_timezone_string' ) ) {
	function wp_timezone_string(): string {
		global $magicauth_test_state;
		return (string) ( $magicauth_test_state['timezone_string'] ?? 'UTC' );
	}
}

if ( ! function_exists( 'wp_timezone' ) ) {
	function wp_timezone(): DateTimeZone {
		return new DateTimeZone( wp_timezone_string() );
	}
}

if ( ! function_exists( 'wp_date' ) ) {
	/** @return string|false */
	function wp_date( string $format, ?int $timestamp = null, ?DateTimeZone $timezone = null ) {
		$timestamp = $timestamp ?? time();
		$timezone  = $timezone ?? wp_timezone();
		return ( new DateTimeImmutable( '@' . $timestamp ) )->setTimezone( $timezone )->format( $format );
	}
}

if ( ! function_exists( 'get_post_status' ) ) {
	/** @return string|false */
	function get_post_status( $post = null ) {
		global $magicauth_test_state;
		$id = $post instanceof WP_Post ? 0 : (int) $post;
		return isset( $magicauth_test_state['posts'][ $id ] ) ? (string) ( $magicauth_test_state['posts'][ $id ]['status'] ?? 'publish' ) : false;
	}
}

if ( ! function_exists( 'get_post_type' ) ) {
	/** @return string|false */
	function get_post_type( $post = null ) {
		global $magicauth_test_state;
		$id = $post instanceof WP_Post ? 0 : (int) $post;
		return isset( $magicauth_test_state['posts'][ $id ] ) ? (string) ( $magicauth_test_state['posts'][ $id ]['type'] ?? 'page' ) : false;
	}
}

if ( ! function_exists( 'get_permalink' ) ) {
	/** @return string|false */
	function get_permalink( $post = 0 ) {
		global $magicauth_test_state;
		$id = $post instanceof WP_Post ? 0 : (int) $post;
		if ( ! isset( $magicauth_test_state['posts'][ $id ] ) ) {
			return false;
		}
		return (string) ( $magicauth_test_state['posts'][ $id ]['permalink'] ?? home_url( '/?page_id=' . $id ) );
	}
}

if ( ! function_exists( 'get_the_title' ) ) {
	/** Title from posts[ id ]['title'], returned as stored (core may hand back entities). */
	function get_the_title( $post = 0 ): string {
		global $magicauth_test_state;
		$id = $post instanceof WP_Post ? 0 : (int) $post;
		return (string) ( $magicauth_test_state['posts'][ $id ]['title'] ?? '' );
	}
}

/*
 * Settings API: add_settings_error() records into settings_errors (core keeps
 * them in $wp_settings_errors); checked(), selected() and wp_dropdown_pages()
 * print core-shaped markup (the dropdown lists posts[] entries of type page
 * with status publish, and is '' without one).
 */

if ( ! function_exists( 'add_settings_error' ) ) {
	function add_settings_error( string $setting, string $code, string $message, string $type = 'error' ): void {
		global $magicauth_test_state;
		$magicauth_test_state['settings_errors'][] = [
			'setting' => $setting,
			'code'    => $code,
			'message' => $message,
			'type'    => $type,
		];
	}
}

if ( ! function_exists( 'checked' ) ) {
	/** Core __checked_selected_helper() for checked. */
	function checked( $checked, $current = true, bool $display = true ): string {
		$result = (string) $checked === (string) $current ? " checked='checked'" : '';
		if ( $display ) {
			echo $result; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}
		return $result;
	}
}

if ( ! function_exists( 'selected' ) ) {
	function selected( $selected, $current = true, bool $display = true ): string {
		$result = (string) $selected === (string) $current ? " selected='selected'" : '';
		if ( $display ) {
			echo $result; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}
		return $result;
	}
}

if ( ! function_exists( 'wp_dropdown_pages' ) ) {
	/**
	 * Core wp_dropdown_pages() markup: '' when no page is published, and
	 * show_option_none printed as given (core does not escape it).
	 *
	 * @param array<string,mixed> $args
	 */
	function wp_dropdown_pages( array $args = [] ): string {
		global $magicauth_test_state;
		$pages = [];
		foreach ( (array) ( $magicauth_test_state['posts'] ?? [] ) as $id => $post ) {
			if ( 'page' === ( $post['type'] ?? 'page' ) && 'publish' === ( $post['status'] ?? 'publish' ) ) {
				$pages[ (int) $id ] = (string) ( $post['title'] ?? '' );
			}
		}
		$output = '';
		if ( [] !== $pages ) {
			$name   = esc_attr( (string) ( $args['name'] ?? 'page_id' ) );
			$output = "<select name='{$name}' id='{$name}'>\n";
			if ( ! empty( $args['show_option_none'] ) ) {
				$output .= "\t<option value=\"" . esc_attr( (string) ( $args['option_none_value'] ?? '' ) ) . '">' . (string) $args['show_option_none'] . "</option>\n";
			}
			foreach ( $pages as $id => $title ) {
				$output .= "\t<option class=\"level-0\" value=\"" . $id . '"' . selected( (int) ( $args['selected'] ?? 0 ), $id, false ) . '>' . esc_html( $title ) . "</option>\n";
			}
			$output .= "</select>\n";
		}
		if ( ! isset( $args['echo'] ) || $args['echo'] ) {
			echo $output; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}
		return $output;
	}
}

if ( ! function_exists( 'is_multisite' ) ) {
	function is_multisite(): bool {
		global $magicauth_test_state;
		return ! empty( $magicauth_test_state['multisite'] );
	}
}

if ( ! function_exists( 'is_subdomain_install' ) ) {
	function is_subdomain_install(): bool {
		global $magicauth_test_state;
		return ! empty( $magicauth_test_state['subdomain_install'] );
	}
}

if ( ! function_exists( 'get_sites' ) ) {
	/**
	 * Subset of core get_sites(): filters on domain and path; 'count' returns an int.
	 *
	 * @param array<string,mixed> $args
	 * @return array<int,object>|int
	 */
	function get_sites( array $args = [] ) {
		global $magicauth_test_state;
		$sites = [];
		foreach ( (array) ( $magicauth_test_state['sites'] ?? [] ) as $site ) {
			$site = (object) $site;
			if ( isset( $args['domain'] ) && (string) ( $site->domain ?? '' ) !== (string) $args['domain'] ) {
				continue;
			}
			if ( isset( $args['path'] ) && (string) ( $site->path ?? '' ) !== (string) $args['path'] ) {
				continue;
			}
			$sites[] = $site;
		}
		return ! empty( $args['count'] ) ? count( $sites ) : $sites;
	}
}

if ( ! function_exists( 'is_user_spammy' ) ) {
	function is_user_spammy( $user = null ): bool {
		global $magicauth_test_state;
		if ( null === $user ) {
			$user = wp_get_current_user();
		} elseif ( ! $user instanceof WP_User ) {
			$user = get_user_by( 'login', (string) $user );
		}
		return $user instanceof WP_User && in_array( $user->ID, array_map( 'intval', (array) ( $magicauth_test_state['spammy_users'] ?? [] ) ), true );
	}
}

if ( ! function_exists( 'magicauth_test_reset_state' ) ) {
	/**
	 * Test helper: wipe in-memory state between tests.
	 */
	function magicauth_test_reset_state(): void {
		global $magicauth_test_state, $wpdb;
		$magicauth_test_state = [
			'options'     => [],
			'usermeta'    => [],
			'transients'  => [],
			'users'       => [],
			'actions'     => [],
			'filters'     => [],
			'attachments' => [],
		];
		if ( isset( $wpdb ) && method_exists( $wpdb, 'truncate_magicauth_table' ) ) {
			$wpdb->truncate_magicauth_table();
		}
		if ( isset( $wpdb ) && method_exists( $wpdb, 'reset_test_switches' ) ) {
			$wpdb->reset_test_switches();
		}
		// Throttle keeps a static in-process registry cache that survives
		// across tests otherwise — drop it so each test sees a clean slate.
		if ( class_exists( '\\MagicAuth\\Auth\\Throttle' ) ) {
			\MagicAuth\Auth\Throttle::reset_runtime_state_for_tests();
		}
		if ( class_exists( '\\MagicAuth\\Passkeys\\Clock' ) ) {
			\MagicAuth\Passkeys\Clock::set_for_tests( null );
		}
		if ( class_exists( '\\MagicAuth\\Passkeys\\Module' ) ) {
			\MagicAuth\Passkeys\Module::reset_for_tests();
		}
		if ( class_exists( '\\MagicAuth\\Passkeys\\ProfileSection' ) ) {
			\MagicAuth\Passkeys\ProfileSection::reset_for_tests();
		}
		if ( class_exists( '\\MagicAuth\\Passkeys\\Assets' ) ) {
			\MagicAuth\Passkeys\Assets::reset_for_tests();
		}
		if ( class_exists( '\\MagicAuth\\Passkeys\\Prompt' ) ) {
			\MagicAuth\Passkeys\Prompt::reset_for_tests();
		}
	}
}
