<?php
/**
 * Minimal WordPress function shims for model-layer tests.
 *
 * Behaves enough like WP for TokenManager/Throttle/Controller. Anything that
 * touches HTTP, mail, the cache layer, or the option/usermeta tables is
 * stubbed in-process.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

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
		if ( 'magicauth_settings' === $option && function_exists( 'magicauth_invalidate_settings_cache' ) ) {
			magicauth_invalidate_settings_cache();
		}
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
		if ( 'magicauth_settings' === $option && function_exists( 'magicauth_invalidate_settings_cache' ) ) {
			magicauth_invalidate_settings_cache();
		}
		return true;
	}
}

if ( ! function_exists( 'delete_option' ) ) {
	function delete_option( string $option ): bool {
		global $magicauth_test_state;
		unset( $magicauth_test_state['options'][ $option ] );
		if ( 'magicauth_settings' === $option && function_exists( 'magicauth_invalidate_settings_cache' ) ) {
			magicauth_invalidate_settings_cache();
		}
		return true;
	}
}

if ( ! function_exists( 'get_user_meta' ) ) {
	function get_user_meta( int $user_id, string $key = '', bool $single = false ) {
		global $magicauth_test_state;
		$meta = $magicauth_test_state['usermeta'][ $user_id ] ?? [];
		if ( '' === $key ) {
			return $meta;
		}
		$value = $meta[ $key ] ?? '';
		return $single ? $value : (array) $value;
	}
}

if ( ! function_exists( 'update_user_meta' ) ) {
	function update_user_meta( int $user_id, string $key, $value ): bool {
		global $magicauth_test_state;
		$magicauth_test_state['usermeta'][ $user_id ][ $key ] = $value;
		return true;
	}
}

if ( ! function_exists( 'delete_user_meta' ) ) {
	function delete_user_meta( int $user_id, string $key ): bool {
		global $magicauth_test_state;
		unset( $magicauth_test_state['usermeta'][ $user_id ][ $key ] );
		return true;
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
		}
		return false;
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

if ( ! function_exists( 'add_action' ) ) {
	function add_action( string $hook, $callback, int $priority = 10, int $accepted_args = 1 ): bool {
		unset( $priority, $accepted_args );
		global $magicauth_test_state;
		$magicauth_test_state['actions'][ $hook ][] = $callback;
		return true;
	}
}

if ( ! function_exists( 'do_action' ) ) {
	function do_action( string $hook, ...$args ): void {
		global $magicauth_test_state;
		foreach ( $magicauth_test_state['actions'][ $hook ] ?? [] as $cb ) {
			call_user_func_array( $cb, $args );
		}
	}
}

if ( ! function_exists( 'add_filter' ) ) {
	function add_filter( string $hook, $callback, int $priority = 10, int $accepted_args = 1 ): bool {
		unset( $priority, $accepted_args );
		global $magicauth_test_state;
		$magicauth_test_state['filters'][ $hook ][] = $callback;
		return true;
	}
}

if ( ! function_exists( 'apply_filters' ) ) {
	function apply_filters( string $hook, $value, ...$args ) {
		global $magicauth_test_state;
		foreach ( $magicauth_test_state['filters'][ $hook ] ?? [] as $cb ) {
			$value = call_user_func_array( $cb, array_merge( [ $value ], $args ) );
		}
		return $value;
	}
}

if ( ! function_exists( 'home_url' ) ) {
	function home_url( string $path = '' ): string {
		return 'https://example.test' . $path;
	}
}

if ( ! function_exists( 'add_query_arg' ) ) {
	function add_query_arg( $args, string $url ): string {
		$query = http_build_query( $args );
		$sep   = false === strpos( $url, '?' ) ? '?' : '&';
		return $url . $sep . $query;
	}
}

if ( ! function_exists( 'wp_parse_url' ) ) {
	function wp_parse_url( string $url, int $component = -1 ) {
		return $component === -1 ? parse_url( $url ) : parse_url( $url, $component );
	}
}

if ( ! function_exists( '__' ) ) {
	function __( string $text, string $domain = '' ): string {
		unset( $domain );
		return $text;
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

if ( ! function_exists( 'switch_to_locale' ) ) {
	function switch_to_locale( string $locale ): bool {
		unset( $locale );
		return true;
	}
}

if ( ! function_exists( 'restore_previous_locale' ) ) {
	function restore_previous_locale(): bool {
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
	function wp_mail( $to, $subject, $message, $headers = '' ) {
		global $magicauth_test_state;
		$magicauth_test_state['mail'][] = [
			'to'      => $to,
			'subject' => $subject,
			'message' => $message,
			'headers' => $headers,
		];
		return $magicauth_test_state['wp_mail_return'] ?? true;
	}
}

if ( ! function_exists( 'remove_action' ) ) {
	function remove_action( string $hook, $callback, int $priority = 10 ): bool {
		unset( $priority );
		global $magicauth_test_state;
		if ( ! isset( $magicauth_test_state['actions'][ $hook ] ) ) {
			return false;
		}
		foreach ( $magicauth_test_state['actions'][ $hook ] as $i => $cb ) {
			if ( $cb === $callback ) {
				unset( $magicauth_test_state['actions'][ $hook ][ $i ] );
			}
		}
		$magicauth_test_state['actions'][ $hook ] = array_values( $magicauth_test_state['actions'][ $hook ] );
		return true;
	}
}

if ( ! function_exists( 'wp_get_current_user' ) ) {
	function wp_get_current_user() {
		global $magicauth_test_state;
		$id = $magicauth_test_state['current_user'] ?? 0;
		return $magicauth_test_state['users'][ $id ] ?? new WP_User( 0, '' );
	}
}

if ( ! function_exists( 'is_user_logged_in' ) ) {
	function is_user_logged_in(): bool {
		global $magicauth_test_state;
		return ! empty( $magicauth_test_state['current_user'] );
	}
}

if ( ! function_exists( 'current_user_can' ) ) {
	function current_user_can( string $cap, ...$args ) {
		global $magicauth_test_state;
		$user = wp_get_current_user();
		if ( ! $user || $user->ID === 0 ) {
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

if ( ! function_exists( 'wp_roles' ) ) {
	function wp_roles() {
		global $magicauth_test_state;
		if ( empty( $magicauth_test_state['roles'] ) ) {
			$magicauth_test_state['roles'] = new class() {
				public array $roles = [
					'subscriber'  => [ 'name' => 'Subscriber', 'capabilities' => [ 'read' => true ] ],
					'editor'      => [ 'name' => 'Editor',     'capabilities' => [ 'read' => true, 'edit_posts' => true, 'edit_others_posts' => true ] ],
					'administrator' => [ 'name' => 'Administrator', 'capabilities' => [ 'read' => true, 'edit_posts' => true, 'edit_others_posts' => true, 'edit_users' => true, 'manage_options' => true, 'promote_users' => true ] ],
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
	function magicauth_test_caps_for_user( WP_User $user ): array {
		$wp_roles = wp_roles();
		$caps     = [];
		foreach ( (array) $user->roles as $slug ) {
			$role = $wp_roles->get_role( $slug );
			if ( $role && isset( $role->capabilities ) ) {
				$caps += array_filter( (array) $role->capabilities );
			}
		}
		return $caps;
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
		unset( $domain );
		echo esc_html( $text );
	}
}

if ( ! function_exists( 'esc_html__' ) ) {
	function esc_html__( string $text, string $domain = '' ): string {
		unset( $domain );
		return esc_html( $text );
	}
}

if ( ! function_exists( 'esc_attr_e' ) ) {
	function esc_attr_e( string $text, string $domain = '' ): void {
		unset( $domain );
		echo esc_attr( $text );
	}
}

if ( ! function_exists( 'esc_url' ) ) {
	function esc_url( string $url ): string {
		return htmlspecialchars( $url, ENT_QUOTES );
	}
}

if ( ! defined( 'EXTR_SKIP' ) ) {
	// EXTR_SKIP is a PHP built-in; this exists only to satisfy stubbing.
	define( 'EXTR_SKIP', 1 );
}

if ( ! function_exists( 'wp_set_auth_cookie' ) ) {
	function wp_set_auth_cookie( int $user_id, bool $remember = false, $secure = '' ): void {
		global $magicauth_test_state;
		$magicauth_test_state['auth_cookie_set_for'] = $user_id;
		unset( $remember, $secure );
	}
}

if ( ! function_exists( 'wp_set_current_user' ) ) {
	function wp_set_current_user( int $user_id ) {
		global $magicauth_test_state;
		$magicauth_test_state['current_user'] = $user_id;
		return $magicauth_test_state['users'][ $user_id ] ?? new WP_User( 0, '' );
	}
}

if ( ! function_exists( 'user_can' ) ) {
	function user_can( $user, string $cap ): bool {
		if ( $user instanceof WP_User ) {
			$caps = magicauth_test_caps_for_user( $user );
			return ! empty( $caps[ $cap ] );
		}
		return false;
	}
}

if ( ! function_exists( 'admin_url' ) ) {
	function admin_url( string $path = '', string $scheme = 'admin' ): string {
		unset( $scheme );
		return 'https://example.test/wp-admin/' . ltrim( $path, '/' );
	}
}

if ( ! function_exists( 'is_ssl' ) ) {
	function is_ssl(): bool {
		return false;
	}
}

if ( ! function_exists( 'wp_safe_redirect' ) ) {
	function wp_safe_redirect( string $location, int $status = 302 ): bool {
		global $magicauth_test_state;
		$magicauth_test_state['redirects'][] = [ 'location' => $location, 'status' => $status ];
		return true;
	}
}

if ( ! function_exists( 'wp_validate_redirect' ) ) {
	function wp_validate_redirect( string $location, string $default = '' ): string {
		// Trust same-host targets; otherwise fall back to default. Crude but
		// sufficient for tests — the real wp_validate_redirect does the same.
		$host = wp_parse_url( $location, PHP_URL_HOST );
		if ( ! $host || strcasecmp( (string) $host, wp_parse_url( home_url(), PHP_URL_HOST ) ?: '' ) === 0 ) {
			return $location;
		}
		return $default;
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

if ( ! function_exists( 'wp_unslash' ) ) {
	function wp_unslash( $value ) {
		if ( is_array( $value ) ) {
			return array_map( 'wp_unslash', $value );
		}
		return is_string( $value ) ? stripslashes( $value ) : $value;
	}
}

if ( ! function_exists( 'remove_query_arg' ) ) {
	function remove_query_arg( $key, ?string $url = null ): string {
		$url = $url ?? '/';
		$parts = parse_url( $url );
		if ( empty( $parts['query'] ) ) {
			return $url;
		}
		parse_str( (string) $parts['query'], $args );
		foreach ( (array) $key as $k ) {
			unset( $args[ $k ] );
		}
		$query = http_build_query( $args );
		$base  = ( $parts['scheme'] ?? '' ? $parts['scheme'] . '://' . ( $parts['host'] ?? '' ) : '' ) . ( $parts['path'] ?? '' );
		return $base . ( '' !== $query ? '?' . $query : '' );
	}
}

if ( ! function_exists( 'is_admin' ) ) {
	function is_admin(): bool {
		global $magicauth_test_state;
		return ! empty( $magicauth_test_state['is_admin'] );
	}
}

if ( ! function_exists( 'has_shortcode' ) ) {
	function has_shortcode( string $content, string $tag ): bool {
		return false !== strpos( $content, '[' . $tag );
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

if ( ! function_exists( 'wp_attachment_is_image' ) ) {
	function wp_attachment_is_image( int $id ): bool {
		global $magicauth_test_state;
		return ! empty( $magicauth_test_state['attachment_is_image'][ $id ] );
	}
}

if ( ! function_exists( 'get_attached_file' ) ) {
	function get_attached_file( int $id ) {
		global $magicauth_test_state;
		return $magicauth_test_state['attachment_paths'][ $id ] ?? false;
	}
}

if ( ! function_exists( 'wp_check_filetype_and_ext' ) ) {
	// Simplified: match by file extension against the allowlist regex keys.
	// Real WP also peeks at content via finfo; we leave that to the caller's
	// own finfo block, since duplicating WP's logic here adds little value.
	function wp_check_filetype_and_ext( string $file, string $filename, array $mimes = [] ): array {
		unset( $file );
		$ext = strtolower( (string) pathinfo( $filename, PATHINFO_EXTENSION ) );
		foreach ( $mimes as $regex => $mime ) {
			$alternatives = explode( '|', $regex );
			if ( in_array( $ext, $alternatives, true ) ) {
				return [ 'ext' => $ext, 'type' => $mime, 'proper_filename' => false ];
			}
		}
		return [ 'ext' => false, 'type' => false, 'proper_filename' => false ];
	}
}

if ( ! function_exists( 'magicauth_test_register_attachment' ) ) {
	function magicauth_test_register_attachment( int $id, string $url ): void {
		global $magicauth_test_state;
		$magicauth_test_state['attachments'][ $id ] = $url;
	}
}

if ( ! function_exists( 'magicauth_test_register_attachment_file' ) ) {
	/**
	 * Test helper: bind an attachment ID to an on-disk path so sanitize_background()
	 * sees a real file (finfo needs bytes). Marks the attachment as an image by
	 * default; pass $is_image=false to simulate a non-image attachment.
	 */
	function magicauth_test_register_attachment_file( int $id, string $path, bool $is_image = true ): void {
		global $magicauth_test_state;
		$magicauth_test_state['attachment_paths'][ $id ]    = $path;
		$magicauth_test_state['attachment_is_image'][ $id ] = $is_image;
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

// Used by the lostpassword timing-oracle regression test. Tracks invocations
// and is a no-op (we only assert it's reached via the deferred path).
if ( ! function_exists( 'wp_verify_nonce' ) ) {
	function wp_verify_nonce( $nonce, $action = -1 ) {
		unset( $action );
		global $magicauth_test_state;
		$accept = $magicauth_test_state['nonce_accept'] ?? 'test-nonce';
		return (string) $nonce === (string) $accept ? 1 : false;
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

if ( ! function_exists( 'absint' ) ) {
	function absint( $maybeint ): int {
		return abs( (int) $maybeint );
	}
}

if ( ! function_exists( 'sanitize_hex_color' ) ) {
	// Mirrors core: accepts #rgb / #rrggbb only; returns null otherwise.
	function sanitize_hex_color( string $color ) {
		if ( '' === $color ) {
			return '';
		}
		if ( preg_match( '|^#([A-Fa-f0-9]{3}){1,2}$|', $color ) ) {
			return $color;
		}
		return null;
	}
}

if ( ! function_exists( 'add_settings_error' ) ) {
	// Test-time recorder; lets tests assert that an error WAS raised when expected.
	function add_settings_error( string $setting, string $code, string $message, string $type = 'error' ): void {
		global $magicauth_test_state;
		$magicauth_test_state['settings_errors'][] = compact( 'setting', 'code', 'message', 'type' );
	}
}

if ( ! function_exists( 'magicauth_test_reset_state' ) ) {
	/**
	 * Test helper: wipe in-memory state between tests.
	 */
	function magicauth_test_reset_state(): void {
		global $magicauth_test_state, $wpdb;
		$magicauth_test_state = [
			'options'             => [],
			'usermeta'            => [],
			'transients'          => [],
			'users'               => [],
			'actions'             => [],
			'filters'             => [],
			'attachments'         => [],
			'attachment_paths'    => [],
			'attachment_is_image' => [],
		];
		if ( function_exists( 'magicauth_invalidate_settings_cache' ) ) {
			magicauth_invalidate_settings_cache();
		}
		if ( isset( $wpdb ) && method_exists( $wpdb, 'truncate_magicauth_table' ) ) {
			$wpdb->truncate_magicauth_table();
		}
		// Throttle keeps a static in-process registry cache that survives
		// across tests otherwise — drop it so each test sees a clean slate.
		if ( class_exists( '\\MagicAuth\\Auth\\Throttle' ) ) {
			\MagicAuth\Auth\Throttle::reset_runtime_state_for_tests();
		}
	}
}
