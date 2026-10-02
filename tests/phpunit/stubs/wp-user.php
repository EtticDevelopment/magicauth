<?php
/**
 * Minimal WP_User shim for model-layer tests.
 *
 * $allcaps is built as core builds it (class-wp-user.php get_role_caps():
 * role capabilities merged in role order, then $caps merged on top). $caps
 * holds the role names as keys, so $allcaps contains them too (B17).
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

if ( ! class_exists( 'WP_User' ) ) {
	#[AllowDynamicProperties]
	class WP_User { // phpcs:ignore WordPress.NamingConventions.ValidClassName.NotSnakeCaseClassName

		public int $ID = 0; // phpcs:ignore WordPress.NamingConventions.ValidVariableName

		public string $user_email = '';

		public string $user_login = '';

		public string $display_name = '';

		public string $user_registered = '';

		/**
		 * @var array<int,string>
		 */
		public array $roles = [];

		/**
		 * Role names plus directly granted caps (core's capabilities user meta).
		 *
		 * @var array<string,bool>
		 */
		public array $caps = [];

		/**
		 * @var array<string,bool>
		 */
		public array $allcaps = [];

		public function __construct( int $id = 0, string $email = '', array $roles = [] ) {
			$this->ID         = $id; // phpcs:ignore WordPress.NamingConventions.ValidVariableName
			$this->user_email = $email;
			$this->roles      = array_values( $roles );
			foreach ( $this->roles as $role ) {
				$this->caps[ (string) $role ] = true;
			}
			$this->get_role_caps();
		}

		/**
		 * Core order: role caps merged in role order, then $caps on top.
		 *
		 * @return array<string,bool>
		 */
		public function get_role_caps(): array {
			$allcaps = [];
			if ( function_exists( 'wp_roles' ) ) {
				$wp_roles = wp_roles();
				foreach ( $this->roles as $role ) {
					$the_role = $wp_roles->get_role( $role );
					if ( $the_role ) {
						$allcaps = array_merge( $allcaps, (array) $the_role->capabilities );
					}
				}
			}
			$this->allcaps = array_merge( $allcaps, $this->caps );
			return $this->allcaps;
		}

		public function add_cap( string $cap, bool $grant = true ): void {
			$this->caps[ $cap ] = $grant;
			$this->get_role_caps();
		}

		public function has_cap( string $cap ): bool {
			return ! empty( $this->allcaps[ $cap ] );
		}

		public function exists(): bool {
			return $this->ID > 0;
		}
	}
}
