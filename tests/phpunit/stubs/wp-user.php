<?php
/**
 * Minimal WP_User shim for model-layer tests.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

if ( ! class_exists( 'WP_User' ) ) {
	class WP_User { // phpcs:ignore WordPress.NamingConventions.ValidClassName.NotSnakeCaseClassName

		public int $ID = 0; // phpcs:ignore WordPress.NamingConventions.ValidVariableName

		public string $user_email = '';

		public string $user_login = '';

		/**
		 * @var array<int,string>
		 */
		public array $roles = [];

		/**
		 * @var array<string,bool>
		 */
		public array $allcaps = [];

		public function __construct( int $id = 0, string $email = '', array $roles = [] ) {
			$this->ID         = $id; // phpcs:ignore WordPress.NamingConventions.ValidVariableName
			$this->user_email = $email;
			$this->roles      = $roles;
			// Mirror real WP: allcaps is the union of role caps + direct caps.
			$this->allcaps    = function_exists( 'magicauth_test_caps_for_user' ) ? magicauth_test_caps_for_user( $this ) : [];
		}

		public function add_cap( string $cap, bool $grant = true ): void {
			$this->allcaps[ $cap ] = $grant;
		}

		public function exists(): bool {
			return $this->ID > 0;
		}
	}
}
