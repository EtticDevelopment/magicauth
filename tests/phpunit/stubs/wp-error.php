<?php
/**
 * Minimal WP_Error shim for model-layer tests.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

if ( ! class_exists( 'WP_Error' ) ) {
	class WP_Error { // phpcs:ignore WordPress.NamingConventions.ValidClassName.NotSnakeCaseClassName

		/**
		 * @var array<string,array<int,string>>
		 */
		public array $errors = [];

		/**
		 * @var array<string,mixed>
		 */
		public array $error_data = [];

		public function __construct( string $code = '', string $message = '', $data = null ) {
			if ( '' !== $code ) {
				$this->errors[ $code ][] = $message;
				if ( null !== $data ) {
					$this->error_data[ $code ] = $data;
				}
			}
		}

		public function get_error_code(): string {
			return (string) array_key_first( $this->errors );
		}

		public function get_error_message( string $code = '' ): string {
			$code = '' === $code ? $this->get_error_code() : $code;
			return $this->errors[ $code ][0] ?? '';
		}
	}
}
