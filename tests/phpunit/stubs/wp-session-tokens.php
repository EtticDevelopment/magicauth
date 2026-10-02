<?php
/**
 * WP_Session_Tokens stub. Sessions live in $magicauth_test_state['sessions']
 * keyed by user ID and sha256( token ), as core's user-meta manager does.
 *
 * create() applies attach_session_information like core, but writes the
 * record directly: update() throws, so code that would rewrite a session
 * record (SPEC 11.3 invariant 11) fails its test.
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

if ( ! class_exists( 'WP_Session_Tokens' ) ) {
	class WP_Session_Tokens { // phpcs:ignore WordPress.NamingConventions.ValidClassName.NotSnakeCaseClassName

		protected int $user_id;

		protected function __construct( int $user_id ) {
			$this->user_id = $user_id;
		}

		final public static function get_instance( $user_id ): self {
			return new self( (int) $user_id );
		}

		private function hash_token( string $token ): string {
			return hash( 'sha256', $token );
		}

		/** @return array<string,mixed>|null */
		final public function get( $token ): ?array {
			global $magicauth_test_state;
			$verifier = $this->hash_token( (string) $token );
			$session  = $magicauth_test_state['sessions'][ $this->user_id ][ $verifier ] ?? null;
			return is_array( $session ) ? $session : null;
		}

		final public function verify( $token ): bool {
			return null !== $this->get( $token );
		}

		final public function create( $expiration ): string {
			global $magicauth_test_state;
			$session               = apply_filters( 'attach_session_information', [], $this->user_id );
			$session['expiration'] = (int) $expiration;
			if ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
				$session['ip'] = (string) $_SERVER['REMOTE_ADDR'];
			}
			if ( ! empty( $_SERVER['HTTP_USER_AGENT'] ) ) {
				$session['ua'] = (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] );
			}
			$session['login'] = time();

			$token = bin2hex( random_bytes( 21 ) );

			$magicauth_test_state['sessions'][ $this->user_id ][ $this->hash_token( $token ) ] = $session;
			$magicauth_test_state['session_creates'][] = [
				'user_id' => $this->user_id,
				'token'   => $token,
			];
			return $token;
		}

		/**
		 * Never called by MagicAuth (SPEC 11.3 invariant 11, D-30).
		 *
		 * @param array<string,mixed> $session
		 */
		final public function update( $token, $session ): void {
			unset( $token, $session );
			throw new \LogicException( 'WP_Session_Tokens::update() must never be called (SPEC D-30).' );
		}

		final public function destroy( $token ): void {
			global $magicauth_test_state;
			unset( $magicauth_test_state['sessions'][ $this->user_id ][ $this->hash_token( (string) $token ) ] );
		}

		final public function destroy_others( $token_to_keep ): void {
			global $magicauth_test_state;
			$keep     = $this->hash_token( (string) $token_to_keep );
			$sessions = $magicauth_test_state['sessions'][ $this->user_id ] ?? [];
			$magicauth_test_state['sessions'][ $this->user_id ] = isset( $sessions[ $keep ] ) ? [ $keep => $sessions[ $keep ] ] : [];
		}

		final public function destroy_all(): void {
			global $magicauth_test_state;
			$magicauth_test_state['sessions'][ $this->user_id ] = [];
		}

		/** @return array<int,array<string,mixed>> */
		final public function get_all(): array {
			global $magicauth_test_state;
			return array_values( $magicauth_test_state['sessions'][ $this->user_id ] ?? [] );
		}
	}
}
