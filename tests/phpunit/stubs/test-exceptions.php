<?php
/**
 * Exceptions thrown by stubs whose real counterparts end the request
 * (wp_send_json*, wp_die from check_ajax_referer, opt-in redirects).
 *
 * @package MagicAuth\Tests
 */

declare( strict_types=1 );

namespace MagicAuth\Tests\Stubs;

/** Thrown by wp_send_json*() and a failed check_ajax_referer(); the real ones exit. */
final class JsonResponseSent extends \RuntimeException {

	/** @var mixed */
	public $payload;

	public ?int $status;

	public string $body;

	/**
	 * @param mixed $payload Response value as passed to wp_send_json().
	 */
	public function __construct( $payload, ?int $status, string $body ) {
		parent::__construct( 'JSON response sent' );
		$this->payload = $payload;
		$this->status  = $status;
		$this->body    = $body;
	}
}

/** Thrown by wp_safe_redirect()/wp_redirect() when $magicauth_test_state['redirect_throws'] is true. */
final class RedirectSent extends \RuntimeException {

	public string $location;

	public int $status;

	public function __construct( string $location, int $status ) {
		parent::__construct( 'Redirect sent' );
		$this->location = $location;
		$this->status   = $status;
	}
}
