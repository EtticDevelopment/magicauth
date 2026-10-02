<?php

namespace MagicAuth\ThirdParty\Passkeys\Attestation;
defined( 'ABSPATH' ) || exit;
// phpcs:disable WordPress.Security.EscapeOutput.ExceptionNotEscaped -- static messages (R4), int class-constant codes; nothing is output.
use MagicAuth\ThirdParty\Passkeys\WebAuthnException;
use MagicAuth\ThirdParty\Passkeys\CBOR\CborDecoder;
use MagicAuth\ThirdParty\Passkeys\Binary\ByteBuffer;

/**
 * @author Lukas Buchs
 * @license https://github.com/report-uri/passkeys-php/blob/master/LICENSE MIT
 */
class AttestationObject {
    private $_authenticatorData;

    /**
     * @param string $binary attestationObject from the browser
     * @param string|null $clientDataHash SHA-256 of clientDataJSON, needed to verify packed self attestation
     * @throws WebAuthnException
     */
    public function __construct($binary, $clientDataHash = null) {
        $enc = CborDecoder::decode($binary);

        if (!\is_array($enc) || !\array_key_exists('fmt', $enc) || !\is_string($enc['fmt'])) {
            throw new WebAuthnException('invalid attestation format', WebAuthnException::INVALID_DATA);
        }

        if (!\array_key_exists('attStmt', $enc) || !\is_array($enc['attStmt'])) {
            throw new WebAuthnException('invalid attestation format (attStmt not available)', WebAuthnException::INVALID_DATA);
        }

        if (!\array_key_exists('authData', $enc) || !\is_object($enc['authData']) || !($enc['authData'] instanceof ByteBuffer)) {
            throw new WebAuthnException('invalid attestation format (authData not available)', WebAuthnException::INVALID_DATA);
        }

        $this->_authenticatorData = new AuthenticatorData($enc['authData']->getBinaryString());

        // The RP requests attestation: 'none'. Accepted: fmt 'none' with an
        // empty attStmt, and packed self attestation, which L3 create() (5.1.3)
        // forwards unchanged under 'none' and 7.1 step 24 accepts by policy.
        // Every other fmt, and packed with x5c (full attestation), is rejected.
        if ($enc['fmt'] === 'packed') {
            $this->_verifyPackedSelfAttestation($enc['attStmt'], $enc['authData']->getBinaryString(), $clientDataHash);
            return;
        }

        if ($enc['fmt'] !== 'none') {
            throw new WebAuthnException('invalid attestation format', WebAuthnException::INVALID_DATA);
        }

        if (\count($enc['attStmt']) !== 0) {
            throw new WebAuthnException('invalid none attestation: attStmt must be empty', WebAuthnException::INVALID_DATA);
        }
    }

    /**
     * @return AuthenticatorData
     */
    public function getAuthenticatorData() {
        return $this->_authenticatorData;
    }

    /**
     * checks if the RpId-Hash is valid
     * @param string $rpIdHash
     * @return bool
     */
    public function validateRpIdHash($rpIdHash) {
        return $rpIdHash === $this->_authenticatorData->getRpIdHash();
    }

    /**
     * Packed self attestation (L3 8.2, self attestation branch): attStmt is
     * exactly {alg, sig}, alg is the credential key's COSE alg, the AAGUID is
     * zero, and sig verifies over authData || clientDataHash with the
     * credential public key.
     * @param array $attStmt
     * @param string $authData
     * @param string|null $clientDataHash
     * @throws WebAuthnException
     */
    private function _verifyPackedSelfAttestation($attStmt, $authData, $clientDataHash) {
        if (\count($attStmt) !== 2 || !\array_key_exists('alg', $attStmt) || !\array_key_exists('sig', $attStmt)) {
            throw new WebAuthnException('invalid packed attestation: only self attestation is supported', WebAuthnException::INVALID_DATA);
        }

        if (!\is_int($attStmt['alg']) || $attStmt['alg'] !== $this->_authenticatorData->getCredentialPublicKeyAlg()) {
            throw new WebAuthnException('invalid packed attestation: alg', WebAuthnException::INVALID_DATA);
        }

        if (!($attStmt['sig'] instanceof ByteBuffer)) {
            throw new WebAuthnException('invalid packed attestation: sig', WebAuthnException::INVALID_DATA);
        }

        if ($this->_authenticatorData->getAAGUID() !== \str_repeat("\0", 16)) {
            throw new WebAuthnException('invalid packed attestation: AAGUID', WebAuthnException::INVALID_DATA);
        }

        if (!\is_string($clientDataHash) || \strlen($clientDataHash) !== 32) {
            throw new WebAuthnException('invalid packed attestation: client data hash', WebAuthnException::INVALID_DATA);
        }

        if (!$this->_verifySelfSignature($authData . $clientDataHash, $attStmt['sig']->getBinaryString(), $attStmt['alg'])) {
            throw new WebAuthnException('invalid packed attestation signature', WebAuthnException::INVALID_SIGNATURE);
        }
    }

    /**
     * Verifies a signature with the credential public key: ES256 DER and
     * RS256 PKCS#1 v1.5 through OpenSSL, EdDSA (exactly 64 bytes) through
     * sodium or OpenSSL on the same branches as WebAuthn::_verifySignature().
     * @param string $data
     * @param string $signature
     * @param int $alg
     * @return bool
     */
    private function _verifySelfSignature($data, $signature, $alg) {
        $pem = $this->_authenticatorData->getPublicKeyPem();

        if ($alg === -8) {
            if (\strlen($signature) !== 64) {
                return false;
            }

            if (\function_exists('sodium_crypto_sign_verify_detached') && !defined('OPENSSL_KEYTYPE_ED25519')) {
                $der = \base64_decode((string) \preg_replace('/-----[A-Z ]+-----|\s+/', '', $pem), true);
                $okpPrefix = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00";
                if (!\is_string($der) || \strlen($der) !== 44 || \substr($der, 0, 12) !== $okpPrefix) {
                    return false;
                }
                return \sodium_crypto_sign_verify_detached($signature, $data, \substr($der, 12));
            }

            if (!defined('OPENSSL_KEYTYPE_ED25519')) {
                return false;
            }
        }

        $publicKey = \openssl_pkey_get_public($pem);
        if ($publicKey === false) {
            return false;
        }

        // algorithm 0 for EdDSA, which has a built-in hash
        return \openssl_verify($data, $signature, $publicKey, $alg === -8 ? 0 : OPENSSL_ALGO_SHA256) === 1;
    }
}
