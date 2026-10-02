<?php


namespace MagicAuth\ThirdParty\Passkeys\CBOR;
defined( 'ABSPATH' ) || exit;
// phpcs:disable WordPress.Security.EscapeOutput.ExceptionNotEscaped -- static messages (R4), int class-constant codes; nothing is output.
use MagicAuth\ThirdParty\Passkeys\WebAuthnException;
use MagicAuth\ThirdParty\Passkeys\Binary\ByteBuffer;

/**
 * Modified version of https://github.com/madwizard-thomas/webauthn-server/blob/master/src/Format/CborDecoder.php
 * Copyright © 2018 Thomas Bleeker - MIT licensed
 * Modified by Lukas Buchs
 * Thanks Thomas for your work!
 */
class CborDecoder {
    const CBOR_MAJOR_UNSIGNED_INT = 0;
    const CBOR_MAJOR_TEXT_STRING = 3;
    const CBOR_MAJOR_FLOAT_SIMPLE = 7;
    const CBOR_MAJOR_NEGATIVE_INT = 1;
    const CBOR_MAJOR_ARRAY = 4;
    const CBOR_MAJOR_TAG = 6;
    const CBOR_MAJOR_MAP = 5;
    const CBOR_MAJOR_BYTE_STRING = 2;

    // Deepest nesting of arrays, maps and tags; WebAuthn structures nest 3 deep.
    const MAX_DEPTH = 16;

    /**
     * @param ByteBuffer|string $bufOrBin
     * @return mixed
     * @throws WebAuthnException
     */
    public static function decode($bufOrBin) {
        $buf = $bufOrBin instanceof ByteBuffer ? $bufOrBin : new ByteBuffer($bufOrBin);

        $offset = 0;
        $result = self::_parseItem($buf, $offset);
        if ($offset !== $buf->getLength()) {
            throw new WebAuthnException('Unused bytes after data item.', WebAuthnException::CBOR);
        }
        return $result;
    }

    /**
     * @param ByteBuffer|string $bufOrBin
     * @param int $startOffset
     * @param int|null $endOffset
     * @return mixed
     */
    public static function decodeInPlace($bufOrBin, $startOffset, &$endOffset = null) {
        $buf = $bufOrBin instanceof ByteBuffer ? $bufOrBin : new ByteBuffer($bufOrBin);

        $offset = $startOffset;
        $data = self::_parseItem($buf, $offset);
        $endOffset = $offset;
        return $data;
    }

    // ---------------------
    // protected
    // ---------------------

    /**
     * @param ByteBuffer $buf
     * @param int $offset
     * @param int $depth nesting level of this item, 0 at the top
     * @return mixed
     */
    protected static function _parseItem(ByteBuffer $buf, &$offset, $depth = 0) {
        if ($depth > self::MAX_DEPTH) {
            throw new WebAuthnException('Maximum nesting depth exceeded.', WebAuthnException::CBOR);
        }

        $first = $buf->getByteVal($offset++);
        $type = $first >> 5;
        $val = $first & 0b11111;

        if ($type === self::CBOR_MAJOR_FLOAT_SIMPLE) {
            return self::_parseFloatSimple($val, $buf, $offset);
        }

        $val = self::_parseExtraLength($val, $buf, $offset);

        return self::_parseItemData($type, $val, $buf, $offset, $depth);
    }

    protected static function _parseFloatSimple($val, ByteBuffer $buf, &$offset) {
        switch ($val) {
            case 24:
                $val = $buf->getByteVal($offset);
                $offset++;
                return self::_parseSimple($val);

            case 25:
                $floatValue = $buf->getHalfFloatVal($offset);
                $offset += 2;
                return $floatValue;

            case 26:
                $floatValue = $buf->getFloatVal($offset);
                $offset += 4;
                return $floatValue;

            case 27:
                $floatValue = $buf->getDoubleVal($offset);
                $offset += 8;
                return $floatValue;

            case 28:
            case 29:
            case 30:
                throw new WebAuthnException('Reserved value used.', WebAuthnException::CBOR);

            case 31:
                throw new WebAuthnException('Indefinite length is not supported.', WebAuthnException::CBOR);
        }

        return self::_parseSimple($val);
    }

    /**
     * @param int $val
     * @return mixed
     * @throws WebAuthnException
     */
    protected static function _parseSimple($val) {
        if ($val === 20) {
            return false;
        }
        if ($val === 21) {
            return true;
        }
        if ($val === 22) {
            return null;
        }
        throw new WebAuthnException('Unsupported simple value.', WebAuthnException::CBOR);
    }

    protected static function _parseExtraLength($val, ByteBuffer $buf, &$offset) {
        switch ($val) {
            case 24:
                $val = $buf->getByteVal($offset);
                $offset++;
                break;

            case 25:
                $val = $buf->getUint16Val($offset);
                $offset += 2;
                break;

            case 26:
                $val = $buf->getUint32Val($offset);
                $offset += 4;
                break;

            case 27:
                $val = $buf->getUint64Val($offset);
                $offset += 8;
                break;

            case 28:
            case 29:
            case 30:
                throw new WebAuthnException('Reserved value used.', WebAuthnException::CBOR);

            case 31:
                throw new WebAuthnException('Indefinite length is not supported.', WebAuthnException::CBOR);
        }

        return $val;
    }

    protected static function _parseItemData($type, $val, ByteBuffer $buf, &$offset, $depth = 0) {
        switch ($type) {
            case self::CBOR_MAJOR_UNSIGNED_INT: // uint
                return $val;

            case self::CBOR_MAJOR_NEGATIVE_INT:
                return -1 - $val;

            case self::CBOR_MAJOR_BYTE_STRING:
                $data = $buf->getBytes($offset, $val);
                $offset += $val;
                return new ByteBuffer($data); // bytes

            case self::CBOR_MAJOR_TEXT_STRING:
                $data = $buf->getBytes($offset, $val);
                $offset += $val;
                return $data; // UTF-8

            case self::CBOR_MAJOR_ARRAY:
                return self::_parseArray($buf, $offset, $val, $depth + 1);

            case self::CBOR_MAJOR_MAP:
                return self::_parseMap($buf, $offset, $val, $depth + 1);

            case self::CBOR_MAJOR_TAG:
                return self::_parseItem($buf, $offset, $depth + 1); // 1 embedded data item
        }

        // This should never be reached
        throw new WebAuthnException('Unknown major type.', WebAuthnException::CBOR);
    }

    protected static function _parseMap(ByteBuffer $buf, &$offset, $count, $depth = 1) {
        $map = array();

        for ($i = 0; $i < $count; $i++) {
            $mapKey = self::_parseItem($buf, $offset, $depth);
            $mapVal = self::_parseItem($buf, $offset, $depth);

            if (!\is_int($mapKey) && !\is_string($mapKey)) {
                throw new WebAuthnException('Can only use strings or integers as map keys', WebAuthnException::CBOR);
            }

            // PHP turns a text key such as "3" into the integer key 3.
            if (\is_string($mapKey) && \is_int(\array_key_first([$mapKey => true]))) {
                throw new WebAuthnException('Numeric text map key.', WebAuthnException::CBOR);
            }

            // CTAP2 canonical CBOR has no duplicate keys.
            if (\array_key_exists($mapKey, $map)) {
                throw new WebAuthnException('Duplicate map key.', WebAuthnException::CBOR);
            }

            $map[$mapKey] = $mapVal;
        }
        return $map;
    }

    protected static function _parseArray(ByteBuffer $buf, &$offset, $count, $depth = 1) {
        $arr = array();
        for ($i = 0; $i < $count; $i++) {
            $arr[] = self::_parseItem($buf, $offset, $depth);
        }

        return $arr;
    }
}
