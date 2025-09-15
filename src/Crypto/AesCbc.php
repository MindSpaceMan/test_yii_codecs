<?php
// src/Crypto/AesCbc.php
declare(strict_types=1);

namespace WApp\StreamCrypto\Crypto;

final class AesCbc
{
    private const BLOCK = 16;

    public static function encryptBlocks(string $plain, string $key, string $iv, bool $isFinal = false): string
    {
        if ($isFinal) {
            $padLen = self::BLOCK - (\strlen($plain) % self::BLOCK);
            if ($padLen === 0) { $padLen = self::BLOCK; }
            $plain .= \str_repeat(\chr($padLen), $padLen);
        } elseif (\strlen($plain) % self::BLOCK !== 0) {
            throw new \InvalidArgumentException('encryptBlocks non-final must be multiple of 16');
        }

        $cipher = '';
        for ($i = 0, $n = \strlen($plain); $i < $n; $i += self::BLOCK) {
            $block = \substr($plain, $i, self::BLOCK);
            $xored = $block ^ $iv;
            $c = \openssl_encrypt($xored, 'aes-256-ecb', $key, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING);
            if ($c === false) {
                throw new \RuntimeException('openssl_encrypt failed');
            }
            $cipher .= $c;
            $iv = $c;
        }
        return $cipher;
    }

    public static function decryptBlocks(string $cipher, string $key, string $iv, bool $isFinal = false): string
    {
        if (!$isFinal && \strlen($cipher) % self::BLOCK !== 0) {
            throw new \InvalidArgumentException('decryptBlocks non-final must be multiple of 16');
        }

        $plain = '';
        for ($i = 0, $n = \strlen($cipher); $i < $n; $i += self::BLOCK) {
            $cblock = \substr($cipher, $i, self::BLOCK);
            $d = \openssl_decrypt($cblock, 'aes-256-ecb', $key, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING);
            if ($d === false) {
                throw new \RuntimeException('openssl_decrypt failed');
            }
            $plain .= ($d ^ $iv);
            $iv = $cblock;
        }

        if ($isFinal) {
            $last = \ord($plain[\strlen($plain)-1]);
            if ($last < 1 || $last > self::BLOCK) {
                throw new \RuntimeException('Invalid PKCS7 padding');
            }
            $pad = \substr($plain, -$last);
            if ($pad !== \str_repeat(\chr($last), $last)) {
                throw new \RuntimeException('Invalid PKCS7 padding bytes');
            }
            $plain = \substr($plain, 0, -$last);
        }

        return $plain;
    }
}