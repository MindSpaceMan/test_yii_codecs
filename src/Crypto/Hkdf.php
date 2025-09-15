<?php
// src/Crypto/Hkdf.php
declare(strict_types=1);

namespace WApp\StreamCrypto\Crypto;

final class Hkdf
{
    /**
     * HKDF-Expand (SHA-256)
     * @param string $ikm    Input key material (32 bytes here)
     * @param int    $length Output length (112)
     * @param string $info   Context string
     */
    public static function expandSha256(string $ikm, int $length, string $info = ''): string
    {
        $hashLen = 32;
        $blocks  = (int) \ceil($length / $hashLen);
        $okm = '';
        $t = '';
        for ($i = 1; $i <= $blocks; $i++) {
            $t = \hash_hmac('sha256', $t . $info . \chr($i), $ikm, true);
            $okm .= $t;
        }
        return \substr($okm, 0, $length);
    }
}