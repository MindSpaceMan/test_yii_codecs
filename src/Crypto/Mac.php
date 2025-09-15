<?php
// src/Crypto/Mac.php
declare(strict_types=1);

namespace WApp\StreamCrypto\Crypto;

final class Mac
{
    public static function hmacSha256(string $key, string $data, int $truncate = 0): string
    {
        $h = \hash_hmac('sha256', $data, $key, true);
        return $truncate > 0 ? \substr($h, 0, $truncate) : $h;
    }

    public static function equals(string $a, string $b): bool
    {
        return \hash_equals($a, $b);
    }
}