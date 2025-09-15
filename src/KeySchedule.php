<?php
// src/KeySchedule.php
declare(strict_types=1);

namespace WApp\StreamCrypto;

use WApp\StreamCrypto\Crypto\Hkdf;

final class KeySchedule
{
    public const EXPANDED_LEN = 112; // 16 + 32 + 32 + 32

    public static function derive(string $mediaKey32, MediaType $type): array
    {
        if (\strlen($mediaKey32) !== 32) {
            throw new \InvalidArgumentException('mediaKey must be 32 bytes');
        }

        $expanded = Hkdf::expandSha256($mediaKey32, self::EXPANDED_LEN, $type->hkdfInfo());

        $iv        = \substr($expanded, 0, 16);
        $cipherKey = \substr($expanded, 16, 32);
        $macKey    = \substr($expanded, 48, 32);
        $refKey    = \substr($expanded, 80); // not used

        return [$iv, $cipherKey, $macKey, $refKey];
    }
}