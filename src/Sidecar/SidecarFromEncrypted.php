<?php
// src/Sidecar/SidecarFromEncrypted.php
declare(strict_types=1);

namespace WApp\StreamCrypto\Sidecar;

use Psr\Http\Message\StreamInterface;
use WApp\StreamCrypto\Crypto\Mac;

final class SidecarFromEncrypted
{
    private const K = 65536;
    private const OVERLAP = 16;

    public static function generate(StreamInterface $encrypted, string $macKey): string
    {
        $encrypted->rewind();
        $data = $encrypted->getContents(); // если большой — переделай на итеративный сдвиг окна
        $len = \strlen($data);

        $out = '';
        for ($start = 0; $start < $len; $start += self::K) {
            $end = \min($len, $start + self::K + self::OVERLAP);
            $slice = \substr($data, $start, $end - $start);
            $out .= Mac::hmacSha256($macKey, $slice, 10);
        }
        return $out;
    }
}