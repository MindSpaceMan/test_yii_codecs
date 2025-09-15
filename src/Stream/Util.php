<?php
// src/Stream/Util.php
declare(strict_types=1);

namespace WApp\StreamCrypto\Stream;

use Psr\Http\Message\StreamInterface;
use GuzzleHttp\Psr7\Utils;

final class Util
{
    public static function tempStream(): StreamInterface
    {
        // php://temp — держит в памяти, при росте свопает на диск
        return Utils::streamFor(\fopen('php://temp', 'w+b'));
    }

    public static function readAll(StreamInterface $s): string
    {
        $pos = $s->tell();
        $s->seek(0);
        $data = $s->getContents();
        $s->seek($pos);
        return $data;
    }
}