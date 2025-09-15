<?php
// src/Stream/DecryptingStream.php
declare(strict_types=1);

namespace WApp\StreamCrypto\Stream;

use Psr\Http\Message\StreamInterface;
use WApp\StreamCrypto\KeySchedule;
use WApp\StreamCrypto\MediaType;
use WApp\StreamCrypto\Crypto\AesCbc;
use WApp\StreamCrypto\Crypto\Mac;
use WApp\StreamCrypto\Exception\MacMismatch;
use WApp\StreamCrypto\Exception\StreamException;
use GuzzleHttp\Psr7\Utils;

final class DecryptingStream implements StreamInterface
{
    private const BLOCK = 16;
    private StreamInterface $plain;  // раскодированный буфер (php://temp)
    private int $cursor = 0;

    public function __construct(StreamInterface $encryptedWithMac, string $mediaKey32, MediaType $type)
    {
        [$iv, $ck, $mk] = KeySchedule::derive($mediaKey32, $type);

        // читаем enc+mac в temp
        $tmp = Util::tempStream();
        $encryptedWithMac->rewind();
        while (!$encryptedWithMac->eof()) {
            $tmp->write($encryptedWithMac->read(8192));
        }
        $data = Util::readAll($tmp);

        if (\strlen($data) < 10) {
            throw new StreamException('Encrypted payload too short');
        }

        $macGiven = \substr($data, -10);
        $enc = \substr($data, 0, -10);

        // валидация MAC (H(iv||enc)[:10])
        $calc = Mac::hmacSha256($mk, $iv . $enc, 10);
        if (!Mac::equals($calc, $macGiven)) {
            throw new MacMismatch('HMAC mismatch');
        }

        // потоковая расшифровка блоками
        $plainTmp = Utils::streamFor(\fopen('php://temp', 'w+b'));

        $pos = 0;
        $n   = \strlen($enc);
        while ($n - $pos > self::BLOCK) {
            $chunkLen = ((int)\floor(($n - $pos - self::BLOCK)/self::BLOCK)) * self::BLOCK;
            $chunkLen = \max($chunkLen, 0);
            if ($chunkLen === 0) break;
            $chunk = \substr($enc, $pos, $chunkLen);
            $pos  += $chunkLen;
            $plainTmp->write(AesCbc::decryptBlocks($chunk, $ck, $iv, false));
            $iv = \substr($chunk, -self::BLOCK);
        }

        // финальный блок (с паддингом)
        $final = \substr($enc, $pos);
        $plainTmp->write(AesCbc::decryptBlocks($final, $ck, $iv, true));
        $plainTmp->rewind();

        $this->plain = $plainTmp;
    }

    // --- StreamInterface passthrough for $plain ---

    public function __toString(): string
    { try { $this->rewind(); return $this->getContents(); } catch (\Throwable) { return ''; } }
    public function close(): void { $this->plain->close(); }
    public function detach(){ return $this->plain->detach(); }
    public function getSize(): ?int
    { return $this->plain->getSize(); }
    public function tell(): int
    { return $this->plain->tell(); }
    public function eof(): bool { return $this->plain->eof(); }
    public function isSeekable(): bool { return $this->plain->isSeekable(); }
    public function seek($offset, $whence = SEEK_SET): void
    { $this->plain->seek($offset, $whence); }
    public function rewind(): void
    { $this->plain->rewind(); }
    public function isWritable(): bool { return false; }
    public function write($string): int
    { throw new StreamException('DecryptingStream is read-only'); }
    public function isReadable(): bool { return $this->plain->isReadable(); }
    public function read($length): string { return $this->plain->read($length); }
    public function getContents(): string { return $this->plain->getContents(); }
    public function getMetadata($key = null){ return $this->plain->getMetadata($key); }
}