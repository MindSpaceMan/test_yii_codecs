<?php
// src/Stream/DecryptingStream.php
declare(strict_types=1);

namespace WApp\StreamCrypto\Stream;

use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\StreamInterface;
use WApp\StreamCrypto\Crypto\AesCbc;
use WApp\StreamCrypto\Exception\MacMismatch;
use WApp\StreamCrypto\Exception\StreamException;
use WApp\StreamCrypto\KeySchedule;
use WApp\StreamCrypto\MediaType;

final class DecryptingStream implements StreamInterface
{
    private const BLOCK   = 16; // AES-CBC block
    private const MAC_LEN = 10; // truncated HMAC-SHA256 length

    private StreamInterface $plain;

    public function __construct(StreamInterface $encryptedWithMac, string $mediaKey32, MediaType $type)
    {
        // 0) Выводим ключи
        [$iv, $cipherKey, $macKey] = KeySchedule::derive($mediaKey32, $type);

        // 1) Снимаем MAC «на лету»: подпись по (iv || ciphertext),
        //    а последние 10 байт входа — это mac (truncated).
        $h = \hash_init('sha256', \HASH_HMAC, $macKey);
        \hash_update($h, $iv);

        $encTmp = Utils::streamFor(\fopen('php://temp', 'w+b'));
        if (!$encTmp->isWritable()) {
            throw new StreamException('Cannot create temp stream for ciphertext');
        }

        // читаем вход; держим последних 10 байт в $tail
        $tail = '';
        try {
            if ($encryptedWithMac->isSeekable()) {
                $encryptedWithMac->rewind();
            }
        } catch (\Throwable) {
            // допускаем не-seekable поток — читаем «как есть»
        }

        while (!$encryptedWithMac->eof()) {
            $chunk = $encryptedWithMac->read(8192);
            if ($chunk === '') {
                break;
            }

            $tail .= $chunk;
            $len = \strlen($tail);

            if ($len > self::MAC_LEN) {
                $emit = $len - self::MAC_LEN;           // всё кроме последних 10 байт
                $feed = \substr($tail, 0, $emit);
                \hash_update($h, $feed);
                $encTmp->write($feed);
                $tail = \substr($tail, $emit);          // оставили ровно 10 байт в хвосте
            }
        }

        if (\strlen($tail) !== self::MAC_LEN) {
            throw new StreamException('Encrypted payload must end with 10-byte MAC');
        }
        $macGiven = $tail;
        $macCalc10 = \substr(\hash_final($h, true), 0, self::MAC_LEN);
        if (!\hash_equals($macCalc10, $macGiven)) {
            throw new MacMismatch('HMAC mismatch');
        }

        // 2) Потоковая расшифровка: оставляем финальный блок под PKCS7-unpad
        $encTmp->rewind();
        $plainTmp = Utils::streamFor(\fopen('php://temp', 'w+b'));

        $buf = ''; // держим «хвост» минимум в 1 блок
        while (!$encTmp->eof()) {
            $chunk = $encTmp->read(8192);
            if ($chunk === '') {
                break;
            }

            $buf .= $chunk;
            $len = \strlen($buf);

            // если данных <= 1 блока — ждём следующий кусок
            if ($len <= self::BLOCK) {
                continue;
            }

            // отдаём всё, кроме последнего блока; строго кратно 16
            $emitLen = $len - self::BLOCK;
            $emitLen -= $emitLen % self::BLOCK;

            if ($emitLen > 0) {
                $toDec = \substr($buf, 0, $emitLen);
                $plainTmp->write(AesCbc::decryptBlocks($toDec, $cipherKey, $iv, false));
                $iv = \substr($toDec, -self::BLOCK); // IV для следующего блока
                $buf = \substr($buf, $emitLen);      // в буфере остался «хвост»
            }
        }

        // В буфере должен остаться блок(и), кратные 16, последний — с PKCS7
        $bufLen = \strlen($buf);
        if ($bufLen === 0 || ($bufLen % self::BLOCK) !== 0) {
            throw new StreamException('Invalid ciphertext length (not block-aligned)');
        }

        $plainTmp->write(AesCbc::decryptBlocks($buf, $cipherKey, $iv, true));
        $plainTmp->rewind();

        $this->plain = $plainTmp;
    }

    // ---- PSR-7 passthrough ----
    public function __toString(): string
    {
        try {
            $this->rewind();
            return $this->getContents();
        } catch (\Throwable) {
            return '';
        }
    }

    public function close(): void                 { $this->plain->close(); }
    public function detach()                      { return $this->plain->detach(); }
    public function getSize(): ?int               { return $this->plain->getSize(); }
    public function tell(): int                   { return $this->plain->tell(); }
    public function eof(): bool                   { return $this->plain->eof(); }
    public function isSeekable(): bool            { return $this->plain->isSeekable(); }
    public function seek($offset, $whence = SEEK_SET): void { $this->plain->seek($offset, $whence); }
    public function rewind(): void                { $this->plain->rewind(); }
    public function isWritable(): bool            { return false; }
    public function write($string): int           { throw new StreamException('read-only'); }
    public function isReadable(): bool            { return $this->plain->isReadable(); }
    public function read($length): string         { return $this->plain->read($length); }
    public function getContents(): string         { return $this->plain->getContents(); }
    public function getMetadata($key = null)      { return $this->plain->getMetadata($key); }
}