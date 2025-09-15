<?php
// src/Stream/EncryptingStream.php
declare(strict_types=1);

namespace WApp\StreamCrypto\Stream;

use Psr\Http\Message\StreamInterface;
use WApp\StreamCrypto\KeySchedule;
use WApp\StreamCrypto\MediaType;
use WApp\StreamCrypto\Crypto\AesCbc;
use WApp\StreamCrypto\Crypto\Mac;
use WApp\StreamCrypto\Exception\StreamException;
use WApp\StreamCrypto\Sidecar\SidecarCollector;

final class EncryptingStream implements StreamInterface
{
    private const BLOCK = 16;
    private const CHUNK = 8192; // чтение из источника

    private StreamInterface $in;
    private string $iv;
    private string $cipherKey;
    private string $macKey;

    private string $encBuf = '';     // зашифрованные данные, ещё не выданные наружу
    private string $macState;        // накапливаем H(iv||enc) — через update
    private bool   $sourceEof = false;
    private bool   $finalized = false;
    private int    $cursor = 0;      // позиция чтения наружу

    // для «звёздочки»: сборка сайдкара без второго прохода
    private ?\WApp\StreamCrypto\Sidecar\SidecarCollector $sidecar = null;

    public function __construct(StreamInterface $plain, string $mediaKey32, MediaType $type, SidecarCollector $collector = null)
    {
        $this->in = $plain;
        [$iv, $ck, $mk] = KeySchedule::derive($mediaKey32, $type);
        $this->iv = $iv;
        $this->cipherKey = $ck;
        $this->macKey = $mk;

        $this->macState = $iv; // H(iv || enc), начальная часть — iv
        $this->sidecar = $collector;
    }

    private function pump(): void
    {
        if ($this->finalized) { return; }

        // читаем сырой plaintext
        $chunk = $this->in->read(self::CHUNK);
        if ($chunk === '') {
            $this->sourceEof = true;
        }

        // накопим до целых блоков, финальный блок паддим
        static $tail = '';
        $tail .= $chunk;

        if (!$this->sourceEof && \strlen($tail) < self::BLOCK) {
            return; // мало данных
        }

        $toEnc = $tail;
        $isFinal = false;

        if (!$this->sourceEof) {
            $rem = \strlen($toEnc) % self::BLOCK;
            if ($rem !== 0) {
                $emit = \substr($toEnc, 0, -$rem);
                $tail = \substr($toEnc, -$rem);
                $toEnc = $emit;
            } else {
                $tail = '';
            }
        } else {
            // источник закончился — паддим финальный блок
            $isFinal = true;
            $tail = '';
        }

        if ($toEnc !== '') {
            $cipher = AesCbc::encryptBlocks($toEnc, $this->cipherKey, $this->iv, $isFinal);
            // обновляем IV цепочки
            if ($isFinal) {
                $last = \substr($cipher, -self::BLOCK);
                $this->iv = $last; // уже не важно, но логично
            } else {
                $this->iv = \substr($cipher, -self::BLOCK);
            }

            // апдейтим MAC и sidecar
            $this->macState .= $cipher;
            if ($this->sidecar) { $this->sidecar->onCiphertextChunk($cipher); }

            $this->encBuf .= $cipher;
        }

        if ($this->sourceEof) {
            // финализация: считаем MAC(iv||enc) и дописываем 10 байт
            $mac = Mac::hmacSha256($this->macKey, $this->macState, 10);
            if ($this->sidecar) { $this->sidecar->finalize($this->macKey); }
            $this->encBuf .= $mac;
            $this->finalized = true;
        }
    }

    // --- StreamInterface (read-only) ---

    public function __toString(): string
    { try { $this->rewind(); return $this->getContents(); } catch (\Throwable) { return ''; } }
    public function close(): void {}
    public function detach(){ return null; }
    public function getSize(): ?int
    { return null; }
    public function tell(): int
    { return $this->cursor; }
    public function eof(): bool { return $this->finalized && $this->cursor >= \strlen($this->encBuf); }
    public function isSeekable(): bool { return false; }
    public function seek($offset, $whence = SEEK_SET): void
    { throw new StreamException('EncryptingStream is not seekable'); }
    public function rewind(): void
    { $this->cursor = 0; }
    public function isWritable(): bool { return false; }
    public function write($string): int
    { throw new StreamException('EncryptingStream is read-only'); }
    public function isReadable(): bool { return true; }

    public function read($length): string
    {
        while (!$this->finalized && \strlen($this->encBuf) - $this->cursor < $length) {
            $this->pump();
            if (!$this->finalized && $this->encBuf === '') {
                // ждём больше данных
                break;
            }
        }

        $available = \strlen($this->encBuf) - $this->cursor;
        $n = \max(0, \min($length, $available));

        $out = \substr($this->encBuf, $this->cursor, $n);
        $this->cursor += $n;
        return $out;
    }

    public function getContents(): string
    {
        $buf = '';
        while (!$this->eof()) {
            $buf .= $this->read(8192);
        }
        return $buf;
    }

    public function getMetadata($key = null){ return null; }

    // для «звёздочки»
    public function getSidecarBytes(): ?string
    {
        return $this->sidecar?->sidecar();
    }
}