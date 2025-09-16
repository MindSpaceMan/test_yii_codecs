<?php
// src/Stream/EncryptingStream.php
declare(strict_types=1);

namespace WApp\StreamCrypto\Stream;

use Psr\Http\Message\StreamInterface;
use WApp\StreamCrypto\KeySchedule;
use WApp\StreamCrypto\MediaType;
use WApp\StreamCrypto\Crypto\Mac;
use WApp\StreamCrypto\Exception\StreamException;
use WApp\StreamCrypto\Sidecar\SidecarCollector;

final class EncryptingStream implements StreamInterface
{
    private const BLOCK = 16;
    private const IN_CHUNK = 8192;

    private StreamInterface $in;

    private string $cipherKey;
    private string $prev;          // предыдущий шифроблок (IV сначала)

    /** @var resource HMAC контекст */
    private $hmacCtx;

    private string $tail = '';     // неполный plaintext < 16
    private string $outBuf = '';   // готовые к выдаче байты
    private int    $outPos = 0;    // смещение внутри outBuf

    private bool   $srcEof = false;
    private bool   $macAppended = false;

    private ?SidecarCollector $sidecar;

    public function __construct(
        StreamInterface $plain,
        string $mediaKey32,
        MediaType $type,
        ?SidecarCollector $sidecar = null
    ) {
        $this->in = $plain;
        [$iv, $ck, $mk] = KeySchedule::derive($mediaKey32, $type);
        $this->cipherKey = $ck;
        $this->prev = $iv;
        $this->hmacCtx = \hash_init('sha256', \HASH_HMAC, $mk);
        \hash_update($this->hmacCtx, $iv); // H(iv || enc)
        $this->sidecar = $sidecar?->withMacKey($mk) ?? null;
    }

    private function encryptBlock(string $plainBlock, bool $isFinal): string
    {
        // CBC делаем вручную: XOR с prev, затем AES-ECB без паддинга
        $xored = $plainBlock ^ $this->prev;
        $c = \openssl_encrypt($xored, 'aes-256-ecb', $this->cipherKey, \OPENSSL_RAW_DATA|\OPENSSL_ZERO_PADDING);
        if ($c === false) { throw new \RuntimeException('openssl_encrypt failed'); }
        $this->prev = $c;

        // HMAC на лету
        \hash_update($this->hmacCtx, $c);

        // sidecar окно питаем шифротекстом
        $this->sidecar?->feed($c);

        return $c;
    }

    private function pump(int $need): void
    {
        if ($this->macAppended) { return; }

        // подаём столько шифротекста, чтобы покрыть запрос
        while ((\strlen($this->outBuf) - $this->outPos) < $need && !$this->macAppended) {

            if (!$this->srcEof) {
                $chunk = $this->in->read(self::IN_CHUNK);
                if ($chunk === '') { $this->srcEof = true; }
                else { $this->tail .= $chunk; }
            }

            if (!$this->srcEof && \strlen($this->tail) < self::BLOCK) {
                // ждём ещё данных
                break;
            }

            if ($this->srcEof) {
                // финальный паддинг
                $pad = self::BLOCK - (\strlen($this->tail) % self::BLOCK);
                if ($pad === 0) { $pad = self::BLOCK; }
                $this->tail .= \str_repeat(\chr($pad), $pad);

                // шифруем все блоки (включая паддинг)
                for ($i = 0, $n = \strlen($this->tail); $i < $n; $i += self::BLOCK) {
                    $block = \substr($this->tail, $i, self::BLOCK);
                    $this->outBuf .= $this->encryptBlock($block, true);
                }
                $this->tail = '';

                // HMAC финализируем и дописываем 10 байт MAC
                $mac10 = \substr(\hash_final($this->hmacCtx, true), 0, 10);
                $this->sidecar?->finalize(); // докинет последние окна
                $this->outBuf .= $mac10;
                $this->macAppended = true;
                break;
            }

            // у нас есть >= 16 байт, отдадим целые блоки
            $emitLen = \strlen($this->tail) - (\strlen($this->tail) % self::BLOCK);
            if ($emitLen > 0) {
                for ($i = 0; $i < $emitLen; $i += self::BLOCK) {
                    $block = \substr($this->tail, $i, self::BLOCK);
                    $this->outBuf .= $this->encryptBlock($block, false);
                }
                $this->tail = \substr($this->tail, $emitLen);
            }
        }

        // небольшой «гарбедж-коллектор» для outBuf, чтобы не рос из-за outPos
        if ($this->outPos > 1 << 20 || $this->outPos === \strlen($this->outBuf)) {
            $this->outBuf = \substr($this->outBuf, $this->outPos);
            $this->outPos = 0;
        }
    }

    // --- PSR-7 ---

    public function __toString(): string
    { try { $this->rewind(); return $this->getContents(); } catch (\Throwable) { return ''; } }
    public function close(): void {}
    public function detach(){ return null; }
    public function getSize(): ?int
    { return null; }
    public function tell(): int
    { return $this->outPos; }
    public function eof(): bool { return $this->macAppended && $this->outPos >= \strlen($this->outBuf); }
    public function isSeekable(): bool { return false; }
    public function seek($offset, $whence = SEEK_SET): void
    { throw new StreamException('EncryptingStream is not seekable'); }
    public function rewind(): void
    { $this->outBuf=''; $this->outPos=0; $this->tail=''; $this->srcEof=true; /* не поддерживаем повтор */ }
    public function isWritable(): bool { return false; }
    public function write($string): int
    { throw new StreamException('read-only'); }
    public function isReadable(): bool { return true; }

    public function read($length): string
    {
        if ($length <= 0) { return ''; }
        if (!$this->macAppended) { $this->pump($length); }

        $available = \strlen($this->outBuf) - $this->outPos;
        $n = \max(0, \min($length, $available));
        $out = $n ? \substr($this->outBuf, $this->outPos, $n) : '';
        $this->outPos += $n;
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

    public function getSidecarBytes(): ?string
    {
        return $this->sidecar?->sidecar();
    }
}