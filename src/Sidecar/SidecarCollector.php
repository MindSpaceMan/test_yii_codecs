<?php
// src/Sidecar/SidecarCollector.php
declare(strict_types=1);

namespace WApp\StreamCrypto\Sidecar;

use WApp\StreamCrypto\Crypto\Mac;

final class SidecarCollector
{
    private const K = 65536;
    private const OVERLAP = 16;

    private string $buffer = '';  // скользящее окно enc данных
    private string $sidecar = '';
    private int $nextStart = 0;   // старт следующего окна
    private ?string $macKey = null;

    public function onCiphertextChunk(string $cipherChunk): void
    {
        $this->buffer .= $cipherChunk;

        // пока у нас хватает байт, считаем окно
        while (\strlen($this->buffer) >= ($this->nextStart + self::K + self::OVERLAP)) {
            $slice = \substr($this->buffer, $this->nextStart, self::K + self::OVERLAP);
            if ($this->macKey) {
                $this->sidecar .= Mac::hmacSha256($this->macKey, $slice, 10);
            }
            $this->nextStart += self::K;
        }

        // чистим «левую» часть буфера, которая больше не понадобится
        if ($this->nextStart > 0) {
            $this->buffer = \substr($this->buffer, $this->nextStart);
            $this->nextStart = 0;
        }
    }

    public function finalize(string $macKey): void
    {
        $this->macKey = $macKey;

        // добиваем все окна, которые можно сформировать на остатках
        while (\strlen($this->buffer) >= (self::K + self::OVERLAP)) {
            $slice = \substr($this->buffer, 0, self::K + self::OVERLAP);
            $this->sidecar .= Mac::hmacSha256($macKey, $slice, 10);
            $this->buffer = \substr($this->buffer, self::K); // сдвиг на 64K (перекрытие 16 байт учтено в слайсе)
        }

        // крайний частичный чанк (если остался) — тоже подписываем
        if ($this->buffer !== '') {
            $this->sidecar .= Mac::hmacSha256($macKey, $this->buffer, 10);
            $this->buffer = '';
        }
    }

    public function sidecar(): string
    {
        return $this->sidecar;
    }
}