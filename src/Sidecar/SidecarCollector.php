<?php
// src/Sidecar/SidecarCollector.php
declare(strict_types=1);

namespace WApp\StreamCrypto\Sidecar;

final class SidecarCollector
{
    private const K = 65536;
    private const OVERLAP = 16;

    private string $macKey;
    private string $buf = '';      // окно начиная с $bufStart
    private int    $bufStart = 0;  // абсолютный оффсет начала buf
    private int    $total = 0;     // сколько шифротекста обработано всего
    private int    $nextStart = 0; // абсолютный оффсет начала следующего окна n*64K
    private string $sidecar = '';

    public function withMacKey(string $macKey): self
    {
        $this->macKey = $macKey;
        return $this;
    }

    /** Кормим готовым шифротекстом (любого размера) */
    public function feed(string $cipherChunk): void
    {
        $this->buf .= $cipherChunk;
        $this->total += \strlen($cipherChunk);

        // пока доступно окно [nextStart, nextStart+K+16]
        while ($this->bufStart + \strlen($this->buf) >= $this->nextStart + self::K + self::OVERLAP) {
            $local = $this->nextStart - $this->bufStart;
            $slice = \substr($this->buf, $local, self::K + self::OVERLAP);
            $this->sidecar .= \substr(\hash_hmac('sha256', $slice, $this->macKey, true), 0, 10);
            $this->nextStart += self::K;

            // можно отбросить всё левее nextStart — больше не понадобится
            $drop = $this->nextStart - $this->bufStart;
            if ($drop > 0 && $drop <= \strlen($this->buf)) {
                $this->buf = \substr($this->buf, $drop);
                $this->bufStart += $drop;
            }
        }
    }

    /** Завершаем и подписываем последний неполный кусок (если остался) */
    public function finalize(): void
    {
        // после EOF генерим все оставшиеся окна, включая последнее частичное
        while ($this->bufStart < $this->total) {
            $end = \min($this->total, $this->nextStart + self::K + self::OVERLAP);
            if ($end <= $this->nextStart) { break; }
            $localStart = $this->nextStart - $this->bufStart;
            if ($localStart < 0) { $localStart = 0; }
            $slice = \substr($this->buf, $localStart, $end - $this->nextStart);
            if ($slice === '') { break; }
            $this->sidecar .= \substr(\hash_hmac('sha256', $slice, $this->macKey, true), 0, 10);
            $this->nextStart += self::K;

            // отбрасываем ненужное слева
            $drop = $this->nextStart - $this->bufStart;
            if ($drop > 0 && $drop <= \strlen($this->buf)) {
                $this->buf = \substr($this->buf, $drop);
                $this->bufStart += $drop;
            } else {
                break;
            }
        }
    }

    public function sidecar(): string
    {
        return $this->sidecar;
    }
}