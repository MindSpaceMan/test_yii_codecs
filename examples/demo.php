<?php
declare(strict_types=1);

use GuzzleHttp\Psr7\Utils;
use WApp\StreamCrypto\MediaType;
use WApp\StreamCrypto\Stream\EncryptingStream;
use WApp\StreamCrypto\Stream\DecryptingStream;
use WApp\StreamCrypto\Sidecar\SidecarCollector;

require __DIR__ . '/../vendor/autoload.php';

// --- CLI args ---
// php examples/demo.php IMAGE
$base = strtoupper($argv[1] ?? 'IMAGE'); // IMAGE | AUDIO | VIDEO | DOCUMENT

$typeMap = [
    'IMAGE'    => MediaType::IMAGE,
    'VIDEO'    => MediaType::VIDEO,
    'AUDIO'    => MediaType::AUDIO,
    'DOCUMENT' => MediaType::DOCUMENT,
];
if (!isset($typeMap[$base])) {
    fwrite(STDERR, "Unknown type: {$base}. Use IMAGE|AUDIO|VIDEO|DOCUMENT\n");
    exit(1);
}
$type = $typeMap[$base];

// --- paths ---
$srcDir = __DIR__ . '/../samples';
$outDir = __DIR__ . '/../out';
@mkdir($outDir, 0777, true);

// read original + key (key must be 32 raw bytes; if hex — we convert)
$origPath = "{$srcDir}/{$base}.original";
$keyPath  = "{$srcDir}/{$base}.key";
if (!is_file($origPath) || !is_file($keyPath)) {
    fwrite(STDERR, "Missing sample files for {$base} in {$srcDir}\n");
    exit(1);
}

$plain = Utils::streamFor(fopen($origPath, 'rb'));
$mediaKey = file_get_contents($keyPath);

// Allow hex-encoded keys too (in case your key file is hex, 64 chars)
if (strlen($mediaKey) === 64 && ctype_xdigit($mediaKey)) {
    $mediaKey = hex2bin($mediaKey);
}
if (strlen($mediaKey) !== 32) {
    fwrite(STDERR, "mediaKey must be 32 bytes (got " . strlen($mediaKey) . ")\n");
    exit(1);
}

// --- encrypt (+ optional sidecar in one pass) ---
$collector = new SidecarCollector(); // собираем sidecar без доп. чтений
$encStream = new EncryptingStream($plain, $mediaKey, $type, $collector);
$encryptedBytes = $encStream->getContents();
$sidecar = $encStream->getSidecarBytes(); // null для non-streamable — у нас не null, но писать его для IMAGE не обязательно

file_put_contents("{$outDir}/{$base}.encrypted", $encryptedBytes);

// sidecar имеет смысл для AUDIO/VIDEO. На IMAGE писать можно, но не требуется.
if (in_array($base, ['AUDIO', 'VIDEO'], true) && $sidecar !== null) {
    file_put_contents("{$outDir}/{$base}.sidecar", $sidecar);
}

// --- decrypt (MAC is verified first) ---
$enc = Utils::streamFor($encryptedBytes);
$decStream = new DecryptingStream($enc, $mediaKey, $type);
$decrypted = $decStream->getContents();
file_put_contents("{$outDir}/{$base}.decrypted", $decrypted);

// --- sanity check ---
$origBytes = file_get_contents($origPath);
if (hash('sha256', $origBytes) === hash('sha256', $decrypted)) {
    echo "[OK] {$base}: decrypt matches original\n";
} else {
    echo "[FAIL] {$base}: decrypted != original\n";
    exit(2);
}

echo "Written:\n";
echo "  {$outDir}/{$base}.encrypted\n";
if (in_array($base, ['AUDIO','VIDEO'], true)) {
    echo "  {$outDir}/{$base}.sidecar\n";
}
echo "  {$outDir}/{$base}.decrypted\n";