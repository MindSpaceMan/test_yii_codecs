<?php
// tests/EncryptDecryptTest.php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use GuzzleHttp\Psr7\Utils;
use WApp\StreamCrypto\MediaType;
use WApp\StreamCrypto\Stream\EncryptingStream;
use WApp\StreamCrypto\Stream\DecryptingStream;
use WApp\StreamCrypto\Sidecar\SidecarCollector;
use WApp\StreamCrypto\Sidecar\SidecarFromEncrypted;

final class EncryptDecryptTest extends TestCase
{
    /** @dataProvider vectors */
    public function testEncryptDecrypt(string $base, \WApp\StreamCrypto\MediaType $type): void
    {
        $plain = Utils::streamFor(file_get_contents("samples/{$base}.original"));
        $key   = file_get_contents("samples/{$base}.key");
        $encExpected = file_get_contents("samples/{$base}.encrypted");

        $collector = new SidecarCollector();
        $encStream = new EncryptingStream($plain, $key, $type, $collector);
        $enc = $encStream->getContents();

        self::assertSame(bin2hex($encExpected), bin2hex($enc), 'encryption must match vector');

        $decStream = new DecryptingStream(Utils::streamFor($enc), $key, $type);
        $dec = $decStream->getContents();

        $orig = file_get_contents("samples/{$base}.original");
        self::assertSame(bin2hex($orig), bin2hex($dec), 'decryption must restore original');

        if (in_array($type, [MediaType::AUDIO, MediaType::VIDEO], true)) {
            $sidecarExpected = file_get_contents("samples/{$base}.sidecar");
            self::assertSame(bin2hex($sidecarExpected), bin2hex($encStream->getSidecarBytes()), 'inline sidecar must match');

            // альтернативный способ — из готового enc
            $sidecar2 = SidecarFromEncrypted::generate(Utils::streamFor($encExpected), \WApp\StreamCrypto\KeySchedule::derive($key, $type)[2]);
            self::assertSame(bin2hex($sidecarExpected), bin2hex($sidecar2), '2-pass sidecar must match');
        }
    }

    public static function vectors(): array
    {
        return [
            ['IMAGE', MediaType::IMAGE],
            ['AUDIO', MediaType::AUDIO],
            ['VIDEO', MediaType::VIDEO],
            // ['DOCUMENT', MediaType::DOCUMENT], // когда положишь в samples
        ];
    }
}