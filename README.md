# WhatsApp-style Stream Crypto (PSR-7)

Пакет с PSR-7 декораторами для шифрования/дешифрования медиа по схеме WhatsApp:
AES-256-CBC + PKCS#7 + HMAC-SHA256 (усечение до 10 байт). Есть генерация *sidecar* для потокового воспроизведения (видео/аудио).

---

## Требования

- PHP **8.2+**
- Расширение **ext-openssl**
- Composer 2
- [`guzzlehttp/psr7`](https://github.com/guzzle/psr7) (ставится через composer)

---

## Установка

```bash
composer install
```

# IMAGE | AUDIO | VIDEO | DOCUMENT
php examples/demo.php IMAGE
php examples/demo.php AUDIO
php examples/demo.php VIDEO
