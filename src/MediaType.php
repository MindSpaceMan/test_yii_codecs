<?php
// src/MediaType.php
declare(strict_types=1);

namespace WApp\StreamCrypto;

enum MediaType: string
{
    case IMAGE = 'WhatsApp Image Keys';
    case VIDEO = 'WhatsApp Video Keys';
    case AUDIO = 'WhatsApp Audio Keys';
    case DOCUMENT = 'WhatsApp Document Keys';

    public function hkdfInfo(): string
    {
        return $this->value;
    }
}