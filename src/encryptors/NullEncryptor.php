<?php

namespace PhpSendNsca\encryptors;

use PhpSendNsca\interfaces\EncryptorInterface;

/**
 * Doesn't really encrypt.
 * Is needed so typehints work with PHP 7.0, where nullable typehints aren't available
 */
class NullEncryptor implements EncryptorInterface
{
    public function __construct(int $encryptionCipher, string $password)
    {
    }
    
    public function encryptPacket(string $packet, string $initialisationVector): string
    {
        return $packet;
    }
    
    public function getSupportedEncryptionCiphers(): array
    {
        return [ self::ENCRYPT_NONE ];
    }
    
    public function isEncryptionCipherSupported(int $encryptionCipher): bool
    {
        return $encryptionCipher === self::ENCRYPT_NONE;
    }
    
}
