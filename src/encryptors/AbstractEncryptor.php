<?php

namespace PhpSendNsca\encryptors;

use PhpSendNsca\interfaces\EncryptorInterface;
use PhpSendNsca\exceptions\EncryptionException;

/**
 * Basic Encryptor implementation
 * @author Mizzrym
 */
abstract class AbstractEncryptor implements EncryptorInterface {

    /**
     * The cipher to be used for encryption, see the 
     * EncryptorInterfaces class constants for a list of ciphers
     * @var int
     */
    protected $encryptionCipher;
    
    /**
     * The password to be used for encryption
     * @var string
     */
    protected $encryptionPassword;

    /**
     * Default constructor 
     * 
     * @param int $encryptionCipher
     * @param string $password
     * @throws EncryptionException
     */
    public function __construct(int $encryptionCipher, string $password) {
        if(false === $this->isEncryptionCipherSupported($encryptionCipher)) {
            throw new EncryptionException('Trying to use unsupported encryption cipher');
        }
        $this->encryptionCipher = $encryptionCipher;
        $this->encryptionPassword = $password;
    }

    /**
     * Determines if a specific cipher is available for this encryptor
     * @param int $encryptionCipher
     * @return bool
     */
    public function isEncryptionCipherSupported(int $encryptionCipher): bool {
        return in_array($encryptionCipher, $this->getSupportedEncryptionCiphers());
    }

}
