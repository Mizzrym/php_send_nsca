<?php

namespace PhpSendNsca\encryptors;

use PhpSendNsca\interfaces\EncryptorInterface;

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
     */
    public function __construct($encryptionCipher, $password) {
        $this->encryptionCipher = $encryptionCipher;
        $this->encryptionPassword = $password;
    }

    /**
     * Determines if a specific cipher is available for this encryptor
     * @param int $encryptionCipher
     * @return bool
     */
    public function isEncryptionCipherSupported($encryptionCipher) {
        return in_array($encryptionCipher, $this->getSupportedEncryptionCiphers());
    }

}
