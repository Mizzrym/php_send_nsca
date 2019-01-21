<?php

namespace PhpSendNsca\encryptors;

use PhpSendNsca\interfaces\EncryptorInterface;
use PhpSendNsca\exceptions\EncryptionException;

/**
 * Encryptor using OpenSSL
 * 
 * @author Mizzrym
 */
class OpenSslEncryptor extends AbstractEncryptor implements EncryptorInterface {

    /**
     * Optional parameters passed to openssl_encrypt
     */
    const ENCRYPTION_OPTION = true;
    
    /**
     * A map that determines which cipher from the EncryptorInterfaces matches
     * openSSL ciphers and how they're called
     * 
     * @var string[] 
     */
    protected $cipherMap = [
        self::ENCRYPT_DES => 'DES-CFB8',
        self::ENCRYPT_3DES => 'DES-EDE3-CFB8'
    ];
    
    /**
     * Determines which encryption ciphers are supported
     * @return int[]
     */
    public function getSupportedEncryptionCiphers() : array {
      return array_keys($this->cipherMap);
    }
    
    /**
     * Method to translate ciphers from EncryptorInterface to openSSL
     * 
     * @param int $nscaName
     * @return string
     * @throws EncryptionException
     */
    private function translateCipher($nscaName) {
        if (isset($this->cipherMap[$nscaName])) {
            return $this->cipherMap[$nscaName];
        }
        throw new EncryptionException('Unsupported Cipher');
    }

    /**
     * Encrypts the package
     * 
     * @param string $packet
     * @param string $initialisationVector
     * @return string
     * @throws EncryptionException
     */
    public function encryptPacket($packet, $initialisationVector) {
        $sslCipher = $this->translateCipher($this->encryptionCipher);
        $len = openssl_cipher_iv_length($sslCipher);
        if (false === is_int($len)) {
            throw new EncryptionException('Cannot figure out length of ' .
            'initialisation vector for encryption cipher ' .
            $this->encryptionCipher
            );
        }
        $civ = substr($initialisationVector, 0, $len);
        $pass = $this->encryptionPassword;
        $encryptedPackage = openssl_encrypt($packet, $sslCipher, $pass, self::ENCRYPTION_OPTION, $civ);
        if (false === $encryptedPackage) {
            throw new EncryptionException('Failed to encrypt package. ' .
                    'Check if your password is long enough for the cipher ' . 
                    'you chose'
            );
        }
        return $encryptedPackage;
    }

}
