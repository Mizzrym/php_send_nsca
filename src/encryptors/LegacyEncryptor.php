<?php

namespace PhpSendNsca\encryptors;

use PhpSendNsca\encryptors\AbstractEncryptor;
use PhpSendNsca\interfaces\EncryptorInterface;
use PhpSendNsca\exceptions\EncryptionException;

/**
 * Legacy Encryptor using the mcrypt extension which will be removed from 
 * PHP in version 7.2
 * @author Mizzrym
 */
class LegacyEncryptor extends AbstractEncryptor implements EncryptorInterface {

    /**
     * To be honest i stil don't know what this one changes, but mcrypt 
     * needs it for encryption and that mode has worked so far in all tests. 
     * 
     * @var string 
     */
    private $encryptionMode = MCRYPT_MODE_CFB;

    /**
     * LegacyEncryptor supports EVERYTHING (except XOR) out of the box, 
     * since it used the same library as nsca does. 
     * @return int[]
     */
    public function getSupportedEncryptionCiphers(): array {
        return [
            self::ENCRYPT_NONE,
            self::ENCRYPT_DES,
            self::ENCRYPT_3DES,
            self::ENCRYPT_CAST128,
            self::ENCRYPT_CAST256,
            self::ENCRYPT_XTEA,
            self::ENCRYPT_3WAY,
            self::ENCRYPT_BLOWFISH,
            self::ENCRYPT_TWOFISH,
            self::ENCRYPT_LOKI97,
            self::ENCRYPT_RC2,
            self::ENCRYPT_ARCFOUR,
            self::ENCRYPT_RIJNDAEL128,
            self::ENCRYPT_RIJNDAEL192,
            self::ENCRYPT_RIJNDAEL256,
            self::ENCRYPT_WAKE,
            self::ENCRYPT_SERPENT,
            self::ENCRYPT_ENIGMA,
            self::ENCRYPT_GOST,
            self::ENCRYPT_SAFER64,
            self::ENCRYPT_SAFER128,
            self::ENCRYPT_SAFERPLUS
        ];
    }

    /**
     * Translates the EncryptorInterfaces class constants to the legacy 
     * mcrypt constants 
     * 
     * @param int $nscaName
     * @return string
     * @throws EncryptionException
     */
    protected function translateCipher(int $nscaName): string {
        switch ($nscaName) {
            case self::ENCRYPT_DES:
                return MCRYPT_DES;
            case self::ENCRYPT_3DES:
                return MCRYPT_3DES;
            case self::ENCRYPT_CAST128:
                return MCRYPT_CAST_128;
            case self::ENCRYPT_CAST256:
                return MCRYPT_CAST_256;
            case self::ENCRYPT_XTEA:
                return MCRYPT_XTEA;
            case self::ENCRYPT_3WAY:
                return MCRYPT_THREEWAY;
            case self::ENCRYPT_BLOWFISH:
                return MCRYPT_BLOWFISH;
            case self::ENCRYPT_TWOFISH:
                return MCRYPT_TWOFISH;
            case self::ENCRYPT_LOKI97:
                return MCRYPT_LOKI97;
            case self::ENCRYPT_RC2:
                return MCRYPT_RC2;
            case self::ENCRYPT_ARCFOUR:
                return MCRYPT_ARCFOUR;
            case self::ENCRYPT_RIJNDAEL128:
                return MCRYPT_RIJNDAEL_128;
            case self::ENCRYPT_RIJNDAEL192:
                return MCRYPT_RIJNDAEL_192;
            case self::ENCRYPT_RIJNDAEL256:
                return MCRYPT_RIJNDAEL_256;
            case self::ENCRYPT_WAKE:
                return MCRYPT_WAKE;
            case self::ENCRYPT_SERPENT:
                return MCRYPT_SERPENT;
            case self::ENCRYPT_ENIGMA:
                return MCRYPT_ENIGNA;
            case self::ENCRYPT_GOST:
                return MCRYPT_GOST;
            case self::ENCRYPT_SAFER64:
                return MCRYPT_SAFER64;
            case self::ENCRYPT_SAFER128:
                return MCRYPT_SAFER128;
            case self::ENCRYPT_SAFERPLUS:
                return MCRYPT_SAFERPLUS;
        }
        throw new EncryptionException('Unknown Cipher: ' . $nscaName);
    }

    /**
     * Encrypts the package
     * 
     * @param string $packet
     * @param string $initialisationVector
     * @return string
     * @throws EncryptionException
     */
    public function encryptPacket(string $packet, string $initialisationVector): string {
        $mcryptCipher = $this->translateCipher($this->encryptionCipher);
        $len = mcrypt_get_iv_size($mcryptCipher, $this->encryptionMode);
        if (false === is_int($len)) {
            throw new EncryptionException('Cannot figure out length of ' .
            'initialisation vector for encryption cipher ' .
            $this->encryptionCipher
            );
        }
        $civ = substr($initialisationVector, 0, $len);
        /*
         * I encountered a problem with DES that the package won't encrypt 
         * properly if the password is longer than the iv length, for whatever
         * reason. 
         */
        $pass = $this->encryptionMode === self::ENCRYPT_DES 
                ? substr($this->encryptionPassword, 0, $len)
                : $this->encryptionPassword
        ;
        $encryptedPackage = mcrypt_encrypt($mcryptCipher, $pass, $packet, $this->encryptionMode, $civ);
        if (false === $encryptedPackage) {
            throw new EncryptionException('Failed to encrypt package. ' .
                    'Check if your password is long enough for the cipher you chose'
            );
        }
        return $encryptedPackage;
    }

}
