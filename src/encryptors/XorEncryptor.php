<?php

namespace PhpSendNsca\encryptors;

use PhpSendNsca\interfaces\EncryptorInterface;
use PhpSendNsca\encryptors\AbstractEncryptor;

/**
 * Class that implements simpleXOR encryption
 * 
 * @author Mizzrym
 * @author nueaf
 */
class XorEncryptor extends AbstractEncryptor implements EncryptorInterface {
    
    /**
     * Implements EncryptorInterface Method
     * 
     * @return int[]
     */
    public function getSupportedEncryptionCiphers() : array {
        return [
            self::ENCRYPT_XOR
        ];
    }

    /**
     * Encrypts package
     * 
     * @author nueaf
     * @param string $packet
     * @param string $initialisationVector
     * @return string
     */
    public function encryptPacket(string $packet, string $initialisationVector) : string {
        $packetSize = strlen($packet);
        $ivSize = strlen($initialisationVector);
        /* rotate over IV we received from the server... */
        for ($y = 0, $x = 0; $y < $packetSize; $y++, $x++) {
            /* keep rotating over IV */
            if ($x >= $ivSize) {
                $x = 0;
            }
            $packet[$y] = $packet[$y] ^ $initialisationVector[$x];
        }

        /* rotate over password... */
        $passwordLength = strlen($this->encryptionPassword);
        for ($y = 0, $x = 0; $y < $packetSize; $y++, $x++) {
            /* keep rotating over password */
            if ($x >= $passwordLength) {
                $x = 0;
            }
            $packet[$y] = $packet[$y] ^ $this->encryptionPassword[$x];
        }
        return $packet;
        ;
    }

}