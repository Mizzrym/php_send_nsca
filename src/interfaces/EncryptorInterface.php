<?php

namespace PhpSendNsca\interfaces;

/**
 * Interface for Encryptors
 * 
 * @author Mizzrym
 */
interface EncryptorInterface extends Ciphers {

    /**
     * Construct the Encryptor with Cipher and Password
     * 
     * @param int $encryptionCipher see ENCRYPT_* constants
     * @param string $password
     */
    public function __construct($encryptionCipher, $password);

    /**
     * Encrypt the package using the full initialisation vector
     * 
     * @param string $packet
     * @param string $initialisationVector the raw iv from the nsca daemon
     * @return string the encrypted package
     */
    public function encryptPacket($packet, $initialisationVector);

    /**
     * Return an array containing all supported ciphers
     * @return int[]
     */
    public function getSupportedEncryptionCiphers();

    /**
     * Determine if a cipher is supported by this encryptor
     * @param int $encryptionCipher
     * @return bool
     */
    public function isEncryptionCipherSupported($encryptionCipher);
}
