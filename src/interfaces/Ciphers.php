<?php

namespace PhpSendNsca\interfaces;

/**
 * Constants for Ciphers
 * 
 * @author Mizzrym
 */
interface Ciphers {

    const ENCRYPT_NONE = 0;
    const ENCRYPT_XOR = 1;
    const ENCRYPT_DES = 2;
    const ENCRYPT_3DES = 3;
    const ENCRYPT_CAST128 = 4;
    const ENCRYPT_CAST256 = 5;
    const ENCRYPT_XTEA = 6;
    const ENCRYPT_3WAY = 7;
    const ENCRYPT_BLOWFISH = 8;
    const ENCRYPT_TWOFISH = 9;
    const ENCRYPT_LOKI97 = 10;
    const ENCRYPT_RC2 = 11;
    const ENCRYPT_ARCFOUR = 12;
    const ENCRYPT_RIJNDAEL128 = 14;
    const ENCRYPT_RIJNDAEL192 = 15;
    const ENCRYPT_RIJNDAEL256 = 16;
    const ENCRYPT_WAKE = 19;
    const ENCRYPT_SERPENT = 20;
    const ENCRYPT_ENIGMA = 22;
    const ENCRYPT_GOST = 23;
    const ENCRYPT_SAFER64 = 24;
    const ENCRYPT_SAFER128 = 25;
    const ENCRYPT_SAFERPLUS = 26;

}
