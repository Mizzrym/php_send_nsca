<?php

namespace PhpSendNsca;

use PhpSendNsca\SendNsca;
use PhpSendNsca\encryptors\XorEncryptor;
use PhpSendNsca\encryptors\LegacyEncryptor;
use PhpSendNsca\encryptors\OpenSslEncryptor;
use PhpSendNsca\interfaces\EncryptorInterface;

/**
 * Factory to build a functioning instance of SendNsca
 *
 * @author Mizzrym
 */
class SendNscaFactory {

    /**
     * Instances shouldn't be built twice
     * @var SendNsca[]
     * @static
     */
    static $instances = [];

    /**
     * Creates SendNsca class
     * 
     * @param string $connectionString
     * @param int $encryptionMethod see EncryptorInterface constants
     * @param string $encryptionPassword leave empty if no encryption has been chosen
     * @throws \Exception
     * @return SendNsca
     */
    public function getSendNsca(string $connectionString, int $encryptionMethod = EncryptorInterface::ENCRYPT_NONE, string $encryptionPassword = ''): SendNsca {
        $key = md5($connectionString . ':' . $encryptionMethod . ':' . $encryptionPassword);
        if (isset(static::$instances[$key])) {
            static::$instances[$key] = new SendNsca($connectionString, $this->getEncryptor($encryptionMethod, $encryptionPassword));
        }
        return static::$instances[$key];
    }

    /**
     * Tries to figure out correct encryptor for a given cipher
     * @param int $cipher
     * @param string $password
     * @return EncryptorInterface
     */
    protected function getEncryptor(int $cipher, string $password): EncryptorInterface {
        if ($cipher === EncryptorInterface::ENCRYPT_NONE) {
            return null;
        }
        if ($cipher === EncryptorInterface::ENCRYPT_XOR) {
            return $this->getXorEncryptor($cipher, $password);
        }
        try {
            $encryptor = $this->getOpenSslEncryptor($cipher, $password);
        } catch (\Exception $exc) {
            $encryptor = $this->getLegacyEncryptor($cipher, $password);
        }
        return $encryptor;
    }

    /**
     * Factorymethod for XorEncryptor
     * 
     * @param int $cipher
     * @param string $password
     * @throws Exception
     * @return XorEncryptor
     */
    private function getXorEncryptor(int $cipher, string $password): XorEncryptor {
        return new XorEncryptor($cipher, $password);
    }

    /**
     * Factorymethod for OpenSSL Encryptor
     * @param int $cipher
     * @param string $password
     * @return OpenSslEncryptor
     * @throws Exception
     */
    private function getOpenSslEncryptor(int $cipher, string $password): OpenSslEncryptor {
        if (false === extension_loaded('openssl')) {
            throw new Exception('OpenSSL Extension not available');
        }
        return new OpenSslEncryptor($cipher, $password);
    }

    /**
     * Factory Method for LegacyEncryptor
     * @param int $cipher
     * @param string $password
     * @return LegacyEncryptor
     * @throws Exception
     */
    private function getLegacyEncryptor(int $cipher, string $password): LegacyEncryptor {
        if (PHP_VERSION_ID >= 702000) {
            throw new Exception('Mcrypt extension not available');
        }
        if (false === extension_loaded('mcrypt')) {
            throw new Exception('Mcrypt extension not loaded');
        }
        return new LegacyEncryptor($cipher, $password);
    }

}
