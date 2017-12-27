<?php

namespace PhpSendNsca;

use PhpSendNsca\SendNsca;
use PhpSendNsca\interfaces\Ciphers;
use PhpSendNsca\encryptors\XorEncryptor;
use PhpSendNsca\encryptors\LegacyEncryptor;
use PhpSendNsca\encryptors\OpenSslEncryptor;
use PhpSendNsca\interfaces\EncryptorInterface;

/**
 * Factory to build a functioning instance of SendNsca
 *
 * @author Mizzrym
 */
class SendNscaFactory implements Ciphers {

    /**
     * Instances shouldn't be built twice
     * @var SendNsca[]
     * @static
     */
    static $instances = [];

    /**
     * Provides an alternate way to build SendNsca, by parsing the 
     * send_nsca.cfg config file, which should provide all information for 
     * encryption as well. 
     * This isn't very sane however, because if you have the send_nsca c client 
     * installed anyway you don't really need this php implementation. But who 
     * am i to judge. 
     * NOTE: If this factory is called in a webcontext it is possible that 
     *       the webserver will restrict phps readaccess or even run the 
     *       process in a chroot, so this will most likely fail. Don't 
     *       disable the restrictions, they're there for a reason. Use 
     *       the other factory method "getSendNsca" instead. 
     * 
     * @param string $connectionString
     * @param string $path if omitted will use '/etc/send_nsca.cfg'
     * @return SendNsca
     * @throws Exception
     */
    public function getSendNscaFromConfig(string $connectionString, string $path = null): SendNsca {
        $path = $path ?? '/etc/send_nsca.cfg';
        // sanity/permission check
        if (false === is_readable($path)) {
            throw new Exception('Cannot read file at ' . $path);
        }
        if (false === $file = fopen($path, 'r')) {
            throw new Exception('Cannot open file at ' . $path);
        }

        // parse config
        $cipher = 0;
        $password = '';
        while (false !== $line = fgets($file)) {
            if (false === strpos($line, '=')) {
                // not the droids we are looking for
                continue;
            }
            // strip line of whitespaces
            $clean = preg_replace('/\s+/', '', $line);
            // look for the two lines we're interested in
            if (substr($clean, 0, 9) === 'password=') {
                $password = substr($clean, 9);
            } elseif (substr($clean, 0, 18) === 'encryption_method=') {
                $cipher = intval(substr($clean, 18));
            }
        }
        return $this->getSendNsca($connectionString, $cipher, $password);
    }

    /**
     * Creates SendNsca class
     * 
     * @param string $connectionString
     * @param int $encryptionCipher see EncryptorInterface constants
     * @param string $encryptionPassword leave empty if no encryption has been chosen
     * @throws \Exception
     * @return SendNsca
     */
    public function getSendNsca(string $connectionString, int $encryptionCipher = null, string $encryptionPassword = null): SendNsca {
        $password = $encryptionPassword ?? '';
        $cipher = $encryptionCipher ?? Ciphers::ENCRYPT_NONE;
        $key = md5($connectionString . ':' . $cipher . ':' . $password);
        if (false === isset(static::$instances[$key])) {
            static::$instances[$key] = new SendNsca($connectionString, $this->getEncryptor($cipher, $password));
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
        if ($cipher === Ciphers::ENCRYPT_NONE) {
            return null;
        }
        if ($cipher === Ciphers::ENCRYPT_XOR) {
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
