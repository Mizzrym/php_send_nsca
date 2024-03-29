<?php

namespace PhpSendNsca;

use PhpSendNsca\encryptors\NullEncryptor;
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
     * Creates SendNsca class
     * 
     * @param string $connectionString
     * @param int $encryptionCipher see EncryptorInterface constants
     * @param string $encryptionPassword leave empty if no encryption has been chosen
	 * @return SendNsca
     * @throws \Exception
     */
    public function getSendNsca(string $connectionString, int $encryptionCipher = Ciphers::ENCRYPT_NONE, string $encryptionPassword = ''): SendNsca {
        $key = md5($connectionString . ':' . $encryptionCipher . ':' . $encryptionPassword);
        if (false === isset(static::$instances[$key])) {
            static::$instances[$key] = new SendNsca($connectionString, $this->getEncryptor($encryptionCipher, $encryptionPassword));
        }
        return static::$instances[$key];
    }
    
	/**
	 * Tries to figure out correct encryptor for a given cipher
	 *
	 * @param int $cipher
	 * @param string $password
	 * @return EncryptorInterface
	 * @throws \Exception
	 */
    protected function getEncryptor(int $cipher, string $password): EncryptorInterface {
		try {
			if ($cipher === Ciphers::ENCRYPT_NONE) {
				return new NullEncryptor(Ciphers::ENCRYPT_NONE, '');
			}
			if ($cipher === Ciphers::ENCRYPT_XOR) {
				return $this->getXorEncryptor($cipher, $password);
			}
            $encryptor = $this->getOpenSslEncryptor($cipher, $password);
        } catch (\Exception $exc) {
            trigger_error('Falling back to legacy encryption, openssl failed: ' . $exc->getMessage(), E_USER_DEPRECATED);
            $encryptor = $this->getLegacyEncryptor($cipher, $password);
        }
        return $encryptor;
    }
	
	/**
	 * Factorymethod for XorEncryptor
	 *
	 * @param int $cipher
	 * @param string $password
	 * @return XorEncryptor
	 * @throws exceptions\EncryptionException
	 */
    public function getXorEncryptor(int $cipher, string $password) : XorEncryptor {
        return new XorEncryptor($cipher, $password);
    }

    /**
     * Factorymethod for OpenSSL Encryptor
	 *
     * @param int $cipher
     * @param string $password
     * @return OpenSslEncryptor
	 * @throws \Exception
     */
    public function getOpenSslEncryptor(int $cipher, string $password): OpenSslEncryptor {
        if (false === extension_loaded('openssl')) {
            throw new \Exception('OpenSSL Extension not available');
        }
        $encryptor = new OpenSslEncryptor($cipher, $password);
        if (false === $encryptor->isEncryptionCipherSupported($cipher)) {
            throw new \Exception('Trying to use unsupported encryption cipher');
        }
        return $encryptor;
    }

    /**
     * Factory Method for LegacyEncryptor
     * @param int $cipher
     * @param string $password
     * @return LegacyEncryptor
	 * @throws \Exception
     */
    public function getLegacyEncryptor(int $cipher, string $password): LegacyEncryptor {
        if (PHP_VERSION_ID >= 702000) {
            throw new \Exception('Mcrypt extension not available');
        }
        if (false === extension_loaded('mcrypt')) {
            throw new \Exception('Mcrypt extension not loaded');
        }
        return new LegacyEncryptor($cipher, $password);
    }

}
