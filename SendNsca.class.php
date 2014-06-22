<?php

namespace  php_send_nsca;

/**
 * Abstract class to send nsca notifications. Should be extended once for every monitoring server in your
 * network. The extended class needs to overwrite at least $hostname, otherwise function send won't
 * execute and fail with a NscaException.
 * Needs at least PHP 5.3 to work with late static binding. If your PHP version is too old and you cant
 * upgrade, replace all static calls to variables with a get-function (like self::getHostname()) and
 * overwrite them in the extending class.
 *
 * @abstract
 * @author      Mizzrym <og.hartmann@gmail.com>
 * @link        https://github.com/Mizzrym/php_sned_nsca
 */
abstract class SendNsca
{
    /**
     * The hostname, fqdn or ip address to connect to.
     *
     * @var string
     */
    protected static $hostname = null;

    /**
     * Port on which nsca daemon is listening
     *
     * @var int
     */
    protected static $port = 5667;

    /**
     * The encryption method (cipher) used by nsca daemon to encrypt the packages. Use null to disable
     * encryption (not recommended, always encrypt your stuff). Use PHPs MCRYPT constants.
     *
     * @var string
     * @link http://www.php.net//manual/en/mcrypt.ciphers.php
     */
    protected static $encryption = null;

    /**
     * The password used for encryption (if encryption is enabled). You can find this password in
     * your nsca daemons configuration file (usually /etc/nsca.conf)
     *
     * @var string
     */
    protected static $password = null;

    /**
     * The timeout used by stream_socket_client to initiate connection with nsca. 
     * Note that php will call some getaddress whatever function in case you're using a DNS name 
     * instead of an ip address which ignores this timeout. 
     * Of course it does, because obviously DNS doesn't suck enough as it is. 
     * (default 15 seconds)
     *
     * @var int
     */
    protected static $timeout_connect = 15;

    /**
     * The maximum runtime in seconds after the connection with nsca is initiated
     * (default 10 seconds)
     *
     * @var int
     */
    protected static $timeout_stream = 10;

    /**
     * The encryption mode used by mcrypt
     */
    const ENCRYPTION_MODE = 'cfb';

    /*
     * Nagios status codes
     */
    const STATE_OK = 0;
    const STATE_WARNING = 1;
    const STATE_CRITICAL = 2;
    const STATE_UNKNOWN = 3;

    private function __construct() {}

    /**
     * Sends check result to nagios host. nagios/nsca will determine where to use the result using
     * $host (the hostname configured in your nagios configuration) and service (the configured name of
     * the service).
     * Use the SendNsca class constants to set the appropriate returncode.
     * Sending a message is optional.
     * Both hostname and service are case sensitive.
     *
     * @static
     * @param string $host
     * @param string $service
     * @param int $returncode
     * @param string $message
     * @throws NscaException
     */
    public static function send($host, $service, $returncode, $message = '')
    {
        // sanity checks
        if (static::$hostname === null) {
            throw new NscaException('No hostname set');
        }
        if (strlen($host) >= 64) {
            throw new NscaException('Hostname too long');
        }
        if (strlen($service) >= 128) {
            throw new NscaException('Service description too long');
        }
        if (strlen($message) >= 512) {
            throw new NscaException('Message too long');
        }
        switch($returncode) {
            case self::STATE_OK:
            case self::STATE_WARNING:
            case self::STATE_CRITICAL:
            case self::STATE_UNKNOWN:
                break;
            default:
                throw new Exception('Invalid returncode');
        }

        // try to connect to host
        $errno = $errstr = null;
        // i hate myself for using '@' to suppress the warning, but spam in logfiles had to be prevented somehow
        $connection = @stream_socket_client(static::$hostname . ':' . static::$port, $errno, $errstr, static::$timeout_connect);
        if (!$connection) {
            throw new NscaException(
                'Could not connect to NSCA Server on ' . static::$hostname . 
                ' error: ' . $errno . ' - ' . $errstr
            );
        }
        stream_set_timeout($connection, static::$timeout_stream);

        // read initial package
        $iv = stream_get_contents($connection, 128); //initialisation vector for encryption
        $timestamp = reset(unpack('N', stream_get_contents($connection, 4)));

        // fill buffer
        self::fillBufferWithRandomData($host, 64);
        self::fillBufferWithRandomData($service, 128);
        self::fillBufferWithRandomData($message, 512);

        // build package
        $packet = pack('nxxxxxxNna64a128a512xx', 3, $timestamp, $returncode, $host, $service, $message);
        $crc = crc32($packet);
        $packet = pack('nxxNNna64a128a512xx', 3, $crc, $timestamp, $returncode, $host, $service, $message);

        // encrypt
        if (static::$encryption !== null) {
            $packet = self::encrypt($packet, $iv);
        }

        // send it
        fflush($connection);
        fwrite($connection, $packet);
        fclose($connection);
    }

    /**
     * Encrypts a package using mcrypt
     *
     * @param string $packet
     * @param string $iv
     * @return string
     * @throws NscaException
     */
    final private static function encrypt($packet, $iv)
    {
        // sanity check
        if (static::$password === null) {
            throw new NscaException('Can\'t encrypt package without password!');
        }

        // assemble initialisation vector
        $ivlen = mcrypt_get_iv_size(static::$encryption, self::ENCRYPTION_MODE);
        if ($ivlen === false) {
            throw new NscaException('Can\'t determine initialisation vector length');
        }
        $iv = substr($iv, 0, $ivlen);

        // encrypt
        $crypt = mcrypt_encrypt(static::$encryption, static::$password, $packet, self::ENCRYPTION_MODE, $iv);
        if ($crypt === false) {
            throw new NscaException('Encryption failed');
        }

        return $crypt;
    }

    /**
     * Fills buffer with random data (O RLY) for better encryption results.
     *
     * @param string $buffer
     * @param int $maxBufferSize
     */
    final private static function fillBufferWithRandomData(&$buffer, $maxBufferSize)
    {
        $buffer .= "\0";
        while (strlen($buffer) < $maxBufferSize) {
            $buffer .= chr(mt_rand(0, 255));
        }
    }

}
