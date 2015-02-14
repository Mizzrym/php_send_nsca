<?php

namespace phpSendNsca;

abstract class SendNsca
{
    /**
     * The hostname, fqdn or ip address your nsca daemon runs on.
     *
     * @var string
     */
    protected $hostname = null;

    /**
     * Port on which nsca daemon is listening
     *
     * @var int
     */
    protected $port = 5667;

    /**
     * The encryption method (cipher) used by nsca daemon to encrypt the packages. Use null to disable
     * encryption (not recommended, always encrypt your stuff). Use PHPs MCRYPT constants.
     *
     * @var string
     * @link http://www.php.net//manual/en/mcrypt.ciphers.php
     */
    protected $encryption = null;

    /**
     * The password used for encryption (if encryption is enabled). You can find this password in
     * your nsca daemons configuration file (usually /etc/nsca.conf)
     *
     * @var string
     */
    protected $password = null;

    /**
     * The timeout used by stream_socket_client to initiate connection with nsca.
     * Note that php will call some getaddress whatever function in case you're using a DNS name
     * instead of an ip address which ignores this timeout.
     * Of course it does, because obviously DNS doesn't suck enough as it is.
     * (default 15 seconds)
     *
     * @var int
     */
    protected $connectTimeout = 15;

    /**
     * The maximum runtime in seconds after the connection with nsca is initiated
     * (default 10 seconds)
     *
     * @var int
     */
    protected $streamTimeout = 10;

    /**
     * The encryption mode used by mcrypt
     *
     * @var string
     */
    protected $encryptionMode = 'cfb';

    /**
     * Sends check result to nagios host. nagios/nsca will determine where to use the result using
     * $host (the hostname configured in your nagios configuration) and service (the configured name of
     * the service).
     * Use the NagiosCodes class constants to set the appropriate returncode.
     * Sending a message is optional.
     * Both hostname and service are case sensitive.
     *
     * @param string $host Hostname
     * @param string $service Name of the service
     * @param int $returncode Nagios State-code
     * @param string $message (optional) Message
     * @return true|false true on success
     */
    public function send($host, $service, $returncode, $message = '')
    {
        if ($this->hostname === null) {
            return false;
        }
        if (strlen($host) >= 64) {
            return false;
        }
        if (strlen($service) >= 128) {
            return false;
        }
        if (strlen($message) >= 512) {
            return false;
        }
        $Reflection = new \ReflectionClass('\\phpSendNsca\\NagiosCodes');
        if (!in_array($returncode, $Reflection->getConstants())) {
            return false;
        }
        // try to connect to host
        $errno = $errstr = null;
        // i hate myself for using '@' to suppress the warning, but spam in logfiles had to be prevented
        $connection = @stream_socket_client(
                $this->hostname . ':' . $this->port, $errno, $errstr, $this->connectTimeout
        );
        if (!$connection) {
            return false;
        }
        stream_set_timeout($connection, $this->streamTimeout);

        // read initial package
        $iv = stream_get_contents($connection, 128); //initialisation vector for encryption
        $timestampRaw = unpack('N', stream_get_contents($connection, 4));
        $timestamp = reset($timestampRaw);

        // fill buffer
        $this->fillBufferWithRandomData($host, 64);
        $this->fillBufferWithRandomData($service, 128);
        $this->fillBufferWithRandomData($message, 512);

        // build package
        $crcPacket = pack('nxxxxxxNna64a128a512xx', 3, $timestamp, $returncode, $host, $service, $message);
        $crc = crc32($crcPacket);
        $packet = pack('nxxNNna64a128a512xx', 3, $crc, $timestamp, $returncode, $host, $service, $message);

        // encrypt
        if ($this->encryption !== null) {
            if(false === $packet = $this->encrypt($packet, $iv)) {
                return false;
            }
        }

        // send it
        fflush($connection);
        fwrite($connection, $packet);
        fclose($connection);
        return true;
    }

    /**
     * Encrypts a package using mcrypt
     *
     * @param string $packet
     * @param string $iv
     * @return string|false
     */
    private function encrypt($packet, $iv)
    {
        // sanity check
        if ($this->password === null) {
            return false;
        }

        // assemble initialisation vector
        $ivlen = mcrypt_get_iv_size($this->encryption, $this->encryptionMode);
        if ($ivlen === false) {
            return false;
        }
        $cryptIv = substr($iv, 0, $ivlen);

        // encrypt
        $crypt = mcrypt_encrypt($this->encryption, $this->password, $packet, $this->encryptionMode, $cryptIv);
        if ($crypt === false) {
            return false;
        }

        return $crypt;
    }

    /**
     * Fills buffer with random data (O RLY) for better encryption results.
     *
     * @param string $buffer
     * @param int $maxBufferSize
     */
    private function fillBufferWithRandomData(&$buffer, $maxBufferSize)
    {
        $buffer .= "\0";
        while (strlen($buffer) < $maxBufferSize) {
            $buffer .= chr(mt_rand(0, 255));
        }
    }

}
