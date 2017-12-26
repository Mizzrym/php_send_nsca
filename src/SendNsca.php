<?php

namespace PhpSendNsca;

use PhpSendNsca\interfaces\EncryptorInterface;
use PhpSendNsca\interfaces\NagiosCodes;

/**
 * Class to send Nagios passive checks to nsca daemon
 *
 * @author Mizzrym
 */
class SendNsca extends NagiosCodes {
    
    /**
     * Default NSCA port
     */
    const DEFAULT_PORT = 5667;

    /**
     * The hostname, fqdn or ip address your nsca daemon runs on.
     *
     * @var string
     */
    protected $hostname;

    /**
     * Port on which nsca daemon is listening
     *
     * @var int
     */
    protected $port = self::DEFAULT_PORT;

    /**
     *
     * @var encryptors\EncryptorInterface
     */
    protected $encryptor;

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
     * SendNsca constructor.
     *
     * @param string $connectionString Examples: 127.0.0.1, localhost:5667, some.server.local:5555, nagios.local
     * @param null|string $encryptor (optional) Class to encrypt the package with
     */
    public function __construct(string $connectionString, EncryptorInterface $encryptor = null) {
        if (strpos($connectionString, ':')) {
            $connect = explode(':', $connectionString);
            $this->hostname = $connect[0];
            $this->port = intval($connect[1]);
        } else {
            $this->hostname = $connectionString;
        }
        $this->encryptor = $encryptor;
    }

    /**
     * Sends check result to nagios host. nagios/nsca will determine where to use the result using
     * $host (the hostname configured in your nagios configuration) and service (the configured name of
     * the service).
     * Use the NagiosCodes class constants to set the appropriate returncode.
     * Sending a message is optional.
     * Both hostname and service are case sensitive.
     *
     * @param string $host Hostname.
     * @param string $service Name of the service.
     * @param integer $returncode Nagios State-code.
     * @param string $message Message (optional).
     * @throws \Exception only if mode is development mode with exceptions enabled
     * @return true|false true on success.
     */
    public function send(string $host, string $service, int $returncode, string $message = '') {
        if ($this->hostname === null) {
            throw new Exception('No hostname for NSCA daemon given, don\'t know where to connect to - class not properly initialized');
        }
        if (strlen($host) >= 64) {
            trigger_error('Host name too long (max 64 characters) - truncated', \E_USER_WARNING);
            $host = substr($host, 0, 63);
        }
        if (strlen($service) >= 128) {
            trigger_error('Service name too long (max 128 characters) - truncated', \E_USER_WARNING);
            $service = substr($service, 0, 127);
        }
        if (strlen($message) >= 512) {
            trigger_error('Message too long (max 512 characters) - truncated', \E_USER_WARNING);
            $message = substr($message, 0, 511);
        }
        $reflection = new \ReflectionClass('\\' . __NAMESPACE__ . '\\interfaces\\NagiosCodes');
        if (!in_array($returncode, $reflection->getConstants())) {
            throw new \Exception('unknown return code: ' . $returncode);
        }

        // try to connect to host
        $errno = $errstr = null;
        // i hate myself for using '@' to suppress the warning, but spam in logfiles had to be prevented
        $connection = @stream_socket_client(
                        $this->hostname . ':' . $this->port, $errno, $errstr, $this->connectTimeout
        );
        if (!$connection) {
            throw new \Exception('Cannot connect to nsca daemon ' . $this->hostname . ':' . $this->port);
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
        if ($this->encryptor) {
            $packet = $this->encryptor->encryptPacket($packet, $iv);
        }

        // send it
        fflush($connection);
        fwrite($connection, $packet);
        fclose($connection);
        return true;
    }

    /**
     * Fills buffer with random data (O RLY) for better encryption results.
     *
     * @param string $buffer
     * @param integer $maxBufferSize
     */
    protected function fillBufferWithRandomData(&$buffer, $maxBufferSize) {
        $buffer .= "\0";
        while (strlen($buffer) < $maxBufferSize) {
            $buffer .= chr(mt_rand(0, 255));
        }
    }
}
