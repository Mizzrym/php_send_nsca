<?php

namespace PhpSendNsca;

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
     * Constant to set silent mode (default)
     */
    const MODE_SILENT = 0;

    /**
     * Constant to set development mode, which is more verbose
     */
    const MODE_DEVELOPMENT = 1;

    /**
     * Constant to set development mode, but instead of trigger errors
     * class will throw Exceptions
     */
    const MODE_EXCEPTION = 2;

    /**
     * Constant for XOR encryption. For other encryption methods, use
     * the MCRYPT constants
     */
    const ENCRYPT_XOR = 'xor';

    /**
     * Variable to store mode
     *
     * @var int
     */
    protected $mode = self::MODE_SILENT;

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
     * SendNsca constructor.
     *
     * @param string $connectionString Examples: 127.0.0.1, localhost:5667, some.server.local:5555, nagios.local
     * @param null|string $encryption (optional) encryption method, see nsca configuration
     * @param null|string $password (optional) password for encryption method
     */
    public function __construct($connectionString, $encryption = null, $password = null) {
        if (strpos($connectionString, ':')) {
            $connect = explode(':', $connectionString);
            $this->hostname = $connect[0];
            $this->port = intval($connect[1]);
        } else {
            $this->hostname = $connectionString;
        }
        $this->encryption = $encryption;
        $this->password = $password;
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
    public function send($host, $service, $returncode, $message = '') {
        if ($this->hostname === null) {
            return $this->handleError(
                'No hostname for NSCA daemon given, don\'t know where to connect to - class not properly initialized'
            );
        }
        if (strlen($host) >= 64) {
            $this->handleWarning('Host name too long (max 64 characters) - truncated');
            $host = substr($host, 0, 63);
        }
        if (strlen($service) >= 128) {
            $this->handleWarning('Service name too long (max 128 characters) - truncated');
            $service = substr($service, 0, 127);
        }
        if (strlen($message) >= 512) {
            $this->handleWarning('Message too long (max 512 characters) - truncated');
            $message = substr($message, 0, 511);
        }
        $reflection = new \ReflectionClass('\\' . __NAMESPACE__ . '\\NagiosCodes');
        if (!in_array($returncode, $reflection->getConstants())) {
            return $this->handleError('unknown return code: ' . $returncode);
        }

        // try to connect to host
        $errno = $errstr = null;
        // i hate myself for using '@' to suppress the warning, but spam in logfiles had to be prevented
        $connection = @stream_socket_client(
            $this->hostname . ':' . $this->port,
            $errno,
            $errstr,
            $this->connectTimeout
        );
        if (! $connection) {
            return $this->handleError('Cannot connect to nsca daemon ' . $this->hostname . ':' . $this->port);
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
            if (false === $packet = $this->encrypt($packet, $iv)) {
                return $this->handleError('Cannot encrypt package');
            }
        }

        // send it
        fflush($connection);
        fwrite($connection, $packet);
        fclose($connection);
        return true;
    }

    /**
     * Encrypts a package using mcrypt (for all encryptions except simpleXor)
     *
     * @param string $packet
     * @param string $iv
     * @return string|false
     */
    protected function encrypt($packet, $iv) {
        if ($this->encryption === self::ENCRYPT_XOR) {
            return $this->simpleXor($packet, $iv);
        }

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
     * Encrypts a package using nagios simple xor algoritm
     *
     * @param string $packet
     * @param string $initializationVector
     * @author nueaf
     * @return mixed
     */
    protected function simpleXor($packet, $initializationVector) {
        $packetSize = strlen($packet);
        $ivSize = strlen($initializationVector);
        /* rotate over IV we received from the server... */
        for ($y = 0, $x = 0; $y < $packetSize; $y++, $x++) {
            /* keep rotating over IV */
            if ($x >= $ivSize) {
                $x = 0;
            }
            $packet[$y] = $packet[$y] ^ $initializationVector[$x];
        }

        /* rotate over password... */
        $passwordLength = strlen($this->password);
        for ($y = 0, $x = 0; $y < $packetSize; $y++, $x++) {
            /* keep rotating over password */
            if ($x >= $passwordLength) {
                $x = 0;
            }
            $packet[$y] = $packet[$y] ^ $this->password[$x];
        }
        return $packet;
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

    /**
     * Sets mode. By default send_nsca will remain silent and tries not to interrupt
     * the running program in any way, this includes logging warnings and errors.
     *
     * @param int $mode see class constants
     * @return $this
     */
    public function setMode($mode) {
        if (
            $mode === self::MODE_SILENT ||
            $mode === self::MODE_DEVELOPMENT ||
            $mode === self::MODE_EXCEPTION
        ) {
            $this->mode = $mode;
        }
        return $this;
    }

    /**
     * Determines if a warning should be printed or not
     *
     * @param string $message Message to display if development mode is active
     * @return bool
     */
    protected function handleWarning($message) {
        if (
            $this->mode === self::MODE_DEVELOPMENT ||
            $this->mode === self::MODE_EXCEPTION
        ) {
            trigger_error($message, \E_USER_WARNING);
        }
        /* We won't throw an Exception for warnings, even if in developer mode */
        return false;
    }

    /**
     * Determines if an error should be printed or not
     *
     * @param string $message Message to abort with if development mode is active
     * @throws \Exception
     * @return bool
     */
    protected function handleError($message) {
        if ($this->mode === self::MODE_DEVELOPMENT) {
            trigger_error($message, E_USER_ERROR);
        } elseif ($this->mode === self::MODE_EXCEPTION) {
            throw new \Exception($message);
        }
        return false;
    }
}
