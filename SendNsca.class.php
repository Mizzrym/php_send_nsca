<?php

class SendNsca
{
    protected $hostname;
    protected $port;
    protected $encryption;
    protected $password;

    const STATE_OK = 0;
    const STATE_WARNING = 1;
    const STATE_CRITICAL = 2;
    const STATE_UNKNOWN = 3;

    public function __construct($hostname = 'localhost', $port = '5667', $encryption = null, $password = null)
    {
        $this->hostname = $hostname;
        $this->port = $port;
        $this->encryption = $encryption;
        $this->password = $password;
    }

    public function setEncryption($encryption, $password)
    {
        $this->encryption = $encryption;
        $this->password = $password;
    }

    public function send($host, $service, $returncode, $message)
    {
        $connection = stream_socket_client($this->hostname . ':' . $this->port, $errno, $errstr, 30);
        if (!$connection)
            throw new NscaException('Could not connect to NSCA Server on ' . $this->hostname);
        stream_set_timeout($connection, 10);

        $iv = stream_get_contents($connection, 128); //initialisation vector for encryption
        $timestamp = reset(unpack('N', stream_get_contents($connection, 4)));

        $this->fillBufferWithRandomData($host, 64);
        $this->fillBufferWithRandomData($service, 128);
        $this->fillBufferWithRandomData($message, 512);

        $packet = pack('nxxxxxxNna64a128a512xx', 3, $timestamp, $returncode, $host, $service, $message);
        $crc = crc32($packet);
        $packet = pack('nxxNNna64a128a512xx', 3, $crc, $timestamp, $returncode, $host, $service, $message);

        if ($this->encryption !== null)
            $packet = $this->encrypt($packet, $iv);

        fflush($connection);
        fwrite($connection, $packet);
        fclose($connection);
    }

    protected function encrypt($packet, $iv)
    {
        if ($this->password === null)
            throw new NscaException('Can\'t encrypt package without password!');

        $iv = substr($iv, 0, 8);
        $crypt = mcrypt_encrypt($this->encryption, $this->password, $packet, 'cfb', $iv);
        if ($crypt === false)
            throw new NscaException('Encryption failed');
        return $crypt;
    }

    protected function fillBufferWithRandomData(&$buffer, $maxBufferSize)
    {
        $buffer .= "\0";
        while (strlen($buffer) < $maxBufferSize)
            $buffer .= chr(mt_rand(0, 255));
        return $buffer;
    }

}
