<?php

use php_send_nsca\SendNsca;


class MyNscaClassExample extends SendNsca
{
	protected static $hostname = '127.0.0.1';
	protected static $port = '5667';
	protected static $encryption = MCRYPT_3DES;
	protected static $password = 'iwantedtousepenisasapasswordbutiitsaiditwastooshort';

    /*
     * Personally i'd recommend using send like this, so if something fails the 
     * programs execution won't be stopped. Log the exception's message to some 
     * logging facility and be done with it. 
     */
    public static function send($h, $s, $r, $m = '')
    {
        try {
            parent::send($h, $s, $r, $m);
        } catch(Exception $e) {
            return false;
        }
        return true;
    }

}
