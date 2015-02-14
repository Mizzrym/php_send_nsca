<?php

namespace phpSendNsca;

class MyNscaClassExample extends SendNsca
{
    protected $hostname = '127.0.0.1';
    protected $port = '5667';
    protected $encryption = \MCRYPT_3DES;
    protected $password = 'iwantedtousepenisasapasswordbutiitsaiditwastooshort';

}