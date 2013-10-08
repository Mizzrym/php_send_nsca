<?php
class MyNscaClassExample extends SendNsca
{

    public function __construct()
    {
        parent::__construct('localhost', '5667', 'tripledes', 'iwantedtousepenisasapasswordbutitsaiditwastooshort');
    }

}
