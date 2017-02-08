<?php

use UniTel\PHPSendNSCA\NagiosCodes;
use UniTel\PHPSendNSCA\SendNsca;

require __DIR__ . '/vendor/autoload.php';

/**
 * Class SendNscaClient
 *
 * Build your own class to load your configuration with your own preferred method.
 * This is an example of how it could look like
 */
class SendNscaClient extends SendNsca
{
	protected $hostname = '10.253.253.40';
	protected $port = '5667';
	protected $encryption = 'xor';
	protected $password = 'hugo21';
}

/*
 * configuration in nagios could look like this:
 *
define service{
    host_name               example-server
    service_description     example-service
    check_command           check_something
    active_checks_enabled   0
    passive_checks_enabled  1
    check_period            24x7
    notification_interval   30
    notification_period     24x7
    notification_options    w,c,r
    contact_groups          error-500-crew
}
 *
 * The send call itself should not need much explanation.
 */

$Nsca = new SendNscaClient();
$Nsca->send('example-server', 'example-service', NagiosCodes::STATE_OK, 'potato');
