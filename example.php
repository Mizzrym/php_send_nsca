<?php

use PhpSendNsca\SendNscaFactory;

require __DIR__ . '/vendor/autoload.php';

$factory = new SendNscaFactory();
$nsca = $factory->getSendNsca('localhost', SendNscaFactory::ENCRYPT_3DES, 'somepassword');

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

$nsca->send('example-server', 'example-service', $nsca::STATE_OK, 'potato');
