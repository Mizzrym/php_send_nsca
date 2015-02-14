<?php

require __DIR__ . '/phpSendNsca/NagiosCodes.php';
require __DIR__ . '/phpSendNsca/SendNsca.php';
require __DIR__ . '/phpSendNsca/MyNscaClassExample.php';

use phpSendNsca\NagiosCodes;
use phpSendNsca\MyNscaClassExample;

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

$Nsca = new MyNscaClassExample();
$Nsca->send('example-server', 'example-service', NagiosCodes::STATE_OK, 'potato');
