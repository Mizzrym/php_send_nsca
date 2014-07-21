<?php

require __DIR__ . '/autoload.php';
require __DIR__ . '/MyNscaClassExample.class.php';

use php_send_nsca\Nagios;

/*
 * configuration in nagios could look like this: 
 *
define service{
    host_name               example-server
    service_description     example-service
    check_command           check_dummy
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

MyNscaClassExample::send('example-server', 'example-service', Nagios::STATE_OK, 'potato');
