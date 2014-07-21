<?php

/*
 * Usually you should not need this file. 
 * Working in OOP environments you usually have some sort of 
 * /lib, /vendor, /external or /whatever directory where you 
 * just put classes like these ones and your autoloader finds 
 * it using the php_send_nsca namespace. 
 * If your autoloader doesn't find it, maybe because of the 
 * fancy extensions they have, or you happen to work
 * in a rather uncommon environment you can use this file to 
 * load php_send_nsca's classes on demand instead of including 
 * just everything all the time.
 *
 * Keep in mind this won't load YOUR SendNsca-class. 
 * That's not a bug, it's a feature. 
 * Your class shouldn't be in that folder anyway. 
 */

/*
 * use anonymous functions they said
 * all cool kids do it like that they said
 */
spl_autoload_register(function($class) {
    $file = false;
    switch($class) {
        case 'php_send_nsca\Nagios':
            $file = 'Nagios.interface.php';
            break;
        case 'php_send_nsca\SendNsca':
            $file = 'SendNsca.class.php';
            break;
        case 'php_send_nsca\NscaException':
            $file = 'NscaException.class.php';
            break;
    }
    if($file) {
        include __DIR__ . '/' . $file;
    }
});
