<?php
include __DIR__ . '/NscaException.class.php';
include __DIR__ . '/SendNsca.class.php';
include __DIR__ . '/MyNscaClassExample.class.php';

$n = new MyNscaClassExample();
$n->send('somehost', 'someservice', SendNsca::STATE_CRITICAL, 'somemessage');
