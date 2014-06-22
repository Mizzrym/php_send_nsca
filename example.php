<?php
include __DIR__ . '/NscaException.class.php';
include __DIR__ . '/SendNsca.class.php';
include __DIR__ . '/MyNscaClassExample.class.php';

var_dump(MyNscaClassExample::send('example server', 'example service', MyNscaClassExample::STATE_OK, 'potato'));
