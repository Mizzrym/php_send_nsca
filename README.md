php send nsca
=============

send nsca implementation in PHP for nagios.


usage
-----

See example.php and MyNscaClassExample.php


important
---------

"Be aware of bugs in the following code. I've only proved it correct, not tested it". Of course, it's not that kind of extreme, but be aware that i've only tested the code in my environment, where we only use triple DES encryption with NSCA. If you use any other kind of encryption consider yourself a testsubject. Also check how the encryption is called in PHPs mcrypt extension on your system. I've encountered a really old SuSE box where the name of the triple DES encryption in mcrypt was different from the newer debian boxes.

errorhandling
-------------

The class will return true or false. Be aware that wrong encryption typenames can lead to critical failures that will stop your programs execution at runtime (if you don't handle errors on your own)
