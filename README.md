php send nsca
=============

send nsca implementation in PHP for nagios.

php versions
------------
- 7.2+ You have to use the OpenSslEncryptor with DES or 3DES encryption
- 7.0+ You can use the LegacyEncryptor for full compatibility with any nsca ciphers
- lower than 7.0: Checkout Version 1.1.3
- lower than 5.3: not supported


usage
-----

See example.php


important
---------

"Be aware of bugs in the following code. I've only proved it correct, not tested it". Of course, it's not that kind of extreme, but be aware that i've only tested the code in my environment, where we only use triple DES encryption with NSCA. If you use any other kind of encryption consider yourself a testsubject. Also check how the encryption is called in PHPs mcrypt extension on your system. I've encountered a really old SuSE box where the name of the triple DES encryption in mcrypt was different from the newer debian boxes.

errorhandling
-------------

The class used to return true or false and didn't throw any exceptions. However, 
this behaviour has been changed. If you still want to have a "silent" nsca implementation, extend the class and let the send method catch all exceptions
