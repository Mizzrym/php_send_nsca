php send nsca
=============

send nsca implementation in PHP for nagios.

compatibility
-------------
For php versions lower than 7.0.0 use php_send_nsca version 1.1.3

No support for php versions lower than 5.3. C'mon guys, it's almost 2018.


usage
-----

If you don't know exactly what kind of encryptor you want to use, make use of the SendNscaFactory.

You have to provide a connection string like 'nagios.local', a cipher and a password. There is a list of constants for the ciphers available in interfaces/Ciphers.php, but you can 
also just copy&paste the integer value from your nsca configuration, since they match the constants. 

If you know what you're doing you can also construct SendNsca yourself. You have to pick from three encryptors however. 
- use the XorEncryptor for Xor Encryption only
- use the OpenSslEncryptor for DES and Triple-DES encryption
- use the LegacyEncryptor for anything else, but keep in mind that it uses the mcrypt extension which was dropped in php 7.2


important
---------

"Be aware of bugs in the following code. I've only proved it correct, not tested it". Of course, it's not that kind of extreme, but be aware that i've only tested the code in my environment, where we only use triple DES encryption with NSCA. If you use any other kind of encryption consider yourself a testsubject. Also check how the encryption is called in PHPs mcrypt extension on your system. I've encountered a really old SuSE box where the name of the triple DES encryption in mcrypt was different from the newer debian boxes.

errorhandling
-------------

The class used to return true or false and didn't throw any exceptions. However, 
this behaviour has been changed. If you still want to have a "silent" nsca implementation, extend the class and let the send method catch all exceptions
