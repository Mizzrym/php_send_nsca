php send nsca
=============

send nsca implementation in PHP for nagios. 


usage
-----

See example.php and MyNscaClassExample.class.php


important
---------

"Be aware of bugs in the following code. I've only proved it correct, not tested it". Of course, it's not that kind of extreme, but be aware that i've only tested the code in my environment, where we only use triple DES encryption with NSCA. If you use any other kind of encryption and the code fails to work i'd take a look at the length of the initialisation vector first. Also check how the encryption is called in PHPs mcrypt extension on your system. I've encountered a really old SuSE box where the name of the triple DES encryption in mcrypt was different from the newer debian boxes. 

errorhandling
-------------
If you don't want the class to throw Exceptions, override the send function to something like this: 

	public static function send($host, $service, $returncode, $message = '')
	{
		try {
			parent::send($host, $service, $returncode, $message);
			return true;
		} catch(NscaException $e) {
			return false;
		} 
	}

Be aware that wrong encryption typenames can also lead to critical failures that will stop your programs execution at runtime.
