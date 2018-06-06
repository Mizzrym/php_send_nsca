<?php

namespace PhpSendNsca\interfaces;

/**
 * Interface to provide Nagios Status Codes
 *
 * @author Mizzrym
 */
interface NagiosCodes
{
	const STATE_OK = 0;
	const STATE_WARNING = 1;
	const STATE_CRITICAL = 2;
	const STATE_UNKNOWN = 3;
	const HOST_UP = 0;
        const HOST_UPDOWN = 1;
	const HOST_DOWN = 2;
	const HOST_UNKNOWN = 3;
}
