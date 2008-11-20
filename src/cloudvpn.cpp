
#include "cloudvpn.h"
#include "utils.h"
#include "conf.h"
#include "log.h"

#include <unistd.h>

int run_cloudvpn (int argc, char**argv)
{
	Log_info ("cloudvpn: starting");

	setup_sighandler();

	if (!config_parse (argc, argv) ) {
		Log_error ("cloudvpn: failed to parse config, terminating.");
		return 1;
	}

	while (1) {
		//TODO fill;
	}

	return -1; //shall never return!
}

void kill_cloudvpn (int signum)
{
	Log_info ("cloudvpn: killed by signal %d", signum);
	//TODO deinitialize
	Log_info ("cloudvpn: exitting gracefully");
	_exit (0); //properly killed
}
