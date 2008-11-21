
#include "cloudvpn.h"
#include "utils.h"
#include "conf.h"
#include "log.h"

#include <unistd.h>

int g_terminate = 0;

int run_cloudvpn (int argc, char**argv)
{
	Log_info ("cloudvpn: starting");

	setup_sighandler();

	if (!config_parse (argc, argv) ) {
		Log_error ("cloudvpn: failed to parse config, terminating.");
		return 1;
	}

	while (!g_terminate) {
		//TODO fill;
	}

	Log_info ("cloudvpn: exitting gracefully");
	return 0;
}

void kill_cloudvpn (int signum)
{
	Log_info ("cloudvpn: killed by signal %d, will terminate", signum);
	g_terminate = 1;
}
