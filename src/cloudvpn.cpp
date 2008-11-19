
#include "cloudvpn.h"
#include "conf.h"
#include "log.h"

int run_cloudvpn (int argc, char**argv)
{
	Log_info ("cloudvpn: starting");

	if (!config_parse (argc, argv) ) {
		Log_error ("cloudvpn: failed to parse config, terminating.");
		return 1;
	}

	return 0;
}
