
#include "cloudvpn.h"

#include "log.h"
#include "comm.h"
#include "conf.h"
#include "poll.h"
#include "iface.h"
#include "route.h"
#include "utils.h"
#include "timestamp.h"
#include "userswitch.h"

#include <unistd.h>

int g_terminate = 0;

int run_cloudvpn (int argc, char**argv)
{
	int ret = 0;
	int heartbeat_usec = 50000; //20Hz is ok by default
	uint64_t last_beat = 0;

	Log_info ("cloudvpn: starting");

	setup_sighandler();

	/*
	 * initialization
	 */

	if (!config_parse (argc, argv) ) {
		Log_error ("failed to parse config, terminating.");
		ret = 1;
		goto failed_config;
	}

	if (!config_get_int ("heartbeat", heartbeat_usec) )
		heartbeat_usec = 50000;
	Log_info ("heartbeat is set to %d usec", heartbeat_usec);

	timestamp_update(); //get initial timestamp

	route_init();

	if (poll_init() ) {
		Log_fatal ("poll initialization failed");
		ret = 2;
		goto failed_poll;
	}

	if (iface_create() ) {
		Log_fatal ("local interface initialization failed");
		ret = 3;
		goto failed_iface;
	}

	if (comm_init() ) {
		Log_fatal ("communication initialization failed");
		ret = 4;
		goto failed_comm;
	}

	if(do_switch_user() ) {
		Log_fatal ("changing process owner failed");
		ret = 5;
		goto failed_user;
	}

	/*
	 * main loop
	 */

	Log_info ("initialization complete, entering main loop");

	last_beat = 0; //update immediately.

	while (!g_terminate) {

		timestamp_update();

		if ( (timestamp() - last_beat) < heartbeat_usec) {
			//poll more stuff
			poll_wait_for_event (heartbeat_usec
			                     - timestamp()
			                     + last_beat);
			continue;
		}

		last_beat = timestamp();

		route_update();
		comm_periodic_update();

		//this is now subject to deletion.
		Log_debug ("periodical update at %lu usec unixtime", last_beat);
	}

	/*
	 * deinitialization
	 */

	Log_info ("shutting down");

failed_user:

	comm_shutdown();

failed_comm:

	iface_destroy();

failed_iface:

	if (poll_deinit() )
		Log_warn ("poll_deinit somehow failed!");

failed_poll:
failed_config:
	if (!ret) Log_info ("cloudvpn: exiting gracefully");
	else Log_error ("cloudvpn: exiting with code %d", ret);
	return ret;
}

void kill_cloudvpn (int signum)
{
	Log_info ("cloudvpn: killed by signal %d, will terminate", signum);
	g_terminate = 1;
}

