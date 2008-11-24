
#include "cloudvpn.h"

#include "conf.h"
#include "iface.h"
#include "log.h"
#include "poll.h"
#include "timestamp.h"
#include "utils.h"

#include <unistd.h>

int g_terminate = 0;

int run_cloudvpn (int argc, char**argv)
{
	int ret=0;
	Log_info ("cloudvpn: starting");

	setup_sighandler();

	/*
	 * initialization
	 */

	if (!config_parse (argc, argv) ) {
		Log_error ("failed to parse config, terminating.");
		ret=1;
		goto failed_config;
	}

	timestamp_update(); //initial timestamp

	if(poll_init()) {
		Log_error("poll initialization failed");
		ret=2;
		goto failed_poll;
	}

	if(!iface_create()) {
		Log_error("local interface initialization failed");
		ret=3;
		goto failed_iface;
	}

	/*
	 * main loop
	 */

	Log_info("initialization complete, entering main loop");

	while (!g_terminate) {
		poll_wait_for_event(10000); //0.01s looks pretty good.
		timestamp_update();
		//TODO, with some heartbeat, update everything updatable here.
		timestamp_update();
	}

	/*
	 * deinitialization
	 */

	Log_info("shutting down");

	iface_destroy();

failed_iface:

	if(poll_deinit())
		Log_warn("poll_deinit somehow failed!");

failed_poll:
failed_config:

	if(!ret)Log_info ("cloudvpn: exiting gracefully");
	else Log_error("cloudvpn: exiting with code %d",ret);
	return ret;
}

void kill_cloudvpn (int signum)
{
	Log_info ("cloudvpn: killed by signal %d, will terminate", signum);
	g_terminate = 1;
}
