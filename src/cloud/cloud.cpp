
/*
 * CloudVPN
 *
 * This program is a free software: You can redistribute and/or modify it
 * under the terms of GNU GPLv3 license, or any later version of the license.
 * The program is distributed in a good hope it will be useful, but without
 * any warranty - see the aforementioned license for more details.
 * You should have received a copy of the license along with this program;
 * if not, see <http://www.gnu.org/licenses/>.
 */

#include "cloud.h"

#include "sq.h"
#define LOGNAME "cloud"
#include "log.h"
#include "comm.h"
#include "conf.h"
#include "gate.h"
#include "poll.h"
#include "route.h"
#include "status.h"
#include "network.h"
#include "security.h"
#include "timestamp.h"
#include "sighandler.h"

#include <unistd.h>

int g_terminate = 0;

int main (int argc, char**argv)
{
	int ret = 0;
	int heartbeat_usec = 50000; //20Hz is ok by default
	uint64_t last_beat = 0;

	Log_info ("cloudvpn starting");
	Log (0, "You are using CloudVPN, which is Free software.");
	Log (0, "For more information please see the GNU GPL license,");
	Log (0, "which you should have received along with this program.");

	setup_sighandler (kill_cloudvpn);

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

	status_init();
	route_init();
	squeue_init();
	network_init();

	if (poll_init() ) {
		Log_fatal ("poll initialization failed");
		ret = 2;
		goto failed_poll;
	}

	if (do_memlock() ) {
		Log_fatal ("locking process to memory failed");
		ret = 3;
		goto failed_poll;
	}

	if (comm_load() ) {
		Log_fatal ("failed to load comm data");
		ret = 4;
		goto failed_poll;
	}

	if (comm_init() ) {
		Log_fatal ("communication initialization failed");
		ret = 5;
		goto failed_comm;
	}

	if (gate_init() ) {
		Log_fatal ("gate initialization failed");
		ret = 6;
		goto failed_gate;
	}
	if (do_chroot() ) {
		Log_fatal ("chrooting failed");
		ret = 7;
		goto failed_sec;
	}

	if (do_switch_user() ) {
		Log_fatal ("user switch failed");
		ret = 8;
		goto failed_sec;
	}


	/*
	 * main loop
	 */

	Log_info ("initialization complete, entering main loop");

	last_beat = 0; //update immediately.

	while (!g_terminate) {

		timestamp_update();

		if ( (timestamp() - last_beat)
		        < (unsigned int) heartbeat_usec) {
			//poll more stuff
			poll_wait_for_event (heartbeat_usec
			                     - timestamp()
			                     + last_beat);
			//send the results
			comm_flush_data();
			gate_flush_data();
			continue;
		}

		last_beat = timestamp();

		gate_periodic_update();
		comm_periodic_update();
		route_periodic_update();

		status_try_export();
	}

	/*
	 * deinitialization
	 */

	Log_info ("shutting down");

failed_sec:

	gate_shutdown();

failed_gate:

	comm_shutdown();

failed_comm:

	if (poll_deinit() )
		Log_warn ("poll_deinit somehow failed!");

failed_poll:
failed_config:
	if (!ret) Log_info ("cloudvpn exiting gracefully");
	else Log_error ("cloudvpn exiting with code %d", ret);
	return ret;
}

void kill_cloudvpn (int signum)
{
	Log_info ("cloudvpn killed by signal %d, will terminate", signum);
	g_terminate = 1;
}

