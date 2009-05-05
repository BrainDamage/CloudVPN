
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

#include "sighandler.h"
#define LOGNAME "common/sighandler"
#include "log.h"


#include <signal.h>

int setup_sighandler (void (*func) (int) )
{
#ifndef __WIN32__
	struct sigaction a;

	Log_info ("setting up signal handler");

	sigemptyset (&a.sa_mask);
	a.sa_flags = 0;
	a.sa_handler = func;

	sigaction (SIGTERM, &a, 0);
	sigaction (SIGINT, &a, 0);

	a.sa_handler = SIG_IGN;
	sigaction (SIGPIPE, &a, 0);

	return 0;
#else //__WIN32__
	signal (SIGINT, func);
	signal (SIGTERM, func);
	//signal (SIGPIPE, SIG_IGN); How comes?
	return 0;
#endif
}

