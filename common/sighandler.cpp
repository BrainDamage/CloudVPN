
#include "sighandler.h"

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
	signal (SIGPIPE, SIG_IGN);
	return 0;
#endif
}

