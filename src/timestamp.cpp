
#include "timestamp.h"

#include <sys/time.h>

static uint64_t lasttime;

uint64_t timestamp()
{
	return lasttime;
}

void timestamp_update()
{

	struct timeval tv;
	gettimeofday (&tv, 0);
	lasttime = (1000000 * tv.tv_sec) + tv.tv_usec;
}

