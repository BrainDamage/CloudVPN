
#include "utils.h"
#include "log.h"

#include "cloudvpn.h"

#include <signal.h>

int setup_sighandler()
{
	struct sigaction a;

	Log_info ("setting up signal handler");

	sigemptyset (&a.sa_mask);
	a.sa_flags = 0;
	a.sa_handler = kill_cloudvpn;

	sigaction (SIGTERM, &a, 0);
	sigaction (SIGINT, &a, 0);

	return 0;
}

/*
 * hwaddr stuff
 */

#include <string.h>

static int hwaddr_cmp (const uint8_t*a, const uint8_t*b)
{
	for (int i = 0;i < hwaddr_size;++i) {
		if (a[i] == b[i]) continue;

		return a[i] - b[i];
	}
}


bool hwaddr::operator< (const hwaddr&a) const
{
	return hwaddr_cmp (addr, a.addr) < 0 ? true : false;
}

bool hwaddr::operator== (const hwaddr&a) const
{
	return hwaddr_cmp (addr, a.addr) == 0 ? true : false;
}

bool hwaddr::operator== (const uint8_t* a) const
{
	return hwaddr_cmp (addr, a) == 0 ? true : false;
}

void hwaddr::set (uint8_t*c)
{
	memcpy (addr, c, hwaddr_size);
}

void hwaddr::get (uint8_t*c)
{
	memcpy (c, addr, hwaddr_size);
}

#include <stdlib.h>

void sockaddr_free (struct sockaddr**addr)
{
	if (*addr) free (*addr);

	*addr = 0;
}

bool sockaddr_parse (const char *addr,
                     struct sockaddr**newaddr, int*len)
{
	return false;
}
