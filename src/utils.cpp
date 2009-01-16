
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

		return (int) a[i] - (int) b[i];
	}
	return 0;
}


bool hwaddr::operator< (const hwaddr&a) const
{
	return (hwaddr_cmp (addr, a.addr) < 0) ? true : false;
}

bool hwaddr::operator== (const hwaddr&a) const
{
	return (hwaddr_cmp (addr, a.addr) == 0) ? true : false;
}

bool hwaddr::operator== (const uint8_t* a) const
{
	return (hwaddr_cmp (addr, a) == 0) ? true : false;
}

void hwaddr::set (const uint8_t*c)
{
	memcpy (addr, c, hwaddr_size);
}

void hwaddr::get (uint8_t*c) const
{
	memcpy (c, addr, hwaddr_size);
}

/*
 * ip/name -> sockaddr resolution
 */

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>

bool sockaddr_from_str (const char *str,
                        struct sockaddr*addr, int*len, int*sock_domain)
{
	char ip_buf[1025], port_buf[65]; //which should be enough for everyone.
	int port = 0;

	if (! (str && addr) ) return false;

	if (sscanf (str, " %1024s %64s", ip_buf, port_buf) < 2) return false;

	struct addrinfo hints, *res;
	memset (&hints, 0, sizeof (struct addrinfo) );
	hints.ai_socktype = SOCK_STREAM;

	int ret = getaddrinfo (ip_buf, port_buf, &hints, &res);
	if (ret) {
		Log_error ("getaddrinfo failed for entry `%s %s'", ip_buf, port_buf);
		Log_error ("reason was: %d: %s", ret, gai_strerror (ret) );
		return false;
	}

	if (len) *len = res->ai_addrlen;
	if (sock_domain) *sock_domain = res->ai_family;

	memcpy (addr, res->ai_addr, res->ai_addrlen);

	freeaddrinfo (res);

	return true;
}

#include <fcntl.h>
#include <unistd.h>

bool sock_nonblock (int fd)
{
	return fcntl (fd, F_SETFL, O_NONBLOCK) >= 0;
}

string format_hwaddr (const hwaddr& a)
{
	char buf[19];
	snprintf (buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
	          a.addr[0], a.addr[1], a.addr[2],
	          a.addr[3], a.addr[4], a.addr[5]);
	return string (buf);
}

