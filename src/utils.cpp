
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
#ifndef __WIN32__
	struct sigaction a;

	Log_info ("setting up signal handler");

	sigemptyset (&a.sa_mask);
	a.sa_flags = 0;
	a.sa_handler = kill_cloudvpn;

	sigaction (SIGTERM, &a, 0);
	sigaction (SIGINT, &a, 0);

	return 0;
#else //__WIN32__
	signal (SIGINT, kill_cloudvpn);
	signal (SIGTERM, kill_cloudvpn);
	return 0;
#endif
}

/*
 * ip/name -> sockaddr resolution
 */

#ifndef __WIN32__
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#else
#define _WIN32_WINNT 0x0501 //for mingw's addrinfo
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

bool sockaddr_from_str (const char *str,
                        struct sockaddr*addr, int*len, int*sock_domain)
{
	char ip_buf[1025], port_buf[65]; //which should be enough for everyone.

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

const char* sockaddr_to_str (struct sockaddr*addr)
{
#ifndef __WIN32__
	static char buf[128];
	const void*t;
	int port;
	switch (addr->sa_family) {
	case AF_INET:
		t = (const void*) & ( ( (sockaddr_in*) addr)->sin_addr);
		port = ntohs ( ( (sockaddr_in*) addr)->sin_port);
		break;
	case AF_INET6:
		t = (const void*) & ( ( (sockaddr_in6*) addr)->sin6_addr);
		port = ntohs ( ( (sockaddr_in6*) addr)->sin6_port);
		break;
	default:
		return 0;
	}

	if (!inet_ntop (addr->sa_family, t, buf, 127) ) return 0;
	snprintf (buf + strlen (buf), 16, " %d", port);
	return buf;
#else
	return "(?)";
#endif
}

#include <fcntl.h>
#include <unistd.h>

bool sock_nonblock (int fd)
{
#ifndef __WIN32__
	return fcntl (fd, F_SETFL, O_NONBLOCK) >= 0;
#else
	u_long a = 1;
	return ioctlsocket (fd, FIONBIO, &a) >= 0;
#endif
}

string format_hwaddr (const hwaddr& a)
{
	char buf[19];
	snprintf (buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
	          a.addr[0], a.addr[1], a.addr[2],
	          a.addr[3], a.addr[4], a.addr[5]);
	return string (buf);
}

