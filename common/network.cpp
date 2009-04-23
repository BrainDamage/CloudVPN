
#include "network.h"
#include "log.h"
#include "conf.h"


#include <fcntl.h>
#include <unistd.h>

#ifndef __WIN32__
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in_systm.h>  //required on some platforms for n_time
#include <netinet/ip.h>
#include <netinet/tcp.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

static bool tcp_nodelay = false;
static int ip_tos = 0;
static int listen_backlog_size = 32;


bool sock_nonblock (int fd)
{
#ifndef __WIN32__
	return fcntl (fd, F_SETFL, O_NONBLOCK) >= 0;
#else
	u_long a = 1;
	return ioctlsocket (fd, FIONBIO, &a) >= 0;
#endif
}

int tcp_socket_writeable (int sock)
{
	fd_set s;
	struct timeval t = {0, 0};
	FD_ZERO (&s);
	FD_SET (sock, &s);
	select (sock + 1, 0, &s, 0, &t);
	if (FD_ISSET (sock, &s) ) return 1;
	return 0;
}

//TODO, call this from initialization
int network_init()
{
#ifndef __WIN32__
	tcp_nodelay = config_is_true ("tcp_nodelay");
	if (tcp_nodelay) Log_info ("TCP_NODELAY is set for all sockets");
	string t;
	if (!config_get ("ip_tos", t) ) goto no_tos;
	if (t == "lowdelay") ip_tos = IPTOS_LOWDELAY;
	else if (t == "throughput") ip_tos = IPTOS_THROUGHPUT;
	else if (t == "reliability") ip_tos = IPTOS_RELIABILITY;
#ifdef IPTOS_MINCOST  //not available on some platforms.
	else if (t == "mincost") ip_tos = IPTOS_MINCOST;
#endif
	if (ip_tos) Log_info ("type of service is `%s' for all sockets",
		                      t.c_str() );
#endif
no_tos:
	int i;
	if(config_get_int("listen_backlog",i)) listen_backlog_size=i;
	Log_info("listen backlog size is %d",listen_backlog_size);
	return 0;
}

int sockoptions_set (int s)
{
#ifndef __WIN32__
	int t;
	if (tcp_nodelay) {
		t = 1;
		if (setsockopt (s, IPPROTO_TCP, TCP_NODELAY, &t, sizeof (t) ) )
			Log_warn ( "setsockopt(%d,TCP,NODELAY) failed with %d: %s",
			           s, errno, strerror (errno) );
	}
	if (ip_tos) {
		t = ip_tos;
		if (setsockopt (s, IPPROTO_IP, IP_TOS, &t, sizeof (t) ) )
			Log_warn ("setsockopt(%d,IP,TOS) failed with %d: %s",
			          s, errno, strerror (errno) );
	}
#endif
	return 0;
}


/*
 * raw network stuff
 *
 * backends to listen/connect/accept network operations
 */

int tcp_listen_socket (const char* addr)
{
	sockaddr_type (sa);
	int sa_len, domain;
	if (!sockaddr_from_str (addr, &sa, &sa_len, &domain) ) {
		Log_error ("could not resolve address and port `%s'", addr);
		return -1;
	}

	int s = socket (domain, SOCK_STREAM, 0);

	if (s < 0) {
		Log_error ("socket() failed with %d", errno);
		return -2;
	}

	int opt = 1;
	if (setsockopt (s, SOL_SOCKET, SO_REUSEADDR,
#ifdef __WIN32__
	                (const char*)
#endif
	                &opt, sizeof (opt) ) < 0)
		Log_warn ("setsockopt(%d,SO_REUSEADDR) failed, may cause errors.", s);

	if (!sock_nonblock (s) ) {
		Log_error ("can't set socket %d to nonblocking mode", s);
		close (s);
		return -3;
	}

	if (bind (s, &sa, sa_len) ) {
		Log_error ("binding socket %d failed with %d", s, errno);
		close (s);
		return -4;
	}

	if (listen (s, listen_backlog_size) ) {
		Log_error ("listen(%d,%d) failed with %d",
		           s, listen_backlog_size, errno);
		close (s);
		return -5;
	}

	Log_info ("created listening socket %d", s);

	return s;
}

int tcp_connect_socket (const char*addr)
{
	sockaddr_type (sa);
	int sa_len, domain;
	if (!sockaddr_from_str (addr, &sa, &sa_len, &domain) ) {
		Log_error ("could not resolve address and port `%s'", addr);
		return -1;
	}

	int s = socket (domain, SOCK_STREAM, 0);

	if (s < 0) {
		Log_error ("socket() failed with %d", errno);
		return -2;
	}

	if (!sock_nonblock (s) ) {
		Log_error ("can't set socket %d to nonblocking mode", s);
		close (s);
		return -3;
	}

	sockoptions_set (s);

	if (connect (s, &sa, sa_len) < 0 ) {
		int e = errno;
		if (e != EINPROGRESS) {
			Log_error ("connect(%d) to `%s' failed with %d",
			           s, addr, e);
			return -4;
		}
	}

	return s;
}

int tcp_close_socket (int sock)
{
	if (close (sock) ) {
		Log_warn ("closing socket %d failed with %d!", sock, errno);
		return 1;
	}
	return 0;
}



