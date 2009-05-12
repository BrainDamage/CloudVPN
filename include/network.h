
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

#ifndef _CVPN_NETWORK_H
#define _CVPN_NETWORK_H

#include <fcntl.h>
#include <unistd.h>

#ifndef __WIN32__
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>  //required on some platforms for n_time
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <errno.h>
#else
#define _WIN32_WINNT 0x0501 //for mingw's addrinfo
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#undef errno
#define errno (WSAGetLastError())
#undef EAGAIN
#define EAGAIN WSAEINPROGRESS
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif

#ifndef EINPROGRESS
#define EINPROGRESS EAGAIN
#endif

#include <string>
using namespace std;

typedef union {
	struct sockaddr sa;
	struct sockaddr_in sa_4;
	struct sockaddr_in6 sa_6;
#ifndef __WIN32__
	struct sockaddr_un sa_un;
#endif
} sockaddr_type;

#ifdef __WIN32__
#define close closesocket
#endif

/*
 * string conversion stuff
 */

bool sockaddr_from_str (const char*str, struct sockaddr*addr, int*len, int*sock_domain);

const char* sockaddr_to_str (struct sockaddr*addr);

/*
 * socket stuff
 */

bool sock_nonblock (int fd);
int tcp_listen_socket (const char*);
int tcp_connect_socket (const char*);
int tcp_close_socket (int fd, bool unlink = false);

int network_init();
int sockoptions_set (int fd);
int tcp_socket_writeable (int fd);
int sock_get_error (int fd);

#endif

