
#ifndef _CVPN_NETWORK_H
#define _CVPN_NETWORK_H

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

#include <string>
using namespace std;

#define sockaddr_type(x) 	\
union { struct sockaddr x;	\
struct sockaddr_in x##_4;	\
struct sockaddr_in6 x##_6; }

#ifdef __WIN32__
#define close closesocket
#endif


#include <errno.h>
#ifndef EINPROGRESS
#define EINPROGRESS EAGAIN
#endif

/*
 * string conversion stuff
 */

bool sockaddr_from_str(const char*str, struct sockaddr*addr, int*len, int*sock_domain);

string sockaddr_to_str(struct sockaddr*addr);

/*
 * socket stuff
 */

bool sock_nonblock(int fd);
int tcp_listen_socket(const char*);
int tcp_connect_socket(const char*);
int tcp_close_socket(int fd);

int network_init();
int sockoptions_set(int fd);
int tcp_socket_writeable(int fd);

#endif

