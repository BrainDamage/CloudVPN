
#ifndef _CVPN_NETWORK_H
#define _CVPN_NETWORK_H

#include <sys/types.h>

#include <string>
using namespace std;

#define sockaddr_type(x) 	\
union { struct sockaddr x;	\
struct sockaddr_in x##_4;	\
struct sockaddr_in6 x##_6; }

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

int sockoptions_init();
int sockoptions_set(int fd);
int tcp_socket_writeable(int fd);

#endif

