
#ifndef _CVPN_UTILS_H
#define _CVPN_UTILS_H

#include "iface.h"

int setup_sighandler();

/*
 * hwaddr stuff
 */

class hwaddr
{

public:
	uint8_t addr[hwaddr_size];

	void set (const uint8_t*);
	void get (uint8_t*) const;

	inline hwaddr (const uint8_t* data) {
		set (data);
	}

	inline hwaddr (void* data) {
		set ( (uint8_t*) data);
	}

	bool operator< (const hwaddr&) const;
	bool operator== (const hwaddr&) const;
	bool operator== (const uint8_t*) const;
};

inline bool is_packet_broadcast (const void*buf)
{
	return ( (const char*) buf) [0]&1;
}

inline bool is_addr_broadcast (const hwaddr&a)
{
	return is_packet_broadcast (a.addr);
}

/*
 * sockaddr stuff
 */

bool sockaddr_from_str (const char *str, struct sockaddr*addr,
                        int*len = 0, int * sock_domain = 0);

#define sockaddr_type(x)	\
union { struct sockaddr x;	\
struct sockaddr_in x##_4;	\
struct sockaddr_in6 x##_6; };

/*
 * set socket to nonblocking state
 */

bool sock_nonblock (int fd);

#endif

