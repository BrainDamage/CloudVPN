
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

	void set (uint8_t*);
	void get (uint8_t*);

	inline hwaddr (uint8_t* data) {
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

bool sockaddr_from_str (const char *str, struct sockaddr*addr,
                        int*len = 0, int * sock_domain = 0);


#endif

