
#ifndef _CVPN_UTILS_H
#define _CVPN_UTILS_H

#include "iface.h"

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
};

inline bool is_packet_broadcast (const void*buf)
{
	return ( (const char*) buf) [0]&1;
}

inline bool is_addr_broadcast (const hwaddr&a)
{
	return is_packet_broadcast (a.addr);
}

bool sockaddr_parse(const char*a,
	struct sockaddr**newaddr,int*len);

void sockaddr_free(struct sockaddr**addr);

#endif

