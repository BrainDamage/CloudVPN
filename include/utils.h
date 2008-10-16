
#ifndef _CVPN_UTILS_H
#define _CVPN_UTILS_H

#include "iface.h"

class hwaddr {
public:
	uint8_t addr[hwaddr_size];
	
	void set(uint8_t*);
	void get(uint8_t*);

	bool operator<(const hwaddr&);
};

inline bool is_packet_broadcast(const void*buf)
{
	return ((const char*)buf)[0]&1;
}

#endif

