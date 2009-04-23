
#ifndef _CVPN_ADDRESS_H
#define _CVPN_ADDRESS_H

#include <stdint.h>

#include <vector>
#include <string>
#include <algorithm>
using namespace std;

class address
{

public:
	uint16_t proto;
	uint16_t inst;
	vector<uint8_t> addr;

	int cmp (const address&) const;
	inline bool operator< (const address&a) const {
		return cmp (a) < 0;
	}
	inline bool operator> (const address&a) const {
		return cmp (a) > 0;
	}
	inline bool operator== (const address&a) const {
		return cmp (a) == 0;
	}

	inline address (const address&a) :
		proto(a.proto),
		inst(a.inst),
		addr(a.addr) {}
	
	inline address (uint16_t p, uint16_t i, uint8_t*data, size_t size) :
		proto(p), inst(i), addr(size)
	{
		copy(data,data+size,addr.begin());
	}

	/*
	 * string handling
	 */
	string format_addr() const;
	string format() const;
	bool scan_addr(const char*);
	bool scan(const char*);
};


#endif

