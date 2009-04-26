
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
	uint32_t inst;
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

	inline address() {};

	inline address (const address&a) :
			inst (a.inst),
			addr (a.addr) {}

	inline address (uint32_t i, const uint8_t*data, size_t size) :
			inst (i), addr (size) {
		copy (data, data + size, addr.begin() );
	}

	inline void set (uint32_t i, const uint8_t*data, size_t size) {
		addr.resize(size);
		copy (data, data + size, addr.begin() );
		inst=i;
	}
		

	/*
	 * string handling
	 */
	string format_addr() const;
	string format() const;
	bool scan_addr (const char*);
	bool scan (const char*);
};


#endif

