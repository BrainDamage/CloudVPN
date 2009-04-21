
#include "address.h"


int address::cmp (const address&a) const
{
	if (proto != a.proto) return proto -a.proto;
	if (inst != a.inst) return inst -a.inst;

	vector<uint8_t>::const_iterator i, j;
	for (i = addr.begin(), j = a.addr.begin();
	        (i < addr.end() ) && (j < a.addr.end() ); ++i, ++j) {

		if (*i == *j) continue;
		return ( (int) *i) - ( (int) *j);
	}
	if (i == addr.end() )
		if (j == a.addr.end() ) return 0;
		else return -1;
	else return 1;
}


