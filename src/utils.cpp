
#include "utils.h"
#include <string.h>


static int hwaddr_cmp (const uint8_t*a, const uint8_t*b)
{
	for (int i = 0;i < hwaddr_size;++i) {
		if (a[i] == b[i]) continue;
		return a[i] - b[i];
	}
}


bool hwaddr::operator< (const hwaddr&a) const
{
	return hwaddr_cmp (addr, a.addr) < 0 ? true : false;
}

void hwaddr::set (uint8_t*c)
{
	memcpy (addr, c, hwaddr_size);
}

void hwaddr::get (uint8_t*c)
{
	memcpy (c, addr, hwaddr_size);
}
