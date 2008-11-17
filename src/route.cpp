
#include "route.h"
#include "comm.h"

/*
 * utils
 */

#include <stdlib.h>
#include <sys/time.h>

void init_packet_uid_gen()
{
	struct timeval tv;
	gettimeofday (&tv, 0);
	srand (tv.tv_sec ^ tv.tv_usec);
}

#define rand_byte (rand()%256)

uint32_t new_packet_uid()
{
	uint32_t r = rand_byte;
	for (register int i = 0;i < 3;++i) r = (r << 8) | rand_byte;
	return r;
}


/*
 * route
 */

static map<hwaddr, route_info> route;

void route_init()
{
	//not much to do
}

void route_shutdown()
{
	route.clear();
}

void route_update()
{
	map<int, connection>& cons = comm_connections();
	map<int, connection>::iterator i;
	map<hwaddr, int>::iterator j;
	route.clear();
	i = cons.begin();
	/*
	 * i->first = connection ID
	 * i->second = connection
	 * j->first = hwaddr
	 * j->second = ping
	 */
	while (i != cons.end() ) {
		j = i->second.remote_routes.begin();
		while (j != i->second.remote_routes.end() ) {
			if (route.count (j->first) )
				if (route[j->first].ping <
					(j->second + i->second.ping) )
					continue;
			route[j->first] = route_info (j->second, i->first);
			++j;
		}
		++i;
	}
}

void route_packet (void*buf, size_t len, int conn)
{
	if (len < 2 + (2*hwaddr_size) ) return;
	hwaddr a (buf);
	if (is_addr_broadcast (a) ) {
		route_broadcast_packet (new_packet_uid(), buf, len, conn);
		return;
	}
	if (!route.count (a) ) return; //TODO fallback route to parent
	comm_connections() [route[a].id].write_packet (buf, len);
}

void route_broadcast_packet (uint32_t id, void*buf, size_t len, int conn)
{

}

map<hwaddr, route_info>& route_get ()
{
	return route;
}



