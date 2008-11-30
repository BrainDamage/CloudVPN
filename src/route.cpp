
#include "route.h"
#include "comm.h"
#include "timestamp.h"

/*
 * utils
 */

#include <stdlib.h>

void init_packet_uid_gen()
{
	timestamp_update();
	srand (timestamp() ^ (timestamp() / 1000000) );
}

#define rand_byte (rand()%256)

uint32_t new_packet_uid()
{
	uint32_t r = rand_byte;

	for (register int i = 0;i < 3;++i) r = (r << 8) | rand_byte;

	return r;
}

/*
 * ID cache
 */

#include "conf.h"

#include <set>
#include <queue>
using namespace std;

static set<uint32_t> queue_items;
static queue<uint32_t> queue_age;
static size_t queue_max_size = 1024;

static void queue_init()
{
	int t;
	if (!config_get_int ("br_id_cache_size", t) )
		t = 1024;

	queue_max_size = t;
}

static void queue_add_id (uint32_t id)
{
	while (queue_age.size() >= queue_max_size) {
		queue_items.erase (queue_age.front() );
		queue_age.pop();
	}
	queue_items.insert (id);
	queue_age.push (id);
}

static bool queue_already_broadcasted (uint32_t id)
{
	if (queue_items.count (id) ) return false;
	return true;
}

/*
 * route
 */

static map<hwaddr, route_info> route;

void route_init()
{
	queue_init();
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

	hwaddr a (buf); //destination

	if (is_addr_broadcast (a) ) {
		route_broadcast_packet (new_packet_uid(), buf, len, conn);
		return;
	}

	if (a == iface_cached_hwaddr() ) {
		//we accept the packet and write it to interface
		iface_write (buf, len);
		return;
	}

	if (! (route.count (a) ) ) {
		//if the destination is unknown, broadcast it
		route_broadcast_packet (new_packet_uid(), buf, len, conn);
		return;
	}

	comm_connections() [route[a].id].write_packet (buf, len);
}

void route_broadcast_packet (uint32_t id, void*buf, size_t len, int conn)
{
	if (len < 2 + (2*hwaddr_size) ) return;

	if (queue_already_broadcasted (id) ) return; //check duplicates
	queue_add_id (id);

	hwaddr a (buf); //destination

	if (a == iface_cached_hwaddr() ) {
		iface_write (buf, len);
		return; //it was only for us.
	}

	if (is_addr_broadcast (a) )
		iface_write (buf, len); //it was also for us

	//now broadcast the thing.
	map<int, connection>::iterator
	i = comm_connections().begin(),
	    e = comm_connections().end();

	for (;i != e;++i) {
		if (i->first == conn) continue; //dont send back
		i->second.write_broadcast_packet (id, buf, len);
	}
}

map<hwaddr, route_info>& route_get ()
{
	return route;
}



