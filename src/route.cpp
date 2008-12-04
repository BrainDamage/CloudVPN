
#include "route.h"
#include "comm.h"
#include "timestamp.h"
#include "log.h"

/*
 * utils
 */

#include <stdlib.h>
#include <arpa/inet.h> //for net/host endianiness

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

static int route_dirty = 0;

static int route_report_ping_diff = 5000;
/*
 * when a ping differs 5ms from the reported one, report it
 */

static void queue_init()
{
	int t;
	if (!config_get_int ("br_id_cache_size", t) ) t = 1024;
	Log_info ("broadcast ID cache size is %d", t);
	queue_max_size = t;

	if (!config_get_int ("report_ping_changes_above", t) ) t = 5000;
	Log_info ("only ping changes above %gmsec will be reported to peers",
	          0.001*t);
	route_report_ping_diff = t;
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

static map<hwaddr, route_info> route, reported_route;

static void report_route();

void route_init()
{
	queue_init();
	route.clear();
	reported_route.clear();
	route_dirty = 0;
}

void route_shutdown()
{
	route.clear();
}

void route_set_dirty()
{
	++route_dirty;
}

void route_update()
{
	if (!route_dirty) return;

	route_dirty = 0;

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

	route[hwaddr (iface_cached_hwaddr() ) ] = route_info (0, -1);

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

	report_route();
}

void route_packet (void*buf, size_t len, int conn)
{
	if (len < 2 + (2*hwaddr_size) ) return;

	route_update();

	hwaddr a (buf); //destination

	if (is_addr_broadcast (a) ) {
		route_broadcast_packet (new_packet_uid(), buf, len, conn);
		return;
	}

	if (! (route.count (a) ) ) {
		//if the destination is unknown, broadcast it
		route_broadcast_packet (new_packet_uid(), buf, len, conn);
		return;
	}

	if (route[a].id == -1) iface_write (buf, len);
	else comm_connections() [route[a].id].write_packet (buf, len);
}

void route_broadcast_packet (uint32_t id, void*buf, size_t len, int conn)
{
	if (len < 2 + (2*hwaddr_size) ) return;

	if (queue_already_broadcasted (id) ) return; //check duplicates
	queue_add_id (id);

	route_update();

	hwaddr a (buf); //destination

	if (route[a].id == -1) {
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

void route_report_to_connection (connection&c)
{
	route_update();

	/*
	 * maybe we should report "reported route" instead,
	 * but as long as the route gets correctly updated right after
	 * topology changes, there's no harm, only added percision.
	 */

	int n = route.size(), i;
	uint8_t data[n* (hwaddr_size+4) ];
	uint8_t *datap = data;
	map<hwaddr, route_info>::iterator r;
	for (i = 0, r = route.begin(); (i < n) && (r != route.end() );++i, ++r) {
		r->first.get (datap);
		* (uint32_t*) (datap + hwaddr_size) =
		    htonl ( (uint32_t) (r->second.ping) );
		datap += hwaddr_size + 4;
	}
	c.write_route_set (data, n);
}

static void report_route()
{
	/*
	 * called by route_update.
	 * determines which route information needs updating,
	 * and sends the diff info to remote connections
	 */
	map<hwaddr, route_info>::iterator r, oldr;
	list<pair<hwaddr, int> > report;
	for (r = route.begin(), oldr = reported_route.begin();
	        (r != route.end() ) && (oldr != reported_route.end() );) {
		if (r->first == oldr->first) { // hwaddresses match, check ping
			if (abs ( (r->second.ping) - (oldr->second.ping) )
			        >= route_report_ping_diff)
				report.push_back (pair<hwaddr, int> (r->first, r->second.ping) );
			++r;
			++oldr;
		} else if (r->first < oldr->first) { //not in old route
			report.push_back (pair<hwaddr, int> (r->first, r->second.ping) );
			++r;
		} else { //not in new route
			report.push_back (pair<hwaddr, int> (oldr->first, 0) );
			++oldr;
		}
	}
	while (r != route.end() ) { //rest of new routes
		report.push_back (pair<hwaddr, int> (r->first, r->second.ping) );
		++r;
	}
	while (oldr != reported_route.end() ) {
		report.push_back (pair<hwaddr, int> (oldr->first, 0) );
		++oldr;
	}

	/*
	 * now create the data to report, and apply the changes into rep. r.
	 */

	uint8_t data[report.size() * (hwaddr_size+4) ];
	uint8_t*datap = data;
	list<pair<hwaddr, int> >::iterator rep;
	for (rep = report.begin();rep != report.end();++rep) {
		if (rep->second) reported_route[rep->first] = route[rep->first];
		else reported_route.erase (rep->first);

		rep->first.get (datap);
		* (uint32_t*) (datap + hwaddr_size) =
		    htonl ( (uint32_t) (rep->second) );
		datap += hwaddr_size + 4;
	}

	comm_broadcast_route_update (data, report.size() );
}
