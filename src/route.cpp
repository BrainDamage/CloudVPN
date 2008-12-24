
/* 
 * CloudVPN
 *
 * This program is a free software: You can redistribute and/or modify it
 * under the terms of GNU GPLv3 license, or any later version of the license.
 * The program is distributed in a good hope it will be useful, but without
 * any warranty - see the aforementioned license for more details.
 * You should have received a copy of the license along with this program;
 * if not, see <http://www.gnu.org/licenses/>.
 */

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

#include <map>
#include <queue>
using namespace std;

static map<uint32_t, int> queue_items;
static queue<uint32_t> queue_age;
static size_t queue_max_size = 1024;

/*
 * when a ping differs 5ms from the reported one, report it
 */

static void queue_init()
{
	int t;
	if (!config_get_int ("br_id_cache_size", t) ) t = 1024;
	Log_info ("broadcast ID cache size is %d", t);
	queue_max_size = t;
}

static void queue_add_id (uint32_t id)
{
	while (queue_age.size() >= queue_max_size) {
		--queue_items[queue_age.front() ];
		if (!queue_items[queue_age.front() ])
			queue_items.erase (queue_age.front() );
		queue_age.pop();
	}

	if (queue_items.count (id) ) ++queue_items[id];
	else queue_items[id] = 1;
	queue_age.push (id);
}

static bool queue_already_broadcasted (uint32_t id)
{
	if (queue_items.count (id) ) return true;
	return false;
}

/*
 * route
 */

static int route_dirty = 0;
static int route_report_ping_diff = 5000;
static int route_max_dist = 64;
static map<hwaddr, route_info> route, reported_route;

static void report_route();

void route_init()
{
	queue_init();
	route.clear();
	reported_route.clear();
	route_dirty = 0;

	init_packet_uid_gen();

	int t;

	if (!config_get_int ("report_ping_changes_above", t) ) t = 5000;
	Log_info ("only ping changes above %gmsec will be reported to peers",
	          0.001*t);
	route_report_ping_diff = t;
	if (!config_get_int ("route_max_dist", t) ) t = 64;
	Log_info ("maximal node distance is %d", t);
	route_max_dist = t;
}

void route_shutdown()
{
	route.clear();
	reported_route.clear();
}

void route_set_dirty()
{
	++route_dirty;
}

void route_update()
{
	if (!route_dirty) return;
	route_dirty = 0;

	Log_debug ("route update");

	map<int, connection>& cons = comm_connections();
	map<int, connection>::iterator i;
	map<hwaddr, connection::remote_route>::iterator j;

	route.clear();

	/*
	 * Following code just fills the route with stuff from connections
	 *
	 * hints:
	 * i->first = connection ID
	 * i->second = connection
	 * j->first = hwaddr
	 * j->second = ping
	 *
	 * Note that ping can't have ping 0 cuz it would get deleted.
	 *
	 * Number 2 over there is filtering zero routes out,
	 * so that local route doesn't get overpwned by some other.
	 */

	if (iface_get_sockfd() > 0)
		route[hwaddr (iface_cached_hwaddr() ) ] = route_info (1, 0, -1);

	for (i = cons.begin();i != cons.end();++i) {
		if (i->second.state != cs_active)
			continue;

		for ( j = i->second.remote_routes.begin();
		        j != i->second.remote_routes.end();
		        ++j ) {
			if (1 + j->second.dist > route_max_dist) continue;
			if (route.count (j->first) )
				if (route[j->first].ping <=
				        (2 + j->second.ping + i->second.ping) )
					continue;

			route[j->first] = route_info
			                  (2 + j->second.ping + i->second.ping,
			                   1 + j->second.dist,
			                   i->first);
		}
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

	map<hwaddr, route_info>::iterator r = route.find (a);

	if (r == route.end() ) {
		//if the destination is unknown, broadcast it
		route_broadcast_packet (new_packet_uid(), buf, len, conn);
		return;
	}

	if (r->second.id == -1) iface_write (buf, len);
	else {
		map<int, connection>::iterator i;
		i = comm_connections().find (r->second.id);
		if (i != comm_connections().end() )
			i->second.write_packet (buf, len);
		else Log_warn ("dangling route %d", r->second.id);
	}
}

void route_broadcast_packet (uint32_t id, void*buf, size_t len, int conn)
{
	if (len < 2 + (2*hwaddr_size) ) return;

	if (queue_already_broadcasted (id) ) return; //check duplicates
	queue_add_id (id);

	route_update();

	hwaddr a (buf); //destination

	if (a == iface_cached_hwaddr() && (conn >= 0) ) {
		iface_write (buf, len);
		return; //it was only for us.
	}

	if (is_addr_broadcast (a) && (conn >= 0) ) {
		iface_write (buf, len); //it was also for us
	}

	//now broadcast the thing.
	map<int, connection>::iterator
	i = comm_connections().begin(),
	    e = comm_connections().end();

	for (;i != e;++i) {
		if (i->first == conn) continue; //dont send back
		if (i->second.state != cs_active) continue; //ready only
		i->second.write_broadcast_packet (id, buf, len);
	}
}

map<hwaddr, route_info>& route_get ()
{
	return route;
}

void route_report_to_connection (connection&c)
{
	/*
	 * note that route_update is NOT wanted here!
	 */

	int n = reported_route.size(), i;
	uint8_t data[n* (hwaddr_size+4) ];
	uint8_t *datap = data;
	map<hwaddr, route_info>::iterator r;
	for (i = 0, r = reported_route.begin();
	        (i < n) && (r != reported_route.end() );++i, ++r) {
		r->first.get (datap);
		* (uint16_t*) (datap + hwaddr_size) =
		    htons ( (uint16_t) (r->second.dist) );
		* (uint32_t*) (datap + hwaddr_size + 2) =
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
	list<pair<hwaddr, route_info> > report;

	for (r = route.begin(), oldr = reported_route.begin();
	        (r != route.end() ) && (oldr != reported_route.end() );) {

		if (r->first == oldr->first) { // hwaddresses match, check ping and distance
			if ( (abs ( (r->second.ping) - (oldr->second.ping) )
			        >= route_report_ping_diff) ||
			        (r->second.dist != oldr->second.dist) )
				report.push_back (pair<hwaddr, route_info> (r->first, r->second) );
			++r;
			++oldr;
		} else if (r->first < oldr->first) { //not in old route
			report.push_back (pair<hwaddr, route_info> (r->first, r->second) );
			++r;
		} else { //not in new route
			report.push_back (pair<hwaddr, route_info> (oldr->first, route_info (0, 0, 0) ) );
			++oldr;
		}
	}
	while (r != route.end() ) { //rest of new routes
		report.push_back (pair<hwaddr, route_info> (r->first, r->second) );
		++r;
	}
	while (oldr != reported_route.end() ) {
		report.push_back (pair<hwaddr, route_info> (oldr->first, route_info (0, 0, 0) ) );
		++oldr;
	}

	/*
	 * now create the data to report, and apply the changes into rep. r.
	 */

	if (!report.size() ) return;

	uint8_t data[report.size() * (hwaddr_size+4) ];
	uint8_t*datap = data;
	list<pair<hwaddr, route_info> >::iterator rep;
	for (rep = report.begin();rep != report.end();++rep) {
		if (rep->second.ping) reported_route[rep->first] = rep->second;
		else reported_route.erase (rep->first);

		rep->first.get (datap);
		* (uint16_t*) (datap + hwaddr_size) =
		    htonl ( (uint16_t) (rep->second.dist) );
		* (uint32_t*) (datap + hwaddr_size + 2) =
		    htonl ( (uint32_t) (rep->second.ping) );
		datap += hwaddr_size + 4;
	}

	comm_broadcast_route_update (data, report.size() );
}
