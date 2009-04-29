
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

#include "log.h"
#include "conf.h"
#include "gate.h"
#include "network.h"
#include "timestamp.h"

/*
 * utils
 */

#include <stdlib.h>

void init_random()
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

#include <map>
#include <queue>
using namespace std;

static map<uint32_t, int> queue_items;
static queue<uint32_t> queue_age;
static size_t queue_max_size = 1024;

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
 * scattering multipath routing
 *
 * This is viable for many common situations.
 * a] it increases bandwidth between two nodes connected by separate paths
 * b] it can improve network security in the way that attacker has to compromise
 *    more connections to get complete data.
 *
 * However, this can cause harm.
 * a] gaming - usually we want to have the best ping, not the average one.
 *    Also, as multipath can mess up packet order, some badly written games
 *    may show weird behavior.
 * b] high-performance configurations, because additional processing power
 *    is required. (in short, enable this on 'clients', but not on 'servers'.)
 * c] memory required for storing the whole thing can range to
 *    O( max_number_of_routes * max_connections^2 )
 *    which, although unlikely, can fill lots of space pretty fast.
 *
 * Situations where this is definitely _not_ viable:
 * a] server in the center of the star
 * b] long line
 * ...or one could say 'any situation that has no real multipath'
 *
 * Algorithm is:
 *
 * 1 get all connections that can route to given destination, sort them by ping
 * 2 take first N connections, so that their lowest ping is larger than ratio
 *   of highest ping
 * 3 if random number of N+1 == 0, route via random of those, else take next
 *   N connections and continue like in 2.
 *
 * (notice that we don't care about network distances)
 */

static map<address, map<int, int> > multiroute;

static int multi_ratio = 2;
static bool do_multiroute = false;

static int route_init_multi()
{
	if (config_is_true ("multipath") ) {
		do_multiroute = true;
		Log_info ("multipath scattering enabled");

		if (!config_get_int ("multipath_ratio", multi_ratio) )
			multi_ratio = 2;
		if (multi_ratio < 2) multi_ratio = 2;
		Log_info ("multipath scatter ratio is %d", multi_ratio);
	}
	return 0;
}

static void route_update_multi()
{
	if (!do_multiroute) return;

	multiroute.clear();

	map<int, connection>::iterator i, ie;
	i = comm_connections().begin();
	ie = comm_connections().end();

	map<address, connection::remote_route>::iterator j, je;

	for (;i != ie;++i) {
		j = i->second.remote_routes.begin();
		je = i->second.remote_routes.end();
		for (;j != je;++j) multiroute[j->first]
			[i->second.ping+j->second.ping+2] = i->first;
	}
}

static int route_scatter (const hwaddr&a)
{
	map<hwaddr, map<int, int> >::iterator i;
	map<int, int>::iterator j, je, ts;
	int maxping, n, r;

	i = multiroute.find (a);
	if (i == multiroute.end() ) return -2; //not found, drop it.
	j = i->second.begin();

	if (j->second == -1) return -1; //it was a local route. 100% best

	je = i->second.end();
	while (j != je) {
		ts = j;
		n = 0;
		maxping = multi_ratio * j->first;

		for (; (j != je) && (j->first < maxping);++j, ++n);

		if (j == je) r = rand() % n;
		else r = rand() % (n + 1);  //suppose the rand is enough.

		if (r != n) { //this group of connections won!
			for (;r > 0;--r, ++ts);
			return ts->second;
		}
	}
	return -3; //no routes. wtf?! We should never get here.
}

/*
 * route
 */

static map<address, route_info> route, reported_route, promisc;

static int route_dirty = 0;
static int route_report_ping_diff = 5000;
static int route_max_dist = 64;

static void report_route();

void route_init()
{
	queue_init();
	route.clear();
	reported_route.clear();
	route_dirty = 0;

	init_random();

	route_init_multi();

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

	map<int, connection>& cons = comm_connections();
	map<int, connection>::iterator i;
	map<address, connection::remote_route>::iterator j;
	map<int, gate>&gates = gate_gates;
	map<int, gate>::iterator g;
	list<address>::iterator k;

	route.clear();

	/*
	 * Following code just fills the route with stuff from connections
	 *
	 * hints:
	 * i->first = connection ID
	 * i->second = connection
	 * j->first = address
	 * j->second = ping
	 *
	 * Note that ping can't have ping 0 cuz it would get deleted.
	 *
	 * Number 2 over there is filtering zero routes out,
	 * so that local route doesn't get overpwned by some other.
	 */

	for (g = gates.begin();g != gates.end();++g) {
		if (g->second.fd < 0) continue;
		for (k = g->second.local.begin();
		        k != g->second.local.end();++k) {
			route[*k] = route_info (1, 0, - (1 + g->second.id) );
		}
	}

	for (i = cons.begin();i != cons.end();++i) {
		if (i->second.state != cs_active)
			continue;

		for ( j = i->second.remote_routes.begin();
		        j != i->second.remote_routes.end();
		        ++j ) {

			if (1 + j->second.dist > (unsigned int) route_max_dist)
				continue;

			if (route.count (j->first) ) {
				if (route[j->first].ping <
				        (2 + j->second.ping + i->second.ping) )
					continue;
				if ( (route[j->first].ping ==
				        (2 + j->second.ping + i->second.ping) )
				        && ( route[j->first].dist <
				             (1 + j->second.dist) ) ) continue;
			}

			route[j->first] = route_info
			                  (2 + j->second.ping + i->second.ping,
			                   1 + j->second.dist,
			                   i->first);
		}
	}

	promisc.clear();
	for (map<address, route_info>::iterator
	        ri = route.begin();ri != route.end(); ++ri)
		if (!ri->first.size() )
			promisc.insert (*ri);

	route_update_multi();

end:
	report_route();
}

void route_packet (uint32_t inst,
                   uint16_t dof, uint16_t ds,
                   uint16_t sof, uint16_t ss,
                   uint16_t s, const uint8_t*buf, int from)
{
	if (len < 2 + (2*hwaddr_size) ) return;

	address a (buf);

	route_update();

	int res;

	if (do_multiroute)
		res = route_scatter (a);
	else {
		map<address, route_info>::iterator r = route.find (a);

		if (r == route.end() ) {
			//if the destination is unknown, broadcast it
			route_broadcast_packet (new_packet_uid(),
			                        buf, len, conn);
			return;
		}
		res = r->second.id;
	}

	if ( (res == -1) || promisc) iface_write (buf, len);
	if (res >= 0) {
		map<int, connection>::iterator i;
		i = comm_connections().find (res);
		if (i != comm_connections().end() )
			i->second.write_packet (buf, len);
		else Log_warn ("dangling route %d", res);
	}
}

void route_broadcast_packet (uint32_t id, uint32_t ttl, uint32_t inst,
                             uint16_t dof, uint16_t ds,
                             uint16_t sof, uint16_t ss,
                             uint16_t s, const uint8_t*buf, int from)
{
	if (len < 2 + (2*hwaddr_size) ) return;

	if (queue_already_broadcasted (id) ) return; //check duplicates
	queue_add_id (id);

	route_update();

	hwaddr a (buf); //destination

	if ( (!ignore_macs) && (a == iface_cached_hwaddr() ) && (conn >= 0) ) {
		iface_write (buf, len);
		return; //it was only for us.
	}

	if (is_addr_broadcast (a) && (conn >= 0) ) {
		iface_write (buf, len); //it was also for us
	}

	map<hwaddr, route_info>::iterator r;
	if ( !is_addr_broadcast (a) ) {
		if (promisc && (conn >= 0) ) iface_write (buf, len);
		if ( (!ignore_macs) &&
		        (route.end() != (r = route.find (a) ) ) )  {

			/*
			 * if the packet is broadcast only for not knowing
			 * the correct destination, let's send it the right way.
			 * We need to keep it "broadcast", so it doesn't get
			 * duplicated by multiple hosts.
			 */
			if (do_multiroute) {
				int r = route_scatter (a);
				if (r >= 0) comm_connections() [r]
					.write_broadcast_packet (id, buf, len);
				return;
			}
			map<int, connection>::iterator
			i = comm_connections().find (r->second.id);
			if (i != comm_connections().end() ) {
				i->second.write_broadcast_packet (id, buf, len);
				return;
			} //if the connection didn't exist, forget about this.
		}
	}

	//if real broadcast is disabled, select random connection to use
	if (broadcast_nocopy) {
		if (conn >= 0) return;
		//TODO, this works only in connections that are 1:1.
		//We should weight the ratio accordingly to the pings.
		int n = comm_connections().size();
		n = rand() % n; //one random of them
		map<int, connection>::iterator i = comm_connections().begin();
		for (;n > 0;--n, ++i) if (i->first == conn) ++n;
		i->second.write_broadcast_packet (id, buf, len);
		return;
	}

	//now just broadcast the thing.
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
	uint8_t data[n* (hwaddr_size+6) ];
	uint8_t *datap = data;
	map<hwaddr, route_info>::iterator r;
	for (i = 0, r = reported_route.begin();
	        (i < n) && (r != reported_route.end() );++i, ++r) {
		r->first.get (datap);
		* (uint16_t*) (datap + hwaddr_size) =
		    htons ( (uint16_t) (r->second.dist) );
		* (uint32_t*) (datap + hwaddr_size + 2) =
		    htonl ( (uint32_t) (r->second.ping) );
		datap += hwaddr_size + 6;
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
			if ( ( (unsigned int) route_report_ping_diff <

			        ( (r->second.ping > oldr->second.ping) ?
			          r->second.ping - oldr->second.ping :
			          oldr->second.ping - r->second.ping) )

			        || (r->second.dist != oldr->second.dist) )
				report.push_back (*r);
			++r;
			++oldr;
		} else if (r->first < oldr->first) { //not in old route
			report.push_back (*r);
			++r;
		} else { //not in new route
			report.push_back (pair<hwaddr, route_info> (oldr->first, route_info (0, 0, 0) ) );
			++oldr;
		}
	}
	while (r != route.end() ) { //rest of new routes
		report.push_back (*r);
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

	uint8_t data[report.size() * (hwaddr_size+6) ];
	uint8_t*datap = data;
	list<pair<hwaddr, route_info> >::iterator rep;
	for (rep = report.begin();rep != report.end();++rep) {
		if (rep->second.ping) reported_route[rep->first] = rep->second;
		else reported_route.erase (rep->first);

		rep->first.get (datap);
		* (uint16_t*) (datap + hwaddr_size) =
		    htons ( (uint16_t) (rep->second.dist) );
		* (uint32_t*) (datap + hwaddr_size + 2) =
		    htonl ( (uint32_t) (rep->second.ping) );
		datap += hwaddr_size + 6;
	}

	comm_broadcast_route_update (data, report.size() );
}

