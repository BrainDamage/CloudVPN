
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

static bool multiroute_scatter (const address&a, int*result)
{
	map<address, map<int, int> >::iterator i;
	map<int, int>::iterator j, je, ts;
	int maxping, n, r;

	i = multiroute.find (a);
	if (i == multiroute.end() ) return false; //not found, drop it.
	j = i->second.begin();

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
			*result = ts->second;
			return true;
		}
	}
	return false; //no routes. wtf?! We should never get here.
}

/*
 * route
 */

static map<address, route_info> route, reported_route;
static multimap<address, route_info> promisc;

static int route_dirty = 0;
static int route_report_ping_diff = 5000;
static int route_max_dist = 64;
static int default_broadcast_ttl = 128;

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

	if (!config_get_int ("route_broadcast_ttl", t) ) t = 64;
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
	map<int, gate>&gates = gate_gates();
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

			route_info temp (2 + j->second.ping + i->second.ping,
			                 1 + j->second.dist,
			                 i->first);
			route[j->first] = temp;
			if (!j->first.addr.size() )
				promisc.insert (pair<address, route_info>
				                (j->first, temp) );

		}
	}

	route_update_multi();

end:
	report_route();
}

static void send_packet_to_id (int to, uint32_t inst,
                               uint16_t dof, uint16_t ds,
                               uint16_t sof, uint16_t ss,
                               uint16_t s, const uint8_t*buf)
{
	if (to < 0) {
		map<int, gate>::iterator g =
		    gate_gates().find (- (to + 1) );
		if (g == gate_gates().end() ) return;
		g->second.send_packet (inst, dof, ds, sof, ss, s, buf);
	} else {
		map<int, connection>::iterator c =
		    comm_connections().find (to);
		if (c == comm_connections().end() ) return;
		c->second.write_packet (inst, dof, ds, sof, ss, s, buf);
	}
}

void route_packet (uint32_t inst,
                   uint16_t dof, uint16_t ds,
                   uint16_t sof, uint16_t ss,
                   uint16_t s, const uint8_t*buf, int from)
{
	if (s < dof + ds ) return; //invalid packet
	if (!ds) return; //can't do zero destination

	int result;
	bool need_send = true;

	route_update();
	address a (inst, buf + dof, ds), p (inst, 0, 0);
	map<address, route_info>::iterator r;
	multimap<address, route_info>::iterator i, e;

	if (a.is_broadcast() ) goto broadcast;

	if (do_multiroute) { //check for a target
		if (!multiroute_scatter (a, &result) ) goto broadcast;
	} else {
		r = route.find (a);
		if ( (r == route.end() ) || a.is_broadcast() ) goto broadcast;
	}

	//send it to local promiscs
	i = promisc.lower_bound (p);
	e = promisc.upper_bound (p);

	for (;i != e;++i) {
		if (i->second.id >= 0 ) continue; // not local
		if (i->second.id == result) need_send = false;
		if (from == i->second.id) continue;
		send_packet_to_id (i->second.id, inst, dof, ds, sof, ss, s, buf);
	}

	//finally, send it to destination
	if (need_send)
		send_packet_to_id (result, inst, dof, ds, sof, ss, s, buf);

	return;

broadcast: // in case we fail to find a suitable destination, broadcast.
	route_broadcast_packet (new_packet_uid(), default_broadcast_ttl,
	                        inst, dof, ds, sof, ss, s, buf, from);
}

static void send_broadcast_to_id (int to,
                                  uint32_t id, uint16_t ttl, uint32_t inst,
                                  uint16_t dof, uint16_t ds,
                                  uint16_t sof, uint16_t ss,
                                  uint16_t s, const uint8_t*buf)
{
	if (to < 0) {
		map<int, gate>::iterator g =
		    gate_gates().find (- (to + 1) );
		if (g == gate_gates().end() ) return;
		g->second.send_packet (inst, dof, ds, sof, ss, s, buf);
	} else if (ttl) {
		map<int, connection>::iterator c =
		    comm_connections().find (to);
		if (c == comm_connections().end() ) return;
		c->second.write_broadcast_packet (id, ttl - 1,
		                                  inst, dof, ds, sof, ss,
		                                  s, buf);
	}
}

void route_broadcast_packet (uint32_t id, uint16_t ttl, uint32_t inst,
                             uint16_t dof, uint16_t ds,
                             uint16_t sof, uint16_t ss,
                             uint16_t s, const uint8_t*buf, int from)
{
	if (s < dof + ds) return; //invalid one
	if (!ds) return; //cant do zero destination

	if (queue_already_broadcasted (id) ) return; //check duplicates
	queue_add_id (id);

	route_update();

	address a (inst, buf + dof, ds), p (inst, 0, 0);

	bool nosend = false;
	int nosendid;

	if (!a.is_broadcast() ) {
		//send it to probable destination, if we know it
		map<address, route_info>::iterator dest = route.find (a);
		if ( (dest != route.end() ) && (from != dest->second.id) ) {
			nosendid = dest->second.id;
			nosend = true;
			send_broadcast_to_id (dest->second.id, id, ttl,
			                      inst, dof, ds, sof, ss, s, buf);
		}

		//send it to all known promiscs
		multimap<address, route_info>::iterator
		i = promisc.lower_bound (p), e = promisc.upper_bound (p);

		//if we don't know any promiscs, broadcast
		if (i == e) goto broadcast;

		for (;i != e;++i) {
			if (from == i->second.id) continue;
			if (nosend && (nosendid == i->second.id) ) continue;
			send_broadcast_to_id (i->second.id, id, ttl,
			                      inst, dof, ds, sof, ss, s, buf);
		}
		return;
	}

broadcast:

	map<int, gate>::iterator
	j = gate_gates().begin(),
	    je = gate_gates().begin();

	for (;j != je;++j) {
		if (j->first == from) continue; //dont send back
		if (j->second.fd < 0) continue; //ready only
		if (! (j->second.instances.count (address (inst, 0, 0) ) ) )
			continue;

		j->second.send_packet (inst, dof, ds, sof, ss, s, buf);
	}

	if (!ttl) return; //don't spread this any further

	map<int, connection>::iterator
	i = comm_connections().begin(),
	    e = comm_connections().end();

	for (;i != e;++i) {
		if (i->first == from) continue; //dont send back
		if (i->second.state != cs_active) continue; //ready only

		i->second.write_broadcast_packet (id, ttl - 1, inst,
		                                  dof, ds, sof, ss, s, buf);
	}
}

map<address, route_info>& route_get ()
{
	return route;
}

void route_report_to_connection (connection&c)
{
	/*
	 * note that route_update is NOT wanted here!
	 */

	size_t size = 0;
	map<address, route_info>::iterator r;
	for (r = reported_route.begin();r != reported_route.end();++r)
		size += r->first.addr.size() + 14;

	vector<uint8_t> data (size);
	uint8_t *datap = data.begin().base();

	for (r = reported_route.begin(); (r != reported_route.end() ); ++r) {
		* (uint32_t*) (datap) =
		    htonl ( (uint32_t) (r->second.ping) );
		* (uint32_t*) (datap + 4) =
		    htonl ( (uint32_t) (r->second.dist) );
		* (uint32_t*) (datap + 8) =
		    htonl ( (uint32_t) (r->first.inst) );
		* (uint16_t*) (datap + 12) =
		    htons ( (uint16_t) (r->first.addr.size() ) );
		copy (r->first.addr.begin(), r->first.addr.end(), datap + 14);
		datap += 14 + r->first.addr.size();
	}
	c.write_route_set (data.begin().base(), size);
}

static void report_route()
{
	/*
	 * called by route_update.
	 * determines which route information needs updating,
	 * and sends the diff info to remote connections
	 */

	map<address, route_info>::iterator r, oldr;
	list<pair<address, route_info> > report;

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
			report.push_back (pair<address, route_info>
			                  (oldr->first, route_info (0, 0, 0) ) );
			++oldr;
		}
	}
	while (r != route.end() ) { //rest of new routes
		report.push_back (*r);
		++r;
	}
	while (oldr != reported_route.end() ) {
		report.push_back (pair<address, route_info> (oldr->first, route_info (0, 0, 0) ) );
		++oldr;
	}

	/*
	 * now create the data to report, and apply the changes into rep. r.
	 */

	size_t size = 0;
	list<pair<address, route_info> >::iterator rep;
	for (rep = report.begin();rep != report.end();++rep)
		size += rep->first.addr.size() + 14;

	vector<uint8_t> data (size);
	uint8_t *datap = data.begin().base();

	for (rep = report.begin();
	        (rep != report.end() ); ++rep) {

		if (rep->second.ping) reported_route[rep->first] = rep->second;
		else reported_route.erase (rep->first);

		* (uint32_t*) (datap) =
		    htonl ( (uint32_t) (rep->second.ping) );
		* (uint32_t*) (datap + 4) =
		    htonl ( (uint32_t) (rep->second.dist) );
		* (uint32_t*) (datap + 8) =
		    htonl ( (uint32_t) (rep->first.inst) );
		* (uint16_t*) (datap + 12) =
		    htons ( (uint16_t) (rep->first.addr.size() ) );
		copy (rep->first.addr.begin(),
		      rep->first.addr.end(), datap + 14);
		datap += 14 + rep->first.addr.size();
	}
	comm_broadcast_route_update (data.begin().base(), size);
}

