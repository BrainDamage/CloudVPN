
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

#ifndef _CVPN_ROUTE_H
#define _CVPN_ROUTE_H

#include "iface.h"
#include "utils.h"
#include "comm.h"

#include <stdint.h>
#include <stddef.h>

#include <map>
using std::map;

void route_init();
void route_shutdown();
void route_update();
void route_packet (void*buf, size_t len, int incoming_connection = -1);
void route_broadcast_packet (uint32_t id, void*buf, size_t len, int ic = -1);

void route_set_dirty();
void route_report_to_connection (connection&c);

class route_info
{
public:
	int ping;
	int dist;
	int id;

	inline route_info (int p, int d, int i) {
		ping = p;
		id = i;
		dist = d;
	}

	inline route_info() {
		//this shall never be called.
		ping = 0;
		id = -2; //-2==error, -1==iface, 0+ == other connections
		dist = 0;
	}
};

map<hwaddr, route_info>& route_get();

#endif

