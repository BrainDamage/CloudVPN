
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

#ifndef _CVPN_COMM_H
#define _CVPN_COMM_H

#include "sq.h"
#include "address.h"

#include <stdint.h>

#include <gnutls/gnutls.h>

#include <map>
#include <set>
#include <queue>
#include <string>
using namespace std;

class connection
{
public:
	int id; //not meant to be modified.
	int fd; //set to -1 if there's no socket

	void index();
	void deindex();

	void set_fd (int i) {
		if (i < 0) return;
		deindex();
		fd = i;
		index();
	}

	void unset_fd() {
		deindex();
		fd = -1;
	}

	int state;

#define cs_inactive 0
#define cs_retry_timeout 1
#define cs_connecting 2
#define cs_ssl_connecting 3
#define cs_accepting 4
#define cs_closing 5
#define cs_active 6

	uint64_t last_retry; //last connection retry

	uint32_t ping; //cached ping
	uint8_t sent_ping_id;
	uint64_t sent_ping_time;
	//ping is on the way, if sent_ping_time==last_ping

	//all routes the peer reported
	class remote_route
	{
	public:
		uint32_t ping, dist;
		remote_route (uint32_t p, uint32_t d) {
			ping = p;
			dist = d;
		}
		remote_route () { //for STL-ability, shall never be called.
			dist = ping = timeout;
		}
	};
	map<address, remote_route> remote_routes;

	explicit inline connection (int ID) {
		id = ID;
		fd = -1;
		ping = timeout;
		last_ping = 0;
		cached_header.type = 0;
		route_overflow = false;
		stats_clear();
		ubl_available = 0;
		dbl_over = 0;
		session = 0;
		connect_address = peer_addr_str = "";
		peer_connected_since = 0;
		pending_write = 0;
	}

	connection (); //this is supposed to fail, always use c(ID)

	/*
	 * packet handling/sending functions.
	 */

	void handle_packet (uint8_t*data, int len);
	void handle_route (bool set, uint8_t*data, int len);
	void handle_ping (uint8_t id);
	void handle_pong (uint8_t id);
	void handle_route_request ();

	void write_packet (uint32_t id, uint16_t ttl, uint32_t inst,
	                   uint16_t dof, uint16_t ds,
	                   uint16_t sof, uint16_t ss,
	                   uint16_t s, const uint8_t*buf);
	void write_route_set (uint8_t*data, int n);
	void write_route_diff (uint8_t*data, int n);
	void write_ping (uint8_t id);
	void write_pong (uint8_t id);
	void write_route_request ();

	/*
	 * those functions are called by polling interface to do specific stuff
	 */

	squeue recv_q;
	squeue send_q;

	int pending_write;

	struct {
		uint8_t type;
		uint8_t special;
		uint16_t size;
	} cached_header;

	void try_parse_input();

	bool try_read();
	bool try_write(); //both called by try_data(); dont use directly

	void try_data();

	void try_accept();
	void try_connect();
	void try_ssl_connect();
	void try_close();

	void start_connect();
	void start_accept();
	void send_ping();

	void activate();
	void disconnect();
	void reset(); //hard socket disconnect.

	int handle_ssl_error (int);

	/*
	 * direct poll interface
	 */

	void poll_simple();
	void poll_read();
	void poll_write();

	/*
	 * update the stuff
	 */

	void periodic_update();

	/*
	 * address that we should try to reconnect
	 */

	string connect_address;

	/*
	 * operation timings
	 */

	static int timeout;
	static int keepalive;
	static int retry;
	uint64_t last_ping;

	/*
	 * SSL data
	 */

	gnutls_session_t session;

	int alloc_ssl (bool server);
	void dealloc_ssl();

	/*
	 * queue management
	 */

	static unsigned int mtu;
	static unsigned int max_waiting_data_size;
	static unsigned int max_remote_routes;

	inline bool can_write_data (size_t s) {
		return (send_q.len() + s < max_waiting_data_size)
		       && red_can_send (s);
	}

	/*
	 * route information size management
	 */

	bool route_overflow;
	void handle_route_overflow();

	/*
	 * stats, for exporting to status file
	 */

	void stat_packet (bool in, int size);
	void stats_update();
	void stats_clear();

	uint64_t stat_update;

	uint64_t
	in_p_total, in_p_now,
	in_s_total, in_s_now,
	out_p_total, out_p_now,
	out_s_total, out_s_now,
	in_p_speed, in_s_speed,
	out_p_speed, out_s_speed;

	static uint64_t
	all_in_p_total, all_in_s_total,
	all_out_p_total, all_out_s_total;

	string peer_addr_str;
	uint64_t peer_connected_since;

	/*
	 * bandwidth limiting
	 */

	static bool ubl_enabled;
	static int ubl_total, ubl_conn, ubl_burst;
	unsigned int ubl_available;

	static bool dbl_enabled;
	static int dbl_total, dbl_conn, dbl_burst;
	unsigned int dbl_over;

	static void bl_recompute();

	inline bool needs_write() {
		return send_q.len();
	}

	/*
	 * traffic shaping - Random Early Drop
	 */

	static bool red_enabled;
	static int red_threshold;
	bool red_can_send (size_t);
};

void comm_listener_poll (int fd);

int comm_load();
int comm_init();
int comm_shutdown();

void comm_flush_data();
void comm_periodic_update();

void comm_broadcast_route_update (uint8_t*data, int n);

map<int, int>& comm_connection_index();
map<int, connection>& comm_connections();
set<int>& comm_listeners();

#endif

