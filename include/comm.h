
#ifndef _CVPN_COMM_H
#define _CVPN_COMM_H

#include "iface.h"
#include "utils.h"

#include <stdint.h>

#include <map>
#include <set>
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

	int ping; //cached ping

	//all routes the peer reported
	map<hwaddr, int> remote_routes;

	explicit inline connection (int ID) {
		id = ID;
		ping = 1; //measure the distance at least
	}

	connection (); //this is supposed to fail, always use c(ID)

	/*
	 * packet handling/sending functions. Those handle the endianiness.
	 */

	void handle_packet (void*buf, int len);
	void handle_broadcast_packet (uint32_t id, void*buf, int len);
	void handle_route_set();
	void handle_route_diff();
	void handle_ping (uint32_t id);
	void handle_pong (uint32_t id);

	void write_packet (void*buf, int len);
	void write_broadcast_packet (uint32_t id, void*buf, int len);
	void write_route_set();
	void write_route_diff();
	void write_ping (uint32_t id);
	void write_pong (uint32_t id);

	/*
	 * those functions are called by polling interface to do specific stuff
	 */

	void try_read();
	void try_write();

	void try_accept();
	void try_connect();
	void try_close();

	void start_connect();

	/*
	 * direct poll interface
	 */

	void poll_read();
	void poll_write();

	/*
	 * address that we should try to reconnect
	 */

	string address;
};

void comm_listener_poll (int fd);

int comm_init();
int comm_shutdown();

map<int, int>& comm_connection_index();
map<int, connection>& comm_connections();
set<int>& comm_listeners();

#endif

