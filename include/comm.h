
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
	int fd;

	int state;
#define cs_inactive 0
#define cs_retry_timeout 1

#define cs_connecting 2
#define cs_ssl_connecting 3
#define cs_accepting 4
#define cs_closing 5

#define cs_active 6

	int last_retry;

	map<hwaddr, int> remote_routes;

	inline connection () {
		ping = 1; //measure the distance at least
	}

	int ping;

	int write_packet (void*buf, int len);
	int write_broadcast_packet (uint32_t id, void*buf, int len);

	void poll_read();
	void poll_write();

	inline bool status() {
		return state ? true : false;
	}

	string address;
};

void comm_listener_poll (int fd);

int comm_init();
int comm_shutdown();

map<int, connection>& comm_connections();
set<int>& comm_listeners();

#endif

