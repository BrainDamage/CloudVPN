
#ifndef _CVPN_COMM_H
#define _CVPN_COMM_H

#include "iface.h"
#include "utils.h"

#include <stdint.h>

#include <map>
#include <list>
#include <string>

using namespace std;

class connection
{

	//some ssl stuff here

	int flush();
	int write (void*buf, int len);
	int read (void*buf, int len);

	bool working;

public:
	int fd;

	map<hwaddr, int> remote_routes;

	inline connection (string recon = "") {
		ping = 1; //at least measure the distance
		reconnect = recon;
		working = true;
	}

	int ping;

	int write_packet (void*buf, int len);
	int write_broadcast_packet (uint32_t id, void*buf, int len);

	void poll_read();
	void poll_write();

	inline bool status() {
		//false == can be deleted safely
		if (working) return true;

		if (reconnect.length() ) return true;

		return false;
	}

	void update();
	void disconnect();

	string reconnect;
};

int comm_init();
int comm_shutdown();

int comm_update_connections();

map<int, connection>& comm_connections();
list<int> comm_listeners();

#endif

