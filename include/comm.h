
#ifndef _CVPN_COMM_H
#define _CVPN_COMM_H

#include "iface.h"
#include "utils.h"

#include <stdint.h>

#include <map>
#include <set>
#include <string>
using namespace std;

class connection {

	//some ssl stuff here
	
	int flush();
	int write(void*buf, int len);
	int read(void*buf, int len);

public:
	map<hwaddr,int> remote_routes;

	int write_packet(void*buf, int len);
	int read_packet(void*buf, int maxlen);

	bool status(); //false == can be deleted safely

	void update();
	void disconnect();

	string host_to_connect;
};

int comm_init();
int comm_shutdown();
int comm_update(int socket=-1); //-1 = all sockets

const map<int,connection>& comm_connections();
const set<int> comm_listeners();

#endif

