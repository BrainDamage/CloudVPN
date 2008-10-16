
#ifndef _CVPN_COMM_H
#define _CVPN_COMM_H

#include "iface.h"
#include "utils.h"

#include <stdint.h>

#include <map>
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

void comm_init();
void comm_shutdown();
void comm_update();

const map<int,connection>& comm_connections();

#endif

