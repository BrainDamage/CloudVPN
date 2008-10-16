
#include "route.h"
#include "utils.h"
#include "comm.h"
#include <map>
using std::map;

static map<hwaddr,int> route;

void route_init()
{
	//not much to do
}

void route_shutdown()
{
	route.clear();
}

void route_update()
{
	//construct route from connections
}

void route_packet(void*buf, size_t len, int conn)
{
	
}

void route_broadcast_packet(uint32_t id, void*buf, size_t len, int conn)
{
	
}





