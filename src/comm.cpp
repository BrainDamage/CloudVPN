
#include "comm.h"
#include <map>
#include <set>
using namespace std;

static map<int,connection> connections;
static set<int> listeners;

const map<int,connection>& comm_connections()
{
	return connections;
}

void comm_init()
{
}

void comm_shutdown()
{
}

void comm_update()
{
}

