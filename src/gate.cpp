
#include "gate.h"

#include "log.h"
#include "timestamp.h"

/*
 * index stuff
 */

static map<int, int> g_index;
static map<int, gate> gates;
static set<int> listeners;


map<int, int>& gate_index() {return g_index;}
map<int, gate>& gate_gates() {return gates;}
set<int>& gate_listeners() {return listeners;}

void gate::index()
{
	g_index[fd]=id;
}

void gate::deindex()
{
	g_index.erase(fd);
}

#define max_gates 1024 //TODO replace with config var

static int gate_alloc()
{
	int i;
	map<int,gate>::iterator ci;
	i=0;
	ci=gates.begin();
	while( (i<max_gates) && (ci!=gates.end())) {
		if(ci->first == i) {
			++ci; ++i;
		} else if (i<ci->first) goto do_alloc;
		else {
			Log_fatal("corrupted gate list at Gid %d",ci->first);
			++ci;
		}
	}
	if(i==max_gates)
		return -1;
do_alloc:
	gates.insert(pair<int,gate> (i,gate(i)));

	return i;
}

static void gate_delete(int id)
{
	//TODO uncomment route_set_dirty();
	map<int,gate>::iterator i = gates.find(id);
	if (i==gates.end()) return;
	i->second.unset_fd();
	gates.erase(i);
}

gate::gate(int ID)
{
	id=ID;
	fd=-1;
	last_activity=timestamp();
}

gate::gate()
{
	Log_fatal("gate at %p instantiated without ID",this);
	Log_fatal("...this should never happen. Expect failure.");
	fd=-1; //at least kill it asap.
	
#ifdef CVPN_SEGV_ON_HARD_FAULT
	Log_fatal ("in fact, doing a segfault now is nothing bad. weeee!");
	* ( (int*) 0) = 0xDEAD;
#endif
}

/*
 * gate internals
 */

void gate::periodic_update()
{
	//TODO check activity
}

void gate::reset()
{
	//TODO delete poll stuff
	unset_fd();
}

void gate::poll_read()
{

}

void gate::poll_write()
{

}

/*
 * listener stuff
 */

static void poll_gate_listener() {
}

static int start_listeners() {
	return 0;
}

static void stop_listeners() {
}

/*
 * global stuff
 */

int gate_periodic_update() {
	return 0;
}

int gate_init() {
	return 0;
}

void gate_shutdown() {
	
}

