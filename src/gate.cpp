
#include "gate.h"

#include "log.h"
#include "poll.h"
#include "network.h"
#include "timestamp.h"

/*
 * index stuff
 */

static map<int, int> g_index;
static map<int, gate> gates;
static set<int> listeners;


map<int, int>& gate_index()
{
	return g_index;
}
map<int, gate>& gate_gates()
{
	return gates;
}
set<int>& gate_listeners()
{
	return listeners;
}

void gate::index()
{
	g_index[fd] = id;
}

void gate::deindex()
{
	g_index.erase (fd);
}

#define max_gates 1024 //TODO replace with config var

static int gate_alloc()
{
	int i;
	map<int, gate>::iterator ci;
	i = 0;
	ci = gates.begin();
	while ( (i < max_gates) && (ci != gates.end() ) ) {
		if (ci->first == i) {
			++ci;
			++i;
		} else if (i < ci->first) goto do_alloc;
		else {
			Log_fatal ("corrupted gate list at Gid %d", ci->first);
			++ci;
		}
	}
	if (i == max_gates)
		return -1;
do_alloc:
	gates.insert (pair<int, gate> (i, gate (i) ) );

	return i;
}

static void gate_delete (int id)
{
	//TODO uncomment route_set_dirty();
	map<int, gate>::iterator i = gates.find (id);
	if (i == gates.end() ) return;
	i->second.unset_fd();
	gates.erase (i);
}

gate::gate (int ID)
{
	id = ID;
	fd = -1;
}

gate::gate()
{
	Log_fatal ("gate at %p instantiated without ID", this);
	Log_fatal ("...this should never happen. Expect failure.");
	fd = -1; //at least kill it asap.

#ifdef CVPN_SEGV_ON_HARD_FAULT
	Log_fatal ("in fact, doing a segfault now is nothing bad. weeee!");
	* ( (int*) 0) = 0xDEAD;
#endif
}

/*
 * gate internals
 */

#define gate_timeout 60000000

void gate::periodic_update()
{

}

void gate::start()
{
	poll_set_add_read (fd);
}

void gate::reset()
{
	//TODO delete poll stuff
	if (fd < 0) return;
	close (fd);
	unset_fd();
}

int gate::try_read()
{

}

int gate::try_write()
{

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

void poll_gate_listener (int fd)
{
	if (listeners.find (fd) == listeners.end() ) return;

	int r = accept (fd, 0, 0);
	if (r < 0)
		if (errno == EAGAIN) return;
		else Log_warn ("gate accept(%d) failed with %d (%s)",
			               fd, errno, strerror (errno) );
	else {
		sockoptions_set (fd);
		if (!sock_nonblock (fd) ) {
			Log_error ("cannot set gate socket %d to nonblocking mode", fd);
			close (fd);
			return;
		}
		int i = gate_alloc();
		if (i < 0) {
			Log_error ("too many gates already open");
			close (fd);
			return;
		}

		gate&g = gates[i];
		g.set_fd (fd);
		g.last_activity = timestamp();
		g.start();
	}
}

static int start_listeners()
{
	return 0;
}

static void stop_listeners()
{
}

/*
 * global stuff
 */

int gate_periodic_update()
{
	return 0;
}

int gate_init()
{
	return 0;
}

void gate_shutdown()
{

}

