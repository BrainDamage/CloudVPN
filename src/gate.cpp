
#include "gate.h"

#include "log.h"
#include "conf.h"
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
	Log_fatal ("quiz: only thing that can help now is a s-----t");
	* ( (int*) 0) = 0x1337;
#endif
}

/*
 * gate i/o
 */

void gate::try_parse_input()
{

}

/*
 * gate internals
 */

#define gate_timeout 60000000

void gate::periodic_update()
{
	//TODO
}

void gate::start()
{
	poll_set_add_read (fd);
}

void gate::reset()
{
	if (fd < 0) return;
	poll_set_remove_read (fd);
	close (fd);
	unset_fd();
}

void gate::poll_read()
{
	int r;
	uint8_t*buf;
	while (1) {
		buf = recv_q.get_buffer (4096);
		if (!buf) {
			Log_error ("cannot allocate enough buffer space for gate %d", id);
			reset();
			return;
		}

		r = recv (fd, buf, 4096, 0);
		if (!r) {
			Log_info ("gate %d closed by peer", id);
			reset();
			return;
		} else if (r < 0) {
			if (errno != EAGAIN) {
				Log_warn ("gate %d read error");
				reset();
			}
			return;
		} else {
			recv_q.append (r);
			try_parse_input();
		}
	}
}

void gate::poll_write()
{
	int r, n;
	const uint8_t* buf;
	while (send_q.size() ) {
		buf = send_q.front().b.begin().base();
		n = send_q.front().b.size();

		r = 0;
		if (n > 0)	r = send (fd, buf, n, 0);

		if (r == 0) {
			send_q.pop_front();
			continue;
		}

		if (r < 0) {
			if (errno != EAGAIN) {
				Log_info ("gate %d write error", id);
				reset();
			} else poll_set_add_write (fd);
			return;
		}

		if (n == r) {
			send_q.pop_front();
			continue;
		}

		if (n < r) {
			Log_error ("something strange at %d with send(%d)",
			           id, fd);
			return;
		}

		send_q.front().shift (r);
		//TODO, consider breaking the loop here
	}

	poll_set_remove_write (fd);
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
	list<string> l;
	list<string>::iterator i;
	int s;

	config_get_list ("gate", l);

	if (!l.size() ) {
		Log_info ("no gates specified");
		return 0;
	}

	for (i = l.begin();i != l.end();++i) {
		Log_info ("creating gate on `%s'", i->c_str() );
		s = tcp_listen_socket (i->c_str() );
		if (s >= 0) {
			listeners.insert (s);
			poll_set_add_read (s);
		} else return 1;
	}

	Log_info ("gates ready");

	return 0;
}

static void stop_listeners()
{
	set<int>::iterator i;

	Log_info ("Closing gates", *i);

	for (i = listeners.begin();i != listeners.end();++i)
		tcp_close_socket (*i);

	listeners.clear();
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

