
#include "gate.h"

#include "log.h"
#include "conf.h"
#include "poll.h"
#include "route.h"
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
	route_set_dirty();
	map<int, gate>::iterator i = gates.find (id);
	if (i == gates.end() ) return;
	close (i->second.fd);
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

//packet header numbers
#define pt_keepalive 1
#define pt_route 2
#define pt_packet 3

#define p_head_size 3

pbuffer& gate::new_send()
{
	send_q.push_back (pbuffer() );
	return send_q.back();
}

bool gate::parse_packet_header()
{
	if (recv_q.len() < p_head_size) return false;
	recv_q.pop<uint8_t> (cached_header_type);
	recv_q.pop<uint16_t> (cached_header_size);
	cached_header_size = ntohs (cached_header_size);
	return true;
}

void gate::add_packet_header (pbuffer&b, uint8_t type, uint16_t size)
{
	b.b.reserve (p_head_size);
	b.push<uint8_t> (type);
	b.push<uint16_t> (htons (size) );
}

void gate::handle_keepalive()
{
	last_activity = timestamp();
}

void gate::handle_route (uint16_t size, const uint8_t*data)
{

	uint16_t asize;
	uint32_t inst;

	local.clear();
	route_set_dirty();

try_more:
	if (!size) return;

	if (size < 6) goto error;

	asize = ntohs (* (uint16_t*) data);
	inst = ntohl (* (uint32_t*) (data + 2) );
	if (asize + 6 > size) goto error;

	local.push_back (address() );
	local.back().set (inst, data + 6, asize);
	data += 6 + asize;
	size -= 6 + asize;
	goto try_more;

error:
	Log_error ("invalid route packet received from gate %d", id);
	reset();
}

void gate::handle_packet (uint16_t size, const uint8_t*data)
{
	uint32_t inst;
	uint16_t dof, ds, sof, ss, s;

	if (size < 14) goto error;

	inst = ntohl (* (uint32_t*) data);

#define h ((uint16_t*)data)
	dof = ntohs (h[2]);
	ds = ntohs (h[3]);
	sof = ntohs (h[4]);
	ss = ntohs (h[5]);
	s = ntohs (h[6]);
#undef h

	//beware of overflows
	if ( (int) s + 14 > (int) size) goto error;
	if ( (int) sof + (int) ss + 14 > (int) size) goto error;
	if ( (int) dof + (int) ds + 14 > (int) size) goto error;

	route_packet (inst, dof, ds, sof, ss, s, data + 14, - (id + 1) );

	return;
error:
	Log_error ("invalid data packet received from gate %d", id);
	reset();
}

void gate::send_keepalive()
{
	if (!can_send() ) return;
	pbuffer& p = new_send();
	add_packet_header (p, pt_keepalive, 0);
}

void gate::send_packet (uint32_t inst,
                        uint16_t doff, uint16_t ds,
                        uint16_t soff, uint16_t ss,
                        uint16_t size, const uint8_t*data)
{

	if (!can_send() ) return;
	pbuffer&p = new_send();
	add_packet_header (p, pt_packet, size + 14);
	p.b.reserve (size + 14);
	p.push<uint32_t> (htonl (inst) );
	p.push<uint16_t> (htons (doff) );
	p.push<uint16_t> (htons (ds) );
	p.push<uint16_t> (htons (soff) );
	p.push<uint16_t> (htons (ss) );
	p.push<uint16_t> (htons (size) );
	p.push (data, size);
}

void gate::try_parse_input()
{
try_more:
	if (fd < 0) return;

	if (!cached_header_type)
		if (!parse_packet_header() ) return;

	switch (cached_header_type) {
	case pt_keepalive:
		handle_keepalive();
		cached_header_type = 0;
		goto try_more;
	case pt_route:
	case pt_packet:
		if (recv_q.len() < cached_header_size) break;

		if (cached_header_type == pt_route)
			handle_route (cached_header_size, recv_q.begin() );
		else	handle_packet (cached_header_size, recv_q.begin() );

		recv_q.read (cached_header_size);
		cached_header_type = 0;
		goto try_more;
	default:
		Log_error ("invalid packet header received. disconnecting.");
		reset();
	}

}

/*
 * gate internals
 */

#define gate_timeout 60000000

void gate::periodic_update()
{
	if (timestamp() - last_activity > 10000000) //ping every 10 seconds
		if (fd >= 0) send_keepalive();
	if (timestamp() - last_activity > gate_timeout ) {
		Log_error ("gate %d timeout", id);
		reset();
	}
}

void gate::start()
{
	poll_set_add_read (fd);
}

void gate::reset()
{
	send_q.clear();
	recv_q.clear();
	local.clear();
	route_set_dirty();
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
		if (recv_q.len() > gate_max_recv_q_len) {
			Log_error ("gate %d receive queue overflow", id);
			reset();
			return;
		}

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

void gate_listener_poll (int fd)
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
	list<int>to_delete;
	map<int, gate>::iterator i;

	for (i = gates.begin();i != gates.end();++i) {
		i->second.periodic_update();
		if (i->second.fd < 0)
			to_delete.push_back (i->first);
	}

	while (to_delete.size() ) {
		gate_delete (to_delete.front() );
		to_delete.pop_front();
	}

	return 0;
}

int gate_init()
{
	if (start_listeners() ) {
		Log_error ("couldn't start gate listeners");
		return 1;
	}

	Log_info ("gate OK");
	return 0;
}

void gate_shutdown()
{
	while (gates.size() )
		gate_delete (gates.begin()->first);
}

