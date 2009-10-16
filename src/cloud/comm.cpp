
/*
 * CloudVPN
 *
 * This program is a free software: You can redistribute and/or modify it
 * under the terms of GNU GPLv3 license, or any later version of the license.
 * The program is distributed in a good hope it will be useful, but without
 * any warranty - see the aforementioned license for more details.
 * You should have received a copy of the license along with this program;
 * if not, see <http://www.gnu.org/licenses/>.
 */

#include "comm.h"

#include "conf.h"
#define LOGNAME "cloud/comm"
#include "log.h"
#include "poll.h"
#include "route.h"
#include "timestamp.h"
#include "sq.h"
#include "network.h"

#include <gnutls/gnutls.h>
#include <gcrypt.h>

#include <string.h>

#include <list>
using namespace std;

static map<int, int> conn_index; //indexes socket FD to connection ID
static map<int, connection> connections;  //indexes connection ID to real object
static set<int> listeners; //set of listening FDs

/*
 * functions that return references to static members, so others can access
 * the wonders.
 */

map<int, int>&comm_connection_index()
{
	return conn_index;
}

map<int, connection>& comm_connections()
{
	return connections;
}

set<int>& comm_listeners()
{
	return listeners;
}

/*
 * global SSL stuff
 */

static gnutls_certificate_credentials_t xcred;
static gnutls_dh_params_t dh_params;
static gnutls_priority_t prio_cache;

/*
 * GnuTLS initialization
 *
 * What is loaded:
 * - key+cert
 * - DH params
 * - Some number of CA's. If there's no CA specified, there's no checking.
 * - Some number of CRL's.
 */

void ssl_logger (int level, const char*msg)
{
	Log_info ("gnutls (%d): %s", level, msg);
}

#include <stdio.h>

static int ssl_initialize()
{
	string keypath, certpath, t;

	Log_info ("Initializing ssl layer");

	if ( (!config_get ("key", keypath) ) ||
	        (!config_get ("cert", certpath) ) ) {
		Log_fatal ("you must correctly specify key and cert options");
		return 1;
	}

	//start gnutls
	if (gnutls_global_init() ) {
		Log_error ("gnutls_global_init failed");
		return 2;
	}

	gnutls_global_set_log_function (ssl_logger);
	{
		int i;
		gnutls_global_set_log_level (config_get_int ("tls_loglevel", i) ? i : 0);
	}

	gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);

	if (gnutls_certificate_allocate_credentials (&xcred) ) {
		Log_error ("cant allocate credentials");
		return 3;
	}

	//load the keys
	if (gnutls_certificate_set_x509_key_file
	        (xcred, certpath.c_str(), keypath.c_str(), GNUTLS_X509_FMT_PEM) ) {
		Log_error ("loading keypair failed");
		return 4;
	}

	//load DH params, or generate some.
	gnutls_dh_params_init (&dh_params);

	if (config_get ("dh", t) ) {
		FILE*f;
		long s;
		vector<uint8_t>buffer;

		f = fopen (t.c_str(), "r");
		if (!f) {
			Log_error ("can't open DH params file");
			return 5;
		}

		fseek (f, 0, SEEK_END);
		s = ftell (f);
		fseek (f, 0, SEEK_SET);
		if ( (s <= 0) || s > 65536) { //prevent too large files.
			Log_error ("DH params file empty or too big");
			fclose (f);
			return 6;
		}

		buffer.resize (s, 0);
		if (fread (buffer.begin().base(), s, 1, f) != 1) {
			Log_error ("bad DH param read");
			fclose (f);
			return 7;
		}
		fclose (f);

		gnutls_datum_t data = {buffer.begin().base(), s};

		if (gnutls_dh_params_import_pkcs3
		        (dh_params, &data, GNUTLS_X509_FMT_PEM) ) {
			Log_error ("DH params importing failed");
			return 8;
		}

	} else {
		gnutls_dh_params_generate2 (dh_params, 1024);
	}

	gnutls_certificate_set_dh_params (xcred, dh_params);

	//load CAs and CRLs
	list<string> l;
	list<string>::iterator il;

	config_get_list ("ca", l);
	for (il = l.begin();il != l.end();++il) {
		int t = gnutls_certificate_set_x509_trust_file
		        (xcred, il->c_str(), GNUTLS_X509_FMT_PEM);
		if (t < 0) Log_info ("loading CAs from file %s failed",
			                     il->c_str() );
		else Log_info ("loaded %d CAs from %s",
			               t, il->c_str() );
	}

	config_get_list ("crl", l);
	for (il = l.begin();il != l.end();++il) {
		int t = gnutls_certificate_set_x509_crl_file
		        (xcred, il->c_str(), GNUTLS_X509_FMT_PEM);
		if (t < 0) Log_info ("loading CRLs from file %s failed",
			                     il->c_str() );
		else Log_info ("loaded %d CRLs from %s",
			               t, il->c_str() );
	}

	gnutls_certificate_set_verify_limits (xcred, 32768, 8);

	if (gnutls_priority_init (&prio_cache,
	                          config_get ("tls_prio_str", t) ?
	                          t.c_str() : "NORMAL", NULL) ) {
		Log_error ("gnutls priority initialization failed");
		return 8;
	}

	Log_info ("SSL initialized OK");
	return 0;
}

static int ssl_destroy()
{
	Log_info ("destroying SSL layer");
	gnutls_certificate_free_credentials (xcred);
	gnutls_priority_deinit (prio_cache);
	gnutls_dh_params_deinit (dh_params);
	gnutls_global_deinit();
	return 0;
}

/*
 * connection management (allocates/destroys the objects on ID->conn map)
 */

static int max_connections = 1024;

/*
 * connections are allocated in range [0..max_connections)
 *
 * returns -1 on fail.
 *
 * Too bad it has O(n_connections) time, but what can we do.
 */

static int connection_alloc()
{
	int i;
	map<int, connection>::iterator ci;

	i = 0;
	ci = connections.begin();
	while ( (i < max_connections) && (ci != connections.end() ) ) {
		if (ci->first == i) {
			++ci;
			++i;
		} else if (i < ci->first) {
			goto do_alloc;
		} else { //if i>ci->first, which should never happen.
			Log_warn ("some corruption in the connection list at Cid %d", ci->first);
			++ci;
		}
	}
	if (i == max_connections)
		return -1;

//add at tail
do_alloc:
	connections.insert (pair<int, connection> (i, connection (i) ) );
	return i;
}

void connection_delete (int id)
{
	route_set_dirty();

	map<int, connection>::iterator i = connections.find (id);
	if (i == connections.end() ) return;
	i->second.unset_fd();
	connections.erase (i);
}

/*
 * This should accept a connection, and link it into the structure.
 * Generally, only following 2 functions really create connections:
 */

static int try_accept_connection (int sock)
{
	sockaddr_type addr;
	socklen_t addrsize = sizeof (sockaddr_type);
	int s = accept (sock, & (addr.sa), &addrsize);
	if (s < 0) {
		if ( (errno == EWOULDBLOCK) || (!errno) ) return 0;
		Log_error ("accept(%d) failed with %d: %s",
		           sock, errno, strerror (errno) );
		return 1;
	}

	sockoptions_set (s);

	string peer_addr_str = sockaddr_to_str (& (addr.sa) );
	Log_info ("get connection from address %s on socket %d",
	          peer_addr_str.c_str(), s);

	if (!sock_nonblock (s) ) {
		Log_error ("could not put accepted socket %d in nonblocking mode", s);
		close (s);
		return 2;
	}

	int cid = connection_alloc();
	if (cid < 0) {
		Log_info ("connection limit %d hit, closing %d",
		          max_connections, s);
		return 0;
	}

	connection&c = connections[cid];

	c.set_fd (s);
	c.state = cs_accepting;
	c.peer_addr_str = peer_addr_str;
	c.peer_connected_since = timestamp();

	c.start_accept(); //bump the thing

	return 0;
}

static int connect_connection (const string&addr)
{
	int cid = connection_alloc();
	if (cid < 0) {
		Log_warn ("connection limit %d hit, will NOT connect to `%s'",
		          max_connections, addr.c_str() );
		Log_info ("consider increasing the limit");
		return 1;
	}

	Log_info ("connection %d created for connecting to %s",
	          cid, addr.c_str() );

	connection&c = connections[cid];

	c.state = cs_retry_timeout;
	c.last_retry = 0;
	c.connect_address = addr;

	return 0;
}

/*
 * class connection stuff
 */

int connection::timeout = 15000000; //15 sec
int connection::keepalive = 5000000; //5 sec
int connection::retry = 10000000; //10 sec

/*
 * this is needed to keep proper fd->id translation, used by
 * set_fd() and unset_fd()
 */

void connection::index()
{
	conn_index[fd] = id;
}

void connection::deindex()
{
	conn_index.erase (fd);
}

/*
 * PROTOCOL
 * for more protocol information please consider readme
 */

//packet header numbers
#define pt_route_set 1
#define pt_route_diff 2
#define pt_packet 3
#define pt_echo_request 4
#define pt_echo_reply 5
#define pt_route_request 6

//sizes
#define p_head_size 4

static void add_packet_header (pusher&b, uint8_t type,
                               uint8_t special, uint16_t size)
{
	b.push<uint8_t> (type);
	b.push<uint8_t> (special);
	b.push<uint16_t> (htons (size) );
}

static bool parse_packet_header (squeue&q, uint8_t&type,
                                 uint8_t&special, uint16_t&size)
{
	if (q.len() < p_head_size) return false;
	uint8_t t;
	q.pop<uint8_t> (t);
	type = t;
	q.pop<uint8_t> (t);
	special = t;
	uint16_t t2 = 0;
	q.pop<uint16_t> (t2);
	size = ntohs (t2);
	return true;
}

/*
 * handlers of incoming information
 */

void connection::handle_packet (uint8_t*buf, int len)
{
	if (dbl_enabled) {
		if (dbl_over > (unsigned int) dbl_burst) return;
		dbl_over += len + 4;
	}

	uint16_t dof, ds, sof, ss, s, ttl;
	uint32_t inst, ID;

	if (len < 20) goto error;

	ID = ntohl (* (uint32_t*) buf);
	ttl = ntohs (* (uint16_t*) (buf + 4) );
	inst = ntohl (* (uint32_t*) (buf + 6) );
	dof = ntohs (* (uint16_t*) (buf + 10) );
	ds = ntohs (* (uint16_t*) (buf + 12) );
	sof = ntohs (* (uint16_t*) (buf + 14) );
	ss = ntohs (* (uint16_t*) (buf + 16) );
	s = ntohs (* (uint16_t*) (buf + 18) );

	if ( (len < 20 + (int) s)
	        || (s < (int) dof + (int) ds)
	        || (s < (int) sof + (int) ss) )
		goto error;

	stat_packet (true, len + p_head_size);
	route_packet (ID, ttl, inst, dof, ds, sof, ss, s, buf + 20, id);
	return;
error:
	Log_info ("connection %d broadcast read corruption", id);
	reset();
}

void connection::handle_route (bool set, uint8_t*data, int n)
{
	stat_packet (true, n + p_head_size);
	if (set) remote_routes.clear();
	route_set_dirty();

	uint32_t remote_ping;
	uint32_t remote_dist;
	uint32_t instance;
	uint16_t s;

	while (n > 0) {
		if (n < 14) goto error;
		remote_ping = ntohl (* (uint32_t*) data);
		remote_dist = ntohl (* (uint32_t*) (data + 4) );
		instance = ntohl (* (uint32_t*) (data + 8) );
		s = ntohs (* (uint16_t*) (data + 12) );
		if (n < 14 + (int) s) goto error;

		if (remote_ping) remote_routes
			[address (instance,data+14,s) ] =
			    remote_route (remote_ping, remote_dist);
		else remote_routes.erase (address (instance, data + 14, s) );
		n -= 14 + s;
		data += 14 + s;
	}

	handle_route_overflow();
	return;
error:
	Log_info ("connection %d route read corruption", id);
	reset();
}

void connection::handle_ping (uint8_t ID)
{
	stat_packet (true, p_head_size);
	write_pong (ID);
}

void connection::handle_pong (uint8_t ID)
{
	stat_packet (true, p_head_size);
	last_ping = timestamp();
	if (ID != sent_ping_id) {
		Log_info ("connection %d received some very old ping", id);
		return;
	}
	ping = 2 + timestamp() - sent_ping_time;
	route_set_dirty();
}

void connection::handle_route_request ()
{
	stat_packet (true, p_head_size);
	route_report_to_connection (*this);
}

/*
 * senders
 */

void connection::write_packet (uint32_t id, uint16_t ttl,
                               uint32_t inst,
                               uint16_t dof, uint16_t ds,
                               uint16_t sof, uint16_t ss,
                               uint16_t s, const uint8_t*buf)
{
	size_t size = p_head_size + 20 + s;

	if (!can_write_data (size) ) try_write();
	if (!can_write_data (size) ) return;

	if (s > mtu) return;

	pusher b (send_q.get_buffer (size) );
	if (!b.d) return;
	send_q.append (size);

	add_packet_header (b, pt_packet, 0, 20 + s);
	b.push<uint32_t> (htonl (id) );
	b.push<uint16_t> (htons (ttl) );
	b.push<uint32_t> (htonl (inst) );
	b.push<uint16_t> (htons (dof) );
	b.push<uint16_t> (htons (ds) );
	b.push<uint16_t> (htons (sof) );
	b.push<uint16_t> (htons (ss) );
	b.push<uint16_t> (htons (s) );
	b.push ( (uint8_t*) buf, s);
	stat_packet (false, size);
}

void connection::write_route_set (uint8_t*data, int n)
{
	size_t size = p_head_size + n;

	pusher b (send_q.get_buffer (size) );
	if (!b.d) return;
	send_q.append (size);

	add_packet_header (b, pt_route_set, 0, n);
	b.push (data, n);
	stat_packet (false, size);
}

void connection::write_route_diff (uint8_t*data, int n)
{
	size_t size = p_head_size + n;

	pusher b (send_q.get_buffer (size) );
	if (!b.d) return;
	send_q.append (size);

	add_packet_header (b, pt_route_diff, 0, n);
	b.push (data, n);
	stat_packet (false, size);
}

void connection::write_ping (uint8_t ID)
{
	size_t size = p_head_size;

	pusher b (send_q.get_buffer (size) );
	if (!b.d) return;
	send_q.append (size);

	add_packet_header (b, pt_echo_request, ID, 0);
	stat_packet (false, size);
}

void connection::write_pong (uint8_t ID)
{
	size_t size = p_head_size;

	pusher b (send_q.get_buffer (size) );
	if (!b.d) return;
	send_q.append (size);

	add_packet_header (b, pt_echo_reply, ID, 0);
	stat_packet (false, size);
}

void connection::write_route_request ()
{
	size_t size = p_head_size;

	pusher b (send_q.get_buffer (size) );
	if (!b.d) return;
	send_q.append (size);

	add_packet_header (b, pt_route_request, 0, 0);
	stat_packet (false, size);
}

/*
 * try_parse_input examines the content of the incoming queue, and
 * calls appropriate handlers, if some packet is found.
 */

void connection::try_parse_input()
{
	while (true) {
		if (state != cs_active) return; //safety.

		if (cached_header.type == 0)
			if (!parse_packet_header (recv_q,
			                          cached_header.type,
			                          cached_header.special,
			                          cached_header.size) ) return;

		switch (cached_header.type) {
		case pt_route_set:
		case pt_route_diff:
		case pt_packet:
			if (recv_q.len() < (unsigned int)
			        cached_header.size) return;
			switch (cached_header.type) {
			case pt_route_set:
				handle_route (true, recv_q.begin(),
				              cached_header.size);
				break;
			case pt_route_diff:
				handle_route (false, recv_q.begin(),
				              cached_header.size);
				break;
			case pt_packet:
				handle_packet (recv_q.begin(),
				               cached_header.size);
				break;
			}
			recv_q.read (cached_header.size);
			cached_header.type = 0;
			break;

		case pt_echo_request:
			handle_ping (cached_header.special);
			cached_header.type = 0;
			break;

		case pt_echo_reply:
			handle_pong (cached_header.special);
			cached_header.type = 0;
			break;

		case pt_route_request:
			handle_route_request ();
			cached_header.type = 0;
			break;

		default:
			Log_error ("invalid packet header received. disconnecting.");
			disconnect();
			return;
		}
	}
}

/*
 * read/write operations
 */

bool connection::try_read()
{
	//TODO examine whether this is needed. I guess not, but who knows.
	//if (pending_write == 1) return true;

	int r;
	uint8_t*buf;
	while (1) {
		buf = recv_q.get_buffer (4096); //alloc a buffer

		if (!buf) {
			Log_error ("cannot allocate enough buffer space for connection %d", id);
			disconnect();
			return false;
		}

		r = gnutls_record_recv (session, buf, 4096);
		if (r == 0) {
			Log_info ("connection id %d closed by peer", id);
			reset();
			return false;
		} else if (r < 0) {
			if (handle_ssl_error (r) ) {
				Log_info ("connection id %d read error", id);
				reset();
				return false;
			}
			return true;
		} else {
			recv_q.append (r); //confirm read
			try_parse_input();
			if (fd < 0) return false; //we got reset
		}
	}
	return true;
}

bool connection::try_write()
{
	int r, n;

	while (needs_write() ) {

		//choke the bandwidth. Note that we dont want to really
		//discard the packet here, because of SSL.

		n = send_q.len();
		if (ubl_enabled && ( (unsigned int) n > ubl_available)
		        && (n > ubl_available) ) n = ubl_available;

		if (!n) return true; //we ran out of available bandwidth

		//or try to send.

		r = pending_write ?
		    gnutls_record_send (session, send_q.begin(), pending_write) :
		    gnutls_record_send (session, send_q.begin(), n);

		if (r == 0) {
			Log_info ("connection id %d closed by peer", id);
			reset();
			return false;
		} else if (r < 0) {
			if (handle_ssl_error (r) ) {
				Log_error ("connection id %d write error", id);
				reset();
				return false;
			}
			pending_write = n;
			return true;
		} else {
			send_q.read (r);
			pending_write = 0;
		}
	}
	poll_set_remove_write (fd); //don't need any more write
	pending_write = 0;
	return true;
}

void connection::try_data()
{
	/*
	 * try_data is just combined try_read+try_write, used for polling,
	 * because when using SSL we can't really know what to expect.
	 *
	 * try write should be always called first,
	 * because it usually resets the write poll flag, which
	 * should then be restored by try_read.
	 *
	 * Also, no more operations if try_write was forced to reset a conn.
	 */

	if (pending_write) {
		if (try_write() ) try_read();
	} else try_read();
}

/*
 * actions
 * basically these functions are called by poll for some time, then they change
 * connection state so other of these can be called
 */

void connection::try_accept()
{
	int r = gnutls_handshake (session);
	if (r == 0) {
		Log_info ("socket %d accepted SSL connection id %d", fd, id);
		activate();

	} else if (handle_ssl_error (r) ) {
		Log_error ("accepting fd %d lost", fd);
		reset();
	} else if ( (timestamp() - last_ping) > (unsigned int) timeout) {
		Log_error ("accepting fd %d timeout", fd);
		reset();
		return;
	}
}

void connection::try_connect()
{
	//test if the socket is writeable, otherwise still in progress
	if (!tcp_socket_writeable (fd) ) {
		if ( (timestamp() - last_ping) > (unsigned int) timeout) {
			Log_error ("timeout connecting %d", fd);
			reset();
			return;
		} else return;
	}

	int e = sock_get_error (fd);

	if (e < 0) {
		Log_error ("connecting %d failed with errno %d: %s",
		           id, -e, strerror (errno) );
		reset();
		return;
	}

	if (e > 0) {
		if ( (timestamp() - last_ping) > (unsigned int) timeout) {
			Log_error ("timeout connecting %d", fd);
			reset();
			return;
		} else return;
	}

	//print a nice info about who are we connected to
	sockaddr_type addr;
	socklen_t s = sizeof (sockaddr_type);
	if (getpeername (fd, & (addr.sa), &s) )
		Log_info ("conn %d connected to unknown peer", id);
	else {
		peer_addr_str = sockaddr_to_str (& (addr.sa) );
		Log_info ("conn %d connected to address %s",
		          id, peer_addr_str.c_str() );
	}

	peer_connected_since = timestamp();

	poll_set_remove_write (fd);
	poll_set_add_read (fd); //always needed
	state = cs_ssl_connecting;
	if (alloc_ssl (false) ) {
		Log_error ("conn %d failed to allocate SSL stuff", id);
		reset();
	} else try_ssl_connect();
}

void connection::try_ssl_connect()
{
	int r = gnutls_handshake (session);
	if (r == 0) {
		Log_info ("socket %d established SSL connection id %d", fd, id);
		activate();

	} else if (handle_ssl_error (r) ) {
		Log_error ("SSL connecting on %d failed", fd);
		reset();
	} else if ( (timestamp() - last_ping) > (unsigned int) timeout) {
		Log_error ("SSL connecting fd %d timeout", fd);
		reset();
		return;
	}
}

void connection::try_close()
{
	if (!session) {
		reset(); //someone already terminated it.
		return;
	}

	int r = gnutls_bye (session, GNUTLS_SHUT_RDWR);
	if (r == 0) reset(); //closed OK
	else if (handle_ssl_error (r) ) reset ();
	else if ( (timestamp() - last_ping) > (unsigned int) timeout) {
		Log_warn ("%d timeouted disconnecting SSL", fd);
		reset();
	}
}

/*
 * forced state changes - use these functions to manually connect/disconnect
 * or trigger some actions.
 */

void connection::start_connect()
{
	last_retry = timestamp();

	int t = tcp_connect_socket (connect_address.c_str() );
	if (t < 0) {
		Log_error ("failed connecting in connection id %d", id);
		return;
	}

	set_fd (t);

	state = cs_connecting;
	last_ping = timestamp();
	poll_set_add_write (fd); //wait for connect() to be done
	try_connect();
}

void connection::start_accept()
{
	if (alloc_ssl (true) ) {
		Log_error ("failed to allocate SSL stuff for connection %d", id);
		reset();
		return;
	}

	last_ping = timestamp(); //abuse the variable...

	poll_set_add_read (fd); //always needed
	try_accept();
}

void connection::send_ping()
{
	sent_ping_time = timestamp();
	sent_ping_id += 1;
	write_ping (sent_ping_id);
}

void connection::activate()
{
	state = cs_active;
	route_report_to_connection (*this);
	send_ping();
}

void connection::disconnect()
{
	poll_set_remove_write (fd);
	poll_set_remove_read (fd);

	if ( (state == cs_retry_timeout) && (! (connect_address.length() ) ) ) {
		state = cs_inactive;
		return;
	}

	if ( (state == cs_inactive)
	        || (state == cs_retry_timeout)
	        || (state == cs_closing) ) return;

	last_ping = timestamp();
	state = cs_closing;
	remote_routes.clear();
	route_set_dirty();
	try_close();
}

/*
 * reset() clears the connection before destruction/new usage
 */

void connection::reset()
{
	poll_set_remove_write (fd);
	poll_set_remove_read (fd);

	remote_routes.clear();
	route_overflow = false;
	route_set_dirty();

	recv_q.clear();
	send_q.clear();

	pending_write = 0;

	cached_header.type = 0;

	dealloc_ssl();

	ping = timeout;
	last_ping = 0;

	tcp_close_socket (fd);
	unset_fd();

	stats_clear();
	ubl_available = 0;
	dbl_over = 0;

	peer_addr_str = "";
	peer_connected_since = 0;
	if (connect_address.length() )
		state = cs_retry_timeout;
	else state = cs_inactive;
}

/*
 * helper for efficient error handling. When read/write is needed, triggers
 * appropriate poll state.
 */

int connection::handle_ssl_error (int ret)
{
	if (gnutls_error_is_fatal (ret) ) {
		Log_error ("fatal ssl error %d (%s) on connection %d",
		           ret, gnutls_strerror (ret), id);
		return 1;
	}

	switch (ret) {
	case GNUTLS_E_AGAIN:
	case GNUTLS_E_INTERRUPTED:
		if (gnutls_record_get_direction (session) )
			poll_set_add_write (fd);
		else poll_set_remove_write (fd);
		break;
	default:
		Log_warn ("non-fatal ssl error %d (%s) on connection %d",
		          ret, gnutls_strerror (ret), id);
	}

	return 0;
}

/*
 * polling
 */

void connection::poll_simple()
{
	switch (state) {
	case cs_accepting:
		try_accept();
		break;
	case cs_connecting:
		try_connect();
		break;
	case cs_ssl_connecting:
		try_ssl_connect();
		break;
	case cs_closing:
		try_close();
		break;
	case cs_active:
		try_data();
		break;
	default:
		Log_warn ("unexpected poll to connection id %d", id);
	}
}

void connection::poll_read()
{
	poll_simple();
}

void connection::poll_write()
{
	poll_simple();
}

void connection::periodic_update()
{
	stats_update();

	switch (state) {
	case cs_connecting:
		try_connect();
		break;
	case cs_ssl_connecting:
		try_ssl_connect();
		break;
	case cs_closing:
		try_close();
		break;
	case cs_retry_timeout:
		if ( (timestamp() - last_retry) > (unsigned int) retry)
			start_connect();
		break;
	case cs_active:
		if ( (timestamp() - last_ping) > (unsigned int) timeout) {
			Log_info ("Connection %d ping timeout", id);
			disconnect();
			return;
		} else if ( (timestamp() - sent_ping_time) >
		            (unsigned int) keepalive) send_ping();
		try_write();
		break;
	}
}

/*
 * SSL alloc/dealloc
 * create and destroy SSL objects specific for each connection
 */

int connection::alloc_ssl (bool server)
{
	dealloc_ssl();

	if (gnutls_init (&session, server ? GNUTLS_SERVER : GNUTLS_CLIENT) )
		return 1;

	gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) fd);
	gnutls_priority_set (session, prio_cache);
	gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);
	gnutls_certificate_server_set_request (session, GNUTLS_CERT_REQUIRE);

	return 0;
}

void connection::dealloc_ssl()
{
	if (session) {
		gnutls_deinit (session);
		session = 0;
	}
}

/*
 * remote route overflow handling
 *
 * If we decide there's too many remote routes, we align the size to maximum
 * by dropping several most-distant connections, and remember the 'tainted'
 * state. After things go back to normal, we request a full set of routes.
 *
 * route information dropping algorithm strongly depends on situation, so
 * should be mostly random (so no one can get any adventage in this), only
 * depending on generic route properties, like distances.
 */

#include <algorithm>

void connection::handle_route_overflow()
{
	if (route_overflow) {
		if (remote_routes.size() <= max_remote_routes) {
			Log_info ("connection %d - overflow finishes", id);
			route_overflow = false;
			write_route_request();
		}
		return;
	}
	if (remote_routes.size() <= max_remote_routes) return;
	route_overflow = true;
	Log_info ("connection %d - route overflow", id);

	vector<address>to_del;
	vector<address>::iterator hi;
	map<address, remote_route>::iterator rri, rre;
	int max_dist, t;

	while (remote_routes.size() > max_remote_routes) {
		//select all of the largest routes
		max_dist = 0;
		to_del.clear();
		for (rri = remote_routes.begin(), rre = remote_routes.end();
		        rri != rre; ++rri) {
			if (rri->second.dist > (unsigned int) max_dist) {
				to_del.clear();
			}
			if (rri->second.dist == (unsigned int) max_dist)
				to_del.push_back (rri->first);
		}
		if (!to_del.size() ) {
			Log_error ("connection %d remote route handling fail!", id);
			return;
		}
		//now randomize the things so no one is sure
		random_shuffle (to_del.begin(), to_del.end() );
		//and delete some.
		if (to_del.size() + max_remote_routes < remote_routes.size() )
			for (hi = to_del.begin();hi < to_del.end();++hi)
				remote_routes.erase (*hi);
		else for (hi = to_del.begin(),
			          t = remote_routes.size() - max_remote_routes;
			          t > 0;--t, ++hi) remote_routes.erase (*hi);
	}
}

/*
 * not-to-be-used constructor.
 *
 * connection objects must always be created with ID; if not, warn.
 */

connection::connection()
{
	Log_fatal ("connection at %p instantiated without ID", this);
	Log_fatal ("... That should never happen. Not terminating,");
	Log_fatal ("... but expect weird behavior and/or segfault.");
	state = cs_inactive; //at least delete it asap.

	/* =TRICKY=
	 * This is mostly usuable in enterprise situations, when
	 * a simple restart is better than slow painful death.
	 */

#ifdef CVPN_SEGV_ON_HARD_FAULT
	Log_fatal ("in fact, doing a segfault now is nothing bad. weeee!");
	* ( (int*) 0) = 0xDEAD;
#endif
}

/*
 * statistics
 * speeds are updated every 5 seconds, no idea why would someone want
 * to change this interval.
 */

uint64_t connection::all_in_p_total = 0;
uint64_t connection::all_in_s_total = 0;
uint64_t connection::all_out_p_total = 0;
uint64_t connection::all_out_s_total = 0;

void connection::stat_packet (bool in, int size)
{
	if (in) {
		in_p_total += 1;
		in_p_now += 1;
		all_in_p_total += 1;
		in_s_total += size;
		in_s_now += size;
		all_in_s_total += size;
	} else {
		out_p_total += 1;
		out_p_now += 1;
		all_out_p_total += 1;
		out_s_total += size;
		out_s_now += size;
		all_out_s_total += size;
	}
}

void connection::stats_update()
{
	if (timestamp() < stat_update) return;
	stat_update = timestamp() + 5000000; //5 sec

	in_p_speed = in_p_now / 5;
	out_p_speed = out_p_now / 5;
	in_s_speed = in_s_now / 5;
	out_s_speed = out_s_now / 5;
	in_p_now = out_p_now = in_s_now = out_s_now = 0;
}

void connection::stats_clear()
{
	in_p_total = in_p_now = in_s_total = in_s_now = 0;
	out_p_total = out_p_now = out_s_total = out_s_now = 0;
	in_p_speed = in_s_speed = out_p_speed = out_s_speed = 0;
	stat_update = 0;
	peer_addr_str.clear();
	peer_connected_since = 0;
}

/*
 * bandwidth limiting
 *
 * please note that download limiting doesnt really 'limit' much, it only drops
 * incoming overlimit data packets. The actual network traffic is still there.
 */

#define minimum_granularity 10000 //full recompute threshold = 10ms.

void connection::bl_recompute()
{
	if (! (ubl_enabled || dbl_enabled) ) return;

	static uint64_t last_recompute = timestamp();
	uint64_t timediff = timestamp() - last_recompute;
	if (timediff < minimum_granularity) {
		/*
		 * only push some up-bandwidth to connectins which desperately
		 * need it. Spares much time when the connections trigger on
		 * slowly.
		 */
		map<int, connection>::iterator i, e;
		for (i = connections.begin(), e = connections.end(); i != e; ++i)
			if (i->second.needs_write() &&
			        (!i->second.ubl_available) )
				i->second.ubl_available = ubl_burst;

		return;
	}
	/*
	 * normal recompute. Guess how many connections need bandwidth,
	 * give them some, capped by maximal per-connection bandwidth.
	 */
	last_recompute = timestamp();

	map<int, connection>::iterator i, e;
	int up_bandwidth_to_add, down_bandwidth_to_add;

	up_bandwidth_to_add = down_bandwidth_to_add = 0;

	if (ubl_total || dbl_total) {

		for (i = connections.begin(), e = connections.end();
		        i != e; ++i) {
			if (i->second.needs_write() ) ++up_bandwidth_to_add;
			if (i->second.dbl_over > 0) ++down_bandwidth_to_add;
		}

		if (up_bandwidth_to_add)
			up_bandwidth_to_add = timediff * ubl_total
			                      / up_bandwidth_to_add / 1000000;
		if (ubl_conn && (up_bandwidth_to_add > ubl_conn) )
			up_bandwidth_to_add = ubl_conn;

		if (down_bandwidth_to_add)
			down_bandwidth_to_add = timediff * dbl_total
			                        / down_bandwidth_to_add / 1000000;
		if (dbl_conn && (down_bandwidth_to_add > dbl_conn) )
			down_bandwidth_to_add = dbl_conn;

	}
	if (!ubl_total)
		up_bandwidth_to_add = timediff * ubl_conn / 1000000;

	if (!dbl_total)
		down_bandwidth_to_add = timediff * dbl_conn / 1000000;

	for (i = connections.begin(), e = connections.end(); i != e; ++i) {
		if (i->second.needs_write() )
			i->second.ubl_available += up_bandwidth_to_add;
		if (i->second.dbl_over < (unsigned int) down_bandwidth_to_add)
			i->second.dbl_over = 0;
		else i->second.dbl_over -= down_bandwidth_to_add;
	}
}

/*
 * Random Early Detection
 *
 * Note that RED threshold is set in "percent". Below this fill, no packets
 * are discarded; above it, linearly increasing random ratio of packets is
 * discarded. Proto packets are not affected by RED.
 */

bool connection::red_can_send (size_t s)
{
	if (red_enabled) {
		int fill = (100 * (send_q.len() + s) ) / max_waiting_data_size;
		if (fill < red_threshold) return true;
		if (fill > red_threshold + (rand() % (101 - red_threshold) ) )
			return false;
	}
	return true;
}

/*
 * comm_listener stuff
 */

static int comm_listeners_init()
{
	list<string> l;
	list<string>::iterator i;
	int s;

	config_get_list ("listen", l);

	if (!l.size() ) {
		Log_info ("no listeners specified");
		return 0;
	}

	for (i = l.begin();i != l.end();++i) {
		Log_info ("trying to listen on `%s'", i->c_str() );
		s = tcp_listen_socket (i->c_str() );
		if (s >= 0) {
			listeners.insert (s);
			poll_set_add_read (s);
		} else return 1;
	}

	Log_info ("listeners ready");

	return 0;
}

static int comm_listeners_close()
{
	set<int>::iterator i;
	int ret = 0;
	for (i = listeners.begin();i != listeners.end();++i) {
		Log_info ("closing listener %d", *i);
		if (tcp_close_socket (*i, true) ) {
			Log_warn ("problem closing listener socket %d", *i);
			++ret;
		}
	}
	listeners.clear();
	return ret;
}

void comm_listener_poll (int fd)
{
	try_accept_connection (fd);
}

/*
 * create/destroy the connections
 */

static int comm_connections_init()
{
	list<string> c;
	list<string>::iterator i;

	config_get_list ("connect", c);

	if (!c.size() ) {
		Log_info ("no connections specified");
		return 0;
	}

	for (i = c.begin();i != c.end();++i)
		if (connect_connection (*i) ) {
			Log_error ("couldn't start connection to `%s'",
			           i->c_str() );
			return 1;
		}

	Log_info ("connections ready for connecting");
	return 0;
}

static int comm_connections_close()
{
	/*
	 * Close all connection, wait for closing.
	 */

	int timeout_usec;
	if (!config_get_int ("comm_close_timeout", timeout_usec) )
		timeout_usec = 1000000; //10 sec
	Log_info ("waiting %gsec for connections to close...",
	          0.000001*timeout_usec);

	map<int, connection>::iterator i;

	timestamp_update();

	uint64_t cutout_time = timestamp() + timeout_usec;

	//start ssl disconnection
	for (i = connections.begin();i != connections.end();++i) {
		Log_info ("disconnecting connection id %d", i->first);
		i->second.connect_address.clear();
		i->second.disconnect();
	}

	//wait for all connections to close
	while ( (timestamp() < cutout_time) && (connections.size() ) ) {
		poll_wait_for_event (1000);
		comm_periodic_update();
		timestamp_update();
	}

	if (connections.size() ) {
		Log_info ("resetting remaining %u connections",
		          connections.size() );
		//close remaining connections hard.
		for (i = connections.begin();i != connections.end();++i)
			i->second.reset();
	} else Log_info ("all connections closed gracefully");

	comm_periodic_update(); //delete remains

	return 0;
}

/*
 * base comm_ stuff
 */

unsigned int connection::mtu = 8192;
unsigned int connection::max_waiting_data_size = 512000;
unsigned int connection::max_remote_routes = 256;
bool connection::ubl_enabled = false;
int connection::ubl_total = 0;
int connection::ubl_conn = 0;
int connection::ubl_burst = 2048;
bool connection::dbl_enabled = false;
int connection::dbl_total = 0;
int connection::dbl_conn = 0;
int connection::dbl_burst = 20480;
bool connection::red_enabled = true;
int connection::red_threshold = 25;

int comm_load()
{
	int t;

	if (!config_get_int ("max_connections", t) ) max_connections = 1024;
	else max_connections = t;
	Log_info ("max connections count is %d", max_connections);

	if (!config_get_int ("conn-mtu", t) )
		connection::mtu = 8192;
	else 	connection::mtu = t;
	Log_info ("maximal size of internal packets is %d",
	          connection::mtu);

	if (!config_get_int ("max_waiting_data_size", t) )
		connection::max_waiting_data_size = 1024000;
	else connection::max_waiting_data_size = t;
	Log_info ("max %d pending data bytes",
	          connection::max_waiting_data_size);

	if (!config_get_int ("max_remote_routes", t) )
		connection::max_remote_routes = 256;
	else connection::max_remote_routes = t;
	Log_info ("max %d remote routes",
	          connection::max_remote_routes);

	if (!config_get_int ("conn_retry", t) )
		connection::retry = 10000000; //10s is okay
	else	connection::retry = t;
	Log_info ("connection retry is %gsec", 0.000001*connection::retry);

	if (!config_get_int ("conn_timeout", t) )
		connection::timeout = 60000000; //60s is okay
	else	connection::timeout = t;
	Log_info ("connection timeout is %gsec", 0.000001*connection::timeout);

	if (!config_get_int ("conn_keepalive", t) )
		connection::keepalive = 5000000; //5s is okay
	else	connection::keepalive = t;
	Log_info ("connection keepalive is %gsec",
	          0.000001*connection::keepalive);

	if (config_get_int ("uplimit-conn", t) ) {
		connection::ubl_enabled = true;
		connection::ubl_conn = t;
		Log_info ("per-connection upload limit is %dB/s", t);
	}

	if (config_get_int ("uplimit-total", t) ) {
		connection::ubl_enabled = true;
		connection::ubl_total = t;
		Log_info ("total upload limit is %dB/s", t);
	}

	if (config_get_int ("uplimit-burst", t) ) {
		connection::ubl_burst = t;
	} else connection::ubl_burst = 2048;
	if (connection::ubl_enabled)
		Log_info ("burst upload size is %dB", t);

	if (config_get_int ("downlimit-conn", t) ) {
		connection::dbl_enabled = true;
		connection::dbl_conn = t;
		Log_info ("per-connection download limit is %dB/s", t);
	}

	if (config_get_int ("downlimit-total", t) ) {
		connection::dbl_enabled = true;
		connection::dbl_total = t;
		Log_info ("total download limit is %dB/s", t);
	}

	if (config_get_int ("downlimit-burst", t) ) {
		connection::dbl_burst = t;
	} else connection::dbl_burst = 20480;
	if (connection::dbl_enabled)
		Log_info ("burst download size is %dB", t);

	connection::red_enabled = true; //it's better on by default
	connection::red_threshold = 50;
	if (config_get_int ("red-ratio", t) ) {
		connection::red_threshold = t % 100;
		if (t == 100)
			connection::red_enabled = false;
		Log_info ("RED enabled with ratio %d%%",
		          connection::red_threshold);
	}

	/*
	 * configuration done, lets init.
	 */

	if (ssl_initialize() ) {
		Log_fatal ("SSL initialization failed");
		return 2;
	}
	return 0;
}

int comm_init()
{

	if (comm_listeners_init() ) {
		Log_fatal ("couldn't initialize listeners");
		return 3;
	}

	if (comm_connections_init() ) {
		Log_fatal ("couldn't initialize connections");
		return 4;
	}

	return 0;
}

int comm_shutdown()
{
	if (comm_listeners_close() )
		Log_warn ("closing of some listening sockets failed!");

	if (comm_connections_close() )
		Log_warn ("closing of some connections failed!");

	if (ssl_destroy() )
		Log_warn ("SSL shutdown failed!");

	return 0;
}

void comm_flush_data()
{
	/*
	 * call this after each timeslice. It prevents send-data fragmentation.
	 */
	if (connection::ubl_enabled) connection::bl_recompute();

	map<int, connection>::iterator i;
	for (i = connections.begin();i != connections.end();++i)
		i->second.try_write();
}

void comm_periodic_update()
{
	/*
	 * delete inactive connections,
	 * push the other.
	 */

	map<int, connection>::iterator i;
	list<int> to_delete;

	for (i = connections.begin();i != connections.end();++i) {
		i->second.periodic_update();
		if (i->second.state == cs_inactive)
			to_delete.push_back (i->first);
	}

	while (to_delete.size() ) {
		connections.erase (to_delete.front() );
		to_delete.pop_front();
	}

	connection::bl_recompute();
}

/*
 * used by route to report route updates to everyone
 */

void comm_broadcast_route_update (uint8_t*data, int n)
{
	map<int, connection>::iterator i;
	for (i = connections.begin();i != connections.end();++i)
		if (i->second.state == cs_active)
			i->second.write_route_diff (data, n);
}

