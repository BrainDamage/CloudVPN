
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
#include "log.h"
#include "poll.h"
#include "route.h"
#include "timestamp.h"
#include "sq.h"

#include <gnutls/gnutls.h>
#include <gcrypt.h>

#ifndef __WIN32__
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#define close closesocket
#endif

#include <errno.h>
#ifndef EINPROGRESS
#define EINPROGRESS EAGAIN
#endif

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
 * socket initialization
 *
 * generally, sets socket option according to configuration.
 *
 * We support TCP_NODELAY as it is vitable for gaming,
 * and IP_TOS settings for optimizing the delay/throughput/reliability/cost
 */

#ifndef __WIN32__
#include <netinet/in_systm.h>  //required on some platforms for n_time
#include <netinet/ip.h>
#include <netinet/tcp.h>
#endif

static bool tcp_nodelay = false;
static int ip_tos = 0;

static void sockoptions_init()
{
#ifndef __WIN32__
	tcp_nodelay = config_is_true ("tcp_nodelay");
	if (tcp_nodelay) Log_info ("TCP_NODELAY is set for all sockets");
	string t;
	if (!config_get ("ip_tos", t) ) return;
	if (t == "lowdelay") ip_tos = IPTOS_LOWDELAY;
	else if (t == "throughput") ip_tos = IPTOS_THROUGHPUT;
	else if (t == "reliability") ip_tos = IPTOS_RELIABILITY;
#ifdef IPTOS_MINCOST  //not available on some platforms.
	else if (t == "mincost") ip_tos = IPTOS_MINCOST;
#endif
	if (ip_tos) Log_info ("type of service is `%s' for all sockets",
		                      t.c_str() );
#endif
}

static void sockoptions_set (int s)
{
#ifndef __WIN32__
	int t;
	if (tcp_nodelay) {
		t = 1;
		if (setsockopt (s, IPPROTO_TCP, TCP_NODELAY, &t, sizeof (t) ) )
			Log_warn ( "setsockopt(%d,TCP,NODELAY) failed with %d: %s",
			           s, errno, strerror (errno) );
	}
	if (ip_tos) {
		t = ip_tos;
		if (setsockopt (s, IPPROTO_IP, IP_TOS, &t, sizeof (t) ) )
			Log_warn ("setsockopt(%d,IP,TOS) failed with %d: %s",
			          s, errno, strerror (errno) );
	}
#endif
}

/*
 * global SSL stuff
 */

static gnutls_certificate_credentials_t xcred;
static gnutls_dh_params_t dh_params;

/*
 * GnuTLS initialization
 *
 * What is loaded:
 * - key+cert
 * - DH params
 * - Some number of CA's. If there's no CA specified, there's no checking.
 * - Some number of CRL's.
 */

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
	//TODO loading
	/*if (config_get ("dh", t) ) {
		//gnutls_dh_params_import_from_pkcs3 (dh_params, &data,
		                                    GNUTLS_X509_FORMAT_PEM);
	} else */
	gnutls_dh_params_generate2 (dh_params, 1024);
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

	Log_info ("SSL initialized OK");
	return 0;
}

static int ssl_destroy()
{
	Log_info ("destroying SSL layer");
	gnutls_certificate_free_credentials (xcred);
	gnutls_dh_params_deinit (dh_params);
	gnutls_global_deinit();
	return 0;
}

/*
 * raw network stuff
 *
 * backends to listen/connect/accept network operations
 */

static int listen_backlog_size = 32;

static int tcp_listen_socket (const string&addr)
{
	sockaddr_type (sa);
	int sa_len, domain;
	if (!sockaddr_from_str (addr.c_str(), &sa, &sa_len, &domain) ) {
		Log_error ("could not resolve address and port `%s'",
		           addr.c_str() );
		return -1;
	}

	int s = socket (domain, SOCK_STREAM, 0);

	if (s < 0) {
		Log_error ("socket() failed with %d", errno);
		return -2;
	}

	int opt = 1;
	if (setsockopt (s, SOL_SOCKET, SO_REUSEADDR,
#ifdef __WIN32__
	                (const char*)
#endif
	                &opt, sizeof (opt) ) < 0)
		Log_warn ("setsockopt(%d,SO_REUSEADDR) failed, may cause errors.", s);

	if (!sock_nonblock (s) ) {
		Log_error ("can't set socket %d to nonblocking mode", s);
		close (s);
		return -3;
	}

	if (bind (s, &sa, sa_len) ) {
		Log_error ("binding socket %d failed with %d", s, errno);
		close (s);
		return -4;
	}

	if (listen (s, listen_backlog_size) ) {
		Log_error ("listen(%d,%d) failed with %d",
		           s, listen_backlog_size, errno);
		close (s);
		return -5;
	}

	Log_info ("created listening socket %d", s);

	return s;
}

static int tcp_connect_socket (const string&addr)
{
	sockaddr_type (sa);
	int sa_len, domain;
	if (!sockaddr_from_str (addr.c_str(), &sa, &sa_len, &domain) ) {
		Log_error ("could not resolve address and port `%s'",
		           addr.c_str() );
		return -1;
	}

	int s = socket (domain, SOCK_STREAM, 0);

	if (s < 0) {
		Log_error ("socket() failed with %d", errno);
		return -2;
	}

	if (!sock_nonblock (s) ) {
		Log_error ("can't set socket %d to nonblocking mode", s);
		close (s);
		return -3;
	}

	sockoptions_set (s);

	if (connect (s, &sa, sa_len) < 0 ) {
		int e = errno;
		if (e != EINPROGRESS) {
			Log_error ("connect(%d) to `%s' failed with %d",
			           s, addr.c_str(), e);
			return -4;
		}
	}

	return s;
}

static int tcp_close_socket (int sock)
{
	if (close (sock) ) {
		Log_warn ("closing socket %d failed with %d!", sock, errno);
		return 1;
	}
	return 0;
}

/*
 * this is needed to determine if socket is properly connected
 */

#ifndef __WIN32__
#include <sys/select.h>
#endif

static int tcp_socket_writeable (int sock)
{
	fd_set s;
	struct timeval t = {0, 0};
	FD_ZERO (&s);
	FD_SET (sock, &s);
	select (sock + 1, 0, &s, 0, &t);
	if (FD_ISSET (sock, &s) ) return 1;
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
	sockaddr_type (addr);
	socklen_t addrsize = sockaddr_type_size;
	int s = accept (sock, &addr, &addrsize);
	if (s < 0) {
		if (errno == EAGAIN) return 0;
		Log_error ("accept(%d) failed with %d", errno);
		return 1;
	}

	sockoptions_set (s);

	string peer_addr_str = sockaddr_to_str (&addr);
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
		Log_warn ("connection limit %d hit, will NOT connect to `%s'");
		Log_info ("consider increasing the limit");
		return 1;
	}

	Log_info ("connection %d created for connecting to %s",
	          cid, addr.c_str() );

	connection&c = connections[cid];

	c.state = cs_retry_timeout;
	c.last_retry = 0;
	c.address = addr;

	return 0;
}

/*
 * class connection stuff
 */

int connection::timeout = 60000000; //60 sec
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
#define pt_eth_frame 3
#define pt_broadcast 4
#define pt_echo_request 5
#define pt_echo_reply 6
#define pt_route_request 7

//sizes
#define p_head_size 4
#define route_entry_size 12

static void add_packet_header (pbuffer&b, uint8_t type,
                               uint8_t special, uint16_t size)
{
	b.b.reserve (p_head_size);
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
	uint16_t t2;
	q.pop<uint16_t> (t2);
	size = ntohs (t2);
	return true;
}

/*
 * handlers of incoming information
 */

void connection::handle_packet (void*buf, int len)
{
	if (dbl_enabled) {
		if (dbl_over > (unsigned int) dbl_burst) return;
		dbl_over += len + 4;
	}
	stat_packet (true, len + p_head_size);
	route_packet (buf, len, id);
}

void connection::handle_broadcast_packet (uint32_t ID, void*buf, int len)
{
	if (dbl_enabled) {
		if (dbl_over > (unsigned int) dbl_burst) return;
		dbl_over += len + 8;
	}
	stat_packet (true, len + p_head_size + 4);
	route_broadcast_packet (ID, buf, len, id);
}

void connection::handle_route_set (uint8_t*data, int n)
{
	stat_packet (true, n*route_entry_size + p_head_size);
	remote_routes.clear();
	uint32_t remote_ping;
	uint16_t remote_dist;
	for (int i = 0;i < n;++i, data += route_entry_size) {
		remote_dist = ntohs (* ( (uint16_t*) (data + hwaddr_size) ) );
		remote_ping = ntohl (* ( (uint32_t*) (data + hwaddr_size + 2) ) );
		if (remote_ping) remote_routes[hwaddr (data) ] =
			    remote_route (remote_ping, remote_dist);
	}

	handle_route_overflow();
	route_set_dirty();
}

void connection::handle_route_diff (uint8_t*data, int n)
{
	stat_packet (true, n*route_entry_size + p_head_size);
	if (!n) return;

	uint32_t remote_ping;
	uint16_t remote_dist;
	for (int i = 0;i < n;++i, data += route_entry_size) {
		remote_dist = ntohs (* ( (uint16_t*) (data + hwaddr_size) ) );
		remote_ping = ntohl (* ( (uint32_t*) (data + hwaddr_size + 2) ) );
		if (remote_ping) remote_routes[hwaddr (data) ] =
			    remote_route (remote_ping, remote_dist);
		else remote_routes.erase (hwaddr (data) );
	}

	handle_route_overflow();
	route_set_dirty();
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

pbuffer& connection::new_data (size_t size)
{
	data_q_size += size;
	data_q.push_back (pbuffer() );
	data_q.back().b.reserve (size);
	stat_packet (false, size);
	return data_q.back();
}

pbuffer& connection::new_proto (size_t size)
{
	proto_q_size += size;
	proto_q.push_back (pbuffer() );
	proto_q.back().b.reserve (size);
	stat_packet (false, size);
	return proto_q.back();
}

void connection::write_packet (void*buf, int len)
{
	size_t size = p_head_size + len;
	if (!can_write_data (size) ) {
		try_write();
		return;
	}
	if ( (unsigned int) len > mtu) return;
	pbuffer& b = new_data (size);
	add_packet_header (b, pt_eth_frame, 0, len);
	b.push ( (uint8_t*) buf, len);
	try_write();
}

void connection::write_broadcast_packet (uint32_t ID, void*buf, int len)
{
	size_t size = p_head_size + len + 4;
	if (!can_write_data (size) ) {
		try_write();
		return;
	}
	if ( (unsigned int) len > mtu) return;
	pbuffer& b = new_data (size);
	add_packet_header (b, pt_broadcast, 0, len);
	b.push<uint32_t> (htonl (ID) );
	b.push ( (uint8_t*) buf, len);
	try_write();
}

void connection::write_route_set (uint8_t*data, int n)
{
	size_t size = p_head_size + n * route_entry_size;
	if (!can_write_proto (size) ) {
		try_write();
		return;
	}
	pbuffer&b = new_proto (size);
	add_packet_header (b, pt_route_set, 0, n);
	b.push (data, n* route_entry_size );
	try_write();
}

void connection::write_route_diff (uint8_t*data, int n)
{
	size_t size = p_head_size + n * route_entry_size;
	if (!can_write_proto (size) ) {
		try_write();
		return;
	}
	pbuffer&b = new_proto (size);
	add_packet_header (b, pt_route_diff, 0, n);
	b.push (data, n* route_entry_size );
	try_write();
}

void connection::write_ping (uint8_t ID)
{
	size_t size = p_head_size;
	if (!can_write_proto (size) ) {
		try_write();
		return;
	}
	pbuffer&b = new_proto (size);
	add_packet_header (b, pt_echo_request, ID, 0);
	try_write();
}

void connection::write_pong (uint8_t ID)
{
	size_t size = p_head_size;
	if (!can_write_proto (size) ) {
		try_write();
		return;
	}
	pbuffer&b = new_proto (size);
	add_packet_header (b, pt_echo_reply, ID, 0);
	try_write();
}

void connection::write_route_request ()
{
	size_t size = p_head_size;
	if (!can_write_proto (size) ) {
		try_write();
		return;
	}
	pbuffer&b = new_proto (size);
	add_packet_header (b, pt_route_request, 0, 0);
	try_write();
}

/*
 * try_parse_input examines the content of the incoming queue, and
 * calls appropriate handlers, if some packet is found.
 */

void connection::try_parse_input()
{
try_more:
	if (state != cs_active) return; //safety.

	if (cached_header.type == 0)
		parse_packet_header (recv_q,
		                     cached_header.type,
		                     cached_header.special,
		                     cached_header.size);

	switch (cached_header.type) {
	case 0:
		break;
	case pt_route_set:
		if (recv_q.len() >=
		        (unsigned int) cached_header.size*route_entry_size) {
			handle_route_set (recv_q.begin(), cached_header.size);
			recv_q.read (cached_header.size*route_entry_size);
			cached_header.type = 0;
			goto try_more;
		}
		break;
	case pt_route_diff:
		if (recv_q.len() >=
		        (unsigned int) cached_header.size*route_entry_size) {
			handle_route_diff (recv_q.begin(), cached_header.size);
			recv_q.read (cached_header.size*route_entry_size);
			cached_header.type = 0;
			goto try_more;
		}
		break;

	case pt_eth_frame:
		if (recv_q.len() >= cached_header.size) {
			handle_packet (recv_q.begin(), cached_header.size);
			recv_q.read (cached_header.size);
			cached_header.type = 0;
			goto try_more;
		}
		break;

	case pt_broadcast:
		if (recv_q.len() >= (unsigned int) cached_header.size + 4) {
			uint32_t t;
			recv_q.pop<uint32_t> (t);
			t = ntohl (t);
			handle_broadcast_packet (t, recv_q.begin(),
			                         cached_header.size);
			recv_q.read (cached_header.size);
			cached_header.type = 0;
			goto try_more;
		}
		break;

	case pt_echo_request:
		handle_ping (cached_header.special);
		cached_header.type = 0;
		goto try_more;

	case pt_echo_reply:
		handle_pong (cached_header.special);
		cached_header.type = 0;
		goto try_more;

	case pt_route_request:
		handle_route_request ();
		cached_header.type = 0;
		goto try_more;

	default:
		Log_error ("invalid packet header received. disconnecting.");
		disconnect();
	}
}

/*
 * read/write operations
 */

bool connection::try_read()
{
	int r;
	uint8_t*buf;
	while (1) {
		buf = recv_q.get_buffer (4096); //alloc a buffer

		if (!buf) {
			Log_error ("cannot allocate enough buffer space for connection %d");
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
		}
	}
	return true;
}

bool connection::try_write()
{
	const uint8_t *buf;
	int n, r;

	if (ubl_enabled && (!ubl_available) && needs_write() ) bl_recompute();

	while (needs_write() ) {

		if (sending_from_data_q) {
			if (!data_q.size() ) {
				sending_from_data_q = false;
				continue;
			} else {
				buf = data_q.front().b.begin().base();
				n = data_q.front().b.size();
			}
		}

		if (!sending_from_data_q) {
			if (proto_q.size() ) {
				buf = proto_q.front().b.begin().base();
				n = proto_q.front().b.size();
			} else { //we can be pretty sure there's something.
				sending_from_data_q = true;
				buf = data_q.front().b.begin().base();
				n = data_q.front().b.size();
			}
		}

		//choke the bandwidth. Note that we dont want to really
		//discard the packet here, because of SSL.
		if (sending_from_data_q && ubl_enabled &&
		        ( (unsigned int) n > ubl_available) ) break;

		//or try to send.
		r = gnutls_record_send (session, buf, n);

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
			return true;
		} else {
			if (sending_from_data_q) {
				if (ubl_enabled) ubl_available -= n;
				if (data_q_size < data_q.front().b.size() )
					data_q_size = 0;
				else data_q_size -= data_q.front().b.size();
				data_q.pop_front();
				sending_from_data_q = false;
			} else {
				if (proto_q_size < proto_q.front().b.size() )
					proto_q_size = 0;
				else proto_q_size -= proto_q.front().b.size();
				proto_q.pop_front();
			}
		}
	}
	poll_set_remove_write (fd); //don't need any more write
	data_q_size = proto_q_size = 0; //to be sure
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
	if (try_write() )
		try_read();
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

		//TODO, check cert here?

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
	int e = -1, t;
	socklen_t e_len = sizeof (e);

	t = getsockopt (fd, SOL_SOCKET, SO_ERROR,
#ifdef __WIN32__
	                (char*)
#endif
	                & e, &e_len);

	if (t) {
		Log_error ("getsockopt(%d) failed with errno %d", fd, errno);
		reset();
		return;
	}

	if (e == EINPROGRESS) {
		if ( (timestamp() - last_ping) > (unsigned int) timeout) {
			Log_error ("timeout connecting %d", fd);
			reset();
			return;
		} else return;
	}

	if (e == 0) {
		//test if the socket is writeable, otherwise still in progress
		if (!tcp_socket_writeable (fd) ) return;


		//print a nice info about who are we connected to
		sockaddr_type (addr);
		socklen_t s = sockaddr_type_size;
		if (getpeername (fd, (sockaddr*) &addr, &s) )
			Log_info ("conn %d connected to unknown peer", id);
		else {
			peer_addr_str = sockaddr_to_str (&addr);
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
		return;
	}

	Log_error ("connecting %d failed with %d", fd, e);
	reset();
}

void connection::try_ssl_connect()
{
	int r = gnutls_handshake (session);
	if (r == 0) {
		Log_info ("socket %d established SSL connection id %d", fd, id);

		/*
		 * TODO
		 * Do gnutls verification here
		 */

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

	int t = tcp_connect_socket (address);
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
	sending_from_data_q = false;
	send_ping();
	route_report_to_connection (*this);
}

void connection::disconnect()
{
	poll_set_remove_write (fd);
	poll_set_remove_read (fd);

	if ( (state == cs_retry_timeout) && (! (address.length() ) ) ) {
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

	sending_from_data_q = false;
	recv_q.clear();
	proto_q.clear();
	data_q.clear();

	cached_header.type = 0;

	dealloc_ssl();

	ping = timeout;
	last_ping = 0;

	tcp_close_socket (fd);
	unset_fd();

	stats_clear();
	ubl_available = 0;
	dbl_over = 0;

	if (address.length() )
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
		Log_error ("fatal ssl error %d on connection %d", ret, id);
		return 1;
	}

	switch (ret) {
	case GNUTLS_E_AGAIN:
	case GNUTLS_E_INTERRUPTED:
		if (gnutls_record_get_direction (session) )
			poll_set_add_write (fd);
		else if (state != cs_active) poll_set_remove_write (fd);
		break;
	default:
		Log_warn ("non-fatal ssl error %d on connection %d", ret, id);
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

	//TODO set priorities?
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

	vector<hwaddr>to_del;
	vector<hwaddr>::iterator hi;
	map<hwaddr, remote_route>::iterator rri, rre;
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
 * as we rely on TCP, we can limit only upload, but that shouldn't be a problem.
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
		int fill = (100 * (data_q_size + s) ) / max_waiting_data_size;
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
		s = tcp_listen_socket (*i);
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
		if (close (*i) ) {
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
			Log_error ("couldn't start connection to `%s'");
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
		i->second.address.clear();
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
unsigned int connection::max_waiting_data_size = 262144;
unsigned int connection::max_waiting_proto_size = 65536;
unsigned int connection::max_remote_routes = 256;
bool connection::ubl_enabled = false;
int connection::ubl_total = 0;
int connection::ubl_conn = 0;
int connection::ubl_burst = 2048;
bool connection::dbl_enabled = false;
int connection::dbl_total = 0;
int connection::dbl_conn = 0;
int connection::dbl_burst = 20480;
bool connection::red_enabled = false;
int connection::red_threshold = 50;

int comm_init()
{
	int t;

	if (!config_get_int ("max_connections", t) ) max_connections = 1024;
	else max_connections = t;
	Log_info ("max connections count is %d", max_connections);

	if (!config_get_int ("listen_backlog", t) ) listen_backlog_size = 32;
	else listen_backlog_size = t;
	Log_info ("listen backlog size is %d", listen_backlog_size);

	if (!config_get_int ("conn-mtu", t) )
		connection::mtu = 8192;
	else 	connection::mtu = t;
	Log_info ("maximal size of internal packets is %d",
	          connection::mtu);

	if (!config_get_int ("max_waiting_data_size", t) )
		connection::max_waiting_data_size = 262144;
	else connection::max_waiting_data_size = t;
	Log_info ("max %d pending data packets",
	          connection::max_waiting_data_size);

	if (!config_get_int ("max_waiting_proto_size", t) )
		connection::max_waiting_proto_size = 65536;
	else connection::max_waiting_proto_size = t;
	Log_info ("max %d pending proto packets",
	          connection::max_waiting_proto_size);

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

	if (config_get_int ("red-ratio", t) ) {
		connection::red_enabled = true;
		connection::red_threshold = t % 100;
		Log_info ("RED enabled with ratio %d%%",
		          connection::red_threshold);
	}

	/*
	 * configuration done, lets init.
	 */

	sockoptions_init();

	if (ssl_initialize() ) {
		Log_fatal ("SSL initialization failed");
		return 2;
	}

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

