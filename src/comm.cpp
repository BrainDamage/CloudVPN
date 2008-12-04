
#include "comm.h"

#include "conf.h"
#include "log.h"
#include "poll.h"
#include "route.h"
#include "timestamp.h"
#include "sq.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <string.h>

#include <list>
using namespace std;

static map<int, int> conn_index;
static map<int, connection> connections;
static set<int> listeners;

/*
 * NOTICE (FUKKEN IMPORTANT)
 * because of good pollability, connections MUST be IDed by their socket fds.
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

static SSL_CTX* ssl_ctx;
static string ssl_pass;

static int ssl_password_callback (char*buffer, int num, int rwflag, void*udata)
{
	if (num < ssl_pass.length() + 1) {
		Log_warn ("ssl_pw_cb: supplied buffer too small");
		return 0;
	}

	strcpy (buffer, ssl_pass.c_str() );

	return ssl_pass.length();
}

static int ssl_initialize()
{
	SSL_METHOD* meth;

	string keypath, certpath, capath;

	if ( (!config_get ("key", keypath) ) ||
	        (!config_get ("cert", certpath) ) ||
	        (!config_get ("ca_cert", capath) ) ) {
		Log_fatal ("you must correctly specify key, cert and ca_cert options");
		return 1;
	}

	ssl_pass = "";
	if (config_get ("key_pass", ssl_pass) )
		Log_info ("SSL key password loaded");
	else	Log_info ("SSL key password left blank");


	SSL_library_init();

	SSL_load_error_strings();

	//maybe signal(sigpipe) belons here, no idea why.

	meth = SSLv23_method();
	ssl_ctx = SSL_CTX_new (meth);
	SSL_CTX_set_options (ssl_ctx, SSL_OP_NO_SSLv2);
	SSL_CTX_set_options (ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

	SSL_CTX_set_default_passwd_cb (ssl_ctx, ssl_password_callback);

	if (!SSL_CTX_use_certificate_chain_file (ssl_ctx, certpath.c_str() ) ) {
		Log_error ("SSL Certificate loading failed: %s",
		           ERR_error_string (ERR_get_error(), 0) );
		return 2;
	}

	if (!SSL_CTX_use_PrivateKey_file (ssl_ctx,
	                                  keypath.c_str(),
	                                  SSL_FILETYPE_PEM) ) {
		Log_error ("SSL Key loading failed: %s",
		           ERR_error_string (ERR_get_error(), 0) );
		return 3;
	}

	if (!SSL_CTX_load_verify_locations (ssl_ctx, capath.c_str(), 0) ) {
		Log_error ("SSL CA loading failed: %s",
		           ERR_error_string (ERR_get_error(), 0) );
		return 4;
	}

	string dh_file;
	if (config_get ("dh", dh_file) ) {

		BIO*bio;
		DH*dh;

		bio = BIO_new_file (dh_file.c_str(), "r");

		if (!bio) {
			Log_error ("opening DH file `%s' failed",
			           dh_file.c_str() );
			return 5;
		}

		dh = PEM_read_bio_DHparams (bio, 0, 0, 0);

		BIO_free (bio);

		if (!dh) {
			Log_error ("loading DH params failed");
			return 6;
		}

		if (!SSL_CTX_set_tmp_dh (ssl_ctx, dh) ) {
			Log_error ("could not set DH parameters");
			return 7;
		}

		Log_info ("DH parameters of size %db loaded OK",
		          8*DH_size (dh) );

	} else {
		Log_error ("you need to supply server DH parameters");
		return 8;
	}

	if (!SSL_CTX_check_private_key (ssl_ctx) ) {
		Log_error ("supplied private key does not match the certificate!");
		return 9;
	}

	SSL_CTX_set_verify (ssl_ctx, SSL_VERIFY_PEER |
	                    SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);

	Log_info ("SSL initialized OK");
	return 0;
}

static int ssl_destroy()
{
	SSL_CTX_free (ssl_ctx);
	return 0;
}

/*
 * raw network stuff
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
	if (setsockopt (s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof (opt) ) < 0)
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

	if (!connect (s, &sa, sa_len) ) {
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

#include <sys/select.h>

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
 * connection creation helpers
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
	map<int, connection>::iterator i = connections.find (id);
	if (i == connections.end() ) return;
	i->second.unset_fd();
	connections.erase (i);
}

/*
 * This should accept a connection, and link it into the structure.
 * Generally, only these 2 functions really create connections:
 */

static int try_accept_connection (int sock)
{
	int s = accept (sock, 0, 0);
	if (s < 0) {
		if (errno == EAGAIN) return 0;
		Log_error ("accept(%d) failed with %d", errno);
		return 1;
	}

	if (!sock_nonblock (s) ) {
		Log_error ("could not put accepted socket %d in nonblocking mode", s);
		close (s);
		return 2;
	}

	Log_info ("get connection on socket %d", s);

	int cid = connection_alloc();
	if (cid < 0) {
		Log_info ("connection limit %d hit, closing %d",
		          max_connections, s);
		return 0;
	}

	connection&c = connections[cid];

	c.set_fd (s);
	c.state = cs_accepting;

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

void connection::index()
{
	conn_index[fd] = id;
}

void connection::deindex()
{
	conn_index.erase (fd);
}

/*
 * protocol headers
 */

#define pt_route_set 1
#define pt_route_diff 2
#define pt_eth_frame 3
#define pt_broadcast 4
#define pt_echo_request 5
#define pt_echo_reply 6

#define p_head_size 4
#define route_entry_size 10

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
 * handlers
 */

void connection::handle_packet (void*buf, int len)
{
	route_packet (buf, len, id);
}

void connection::handle_broadcast_packet (uint32_t ID, void*buf, int len)
{
	route_broadcast_packet (ID, buf, len, id);
}

void connection::handle_route_set (uint8_t*data, int n)
{
	remote_routes.clear();
	uint32_t remote_ping;
	for (int i = 0;i < n;++i, data += route_entry_size) {
		remote_ping = ntohl (* ( (uint32_t*) (data + hwaddr_size) ) );
		remote_routes.insert
		(pair<hwaddr, int> (hwaddr (data), remote_ping) );
	}
	route_set_dirty();
}

void connection::handle_route_diff (uint8_t*data, int n)
{
	uint32_t remote_ping;
	for (int i = 0;i < n;++i, data += route_entry_size) {
		remote_ping = ntohl (* ( (uint32_t*) (data + hwaddr_size) ) );
		if (ping)
			remote_routes.insert
			(pair<hwaddr, int> (hwaddr (data), remote_ping) );
		else remote_routes.erase (hwaddr (data) );
	}
	route_set_dirty();
}

void connection::handle_ping (uint8_t ID)
{
	write_pong (ID);
}

void connection::handle_pong (uint8_t ID)
{
	last_ping = timestamp();
	if (ID != sent_ping_id) {
		Log_info ("connection %d received some very old ping", id);
		return;
	}
	ping = timestamp() - sent_ping_time;
	Log_info ("connection %d has ping %g", id, 0.000001*ping);
}

/*
 * senders
 */

void connection::write_packet (void*buf, int len)
{
	pbuffer b;
	add_packet_header (b, pt_eth_frame, 0, len);
	write_data (b, true);
	write_data ( (uint8_t*) buf, len);
}

void connection::write_broadcast_packet (uint32_t ID, void*buf, int len)
{
	pbuffer b;
	add_packet_header (b, pt_broadcast, 0, len);
	b.push<uint32_t> (htonl (ID) );
	write_data (b, true);
	write_data ( (uint8_t*) buf, len);
}

void connection::write_route_set (uint8_t*data, int n)
{
	pbuffer b;
	add_packet_header (b, pt_route_set, 0, n);
	write_data (b, true);
	write_data (data, n*route_entry_size);
}

void connection::write_route_diff (uint8_t*data, int n)
{
	pbuffer b;
	add_packet_header (b, pt_route_diff, 0, n);
	write_data (b, true);
	write_data (data, n*route_entry_size);
}

void connection::write_ping (uint8_t ID)
{
	pbuffer b;
	add_packet_header (b, pt_echo_request, ID, 0);
	write_data (b);
}

void connection::write_pong (uint8_t ID)
{
	pbuffer b;
	add_packet_header (b, pt_echo_reply, ID, 0);
	write_data (b);
}

/*
 * actions
 */

void connection::try_parse_input()
{
	if (cached_header.type == 0)
		if (recv_q.len() >= p_head_size)
			parse_packet_header (recv_q,
			                     cached_header.type,
			                     cached_header.special,
			                     cached_header.size);
	switch (cached_header.type) {
	case 0:
		break;
	case pt_route_set:
		if (recv_q.len() >= cached_header.size*route_entry_size) {
			uint8_t buf[cached_header.size*route_entry_size];
			recv_q.pop (buf, cached_header.size*route_entry_size);
			handle_route_set (buf, cached_header.size);
		}
		cached_header.type = 0;
		break;
	case pt_route_diff:
		if (recv_q.len() >= cached_header.size*route_entry_size) {
			uint8_t buf[cached_header.size*route_entry_size];
			recv_q.pop (buf, cached_header.size*route_entry_size);
			handle_route_diff (buf, cached_header.size);
		}
		cached_header.type = 0;
		break;

	case pt_eth_frame:
		if (recv_q.len() >= cached_header.size) {
			uint8_t buf[cached_header.size];
			recv_q.pop (buf, cached_header.size);
			handle_packet (buf, cached_header.size);
		}
		cached_header.type = 0;
		break;

	case pt_broadcast:
		if (recv_q.len() >= cached_header.size + 4) {
			uint32_t t;
			recv_q.pop<uint32_t> (t);
			t = ntohl (t);
			uint8_t buf[cached_header.size];
			recv_q.pop (buf, cached_header.size);
			handle_broadcast_packet (t, buf, cached_header.size);
		}
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

	default:
		Log_error ("invalid packet header received. disconnecting.");
		disconnect();
	}
}

void connection::try_read()
{
	uint8_t buf[4096];
	int r;
	while (1) {
		r = SSL_read (ssl, buf, 4096);
		if (r == 0) {
			Log_info ("connection id %d closed by peer", id);
			disconnect();
			return;
		} else if (r < 0) {
			if (handle_ssl_error (r) ) {
				Log_info ("connection id %d read error", id);
				reset();
			}
			return;
		} else {
			recv_q.push (buf, r);
			try_parse_input();
		}
	}
}

void connection::write_data (pbuffer&b, bool write_wait)
{
	if (state != cs_active) return;
	send_q.push (b);
	if (write_wait) return;
	try_write();
}

void connection::write_data (uint8_t*b, int len, bool write_wait)
{
	if (state != cs_active) return;
	send_q.push (b, len);
	if (write_wait) return;
	try_write();
}

void connection::try_write()
{
	uint8_t buf[4096];
	int n, r;
	while (send_q.len() ) {
		n = send_q.peek (buf, 4096);

		r = SSL_write (ssl, buf, n);

		if (r == 0) {
			Log_info ("connection id %d closed by peer", id);
			disconnect();
			return;
		} else if (r < 0) {
			if (handle_ssl_error (r) ) {
				Log_error ("connection id %d write error", id);
				reset();
				return;
			}
		} else {
			send_q.pop (0, r);
		}
	}
	poll_set_remove_write (fd);
}

void connection::try_data()
{
	if (send_q.len() ) try_write();
	try_read();
}

void connection::try_accept()
{
	int r = SSL_accept (ssl);
	if (r > 0) {
		Log_info ("socket %d accepted SSL connection", fd);

		activate();

	} else if (handle_ssl_error (r) ) {
		Log_error ("accepting fd %d lost", fd);
		reset();
		return;
	}
	if ( (timestamp() - last_ping) > timeout) {
		Log_error ("accepting fd %d timeout", fd);
		reset();
		return;
	}
}

void connection::try_connect()
{
	int e = -1, t;
	socklen_t e_len = sizeof (e);

	t = getsockopt (fd, SOL_SOCKET, SO_ERROR, &e, &e_len);

	if (t) {
		Log_error ("getsockopt(%d) failed with errno %d", fd, errno);
		reset();
		return;
	}

	if (e == EINPROGRESS) {
		if ( (timestamp() - last_ping) > timeout) {
			Log_error ("timeout connecting %d", fd);
			reset();
			return;
		} else return;
	}

	if (e == 0) {
		//test if the socket is writeable, otherwise still in progress
		if (!tcp_socket_writeable (fd) ) return;

		poll_set_remove_write (fd);
		poll_set_add_read (fd); //always needed
		state = cs_ssl_connecting;
		if (alloc_ssl() ) reset();
		else try_ssl_connect();
		return;
	}

	Log_error ("connecting %d failed with %d", fd, e);
	reset();
}

void connection::try_ssl_connect()
{
	int r = SSL_connect (ssl);
	if (r > 0) {
		Log_info ("socket %d established SSL connection", fd);

		activate();

	} else if (handle_ssl_error (r) ) {
		Log_error ("SSL connecting on %d failed", fd);
		reset();
		return;
	}

}

void connection::try_close()
{
	int r = SSL_shutdown (ssl);
	if (r < 0) {
		Log_warn ("SSL connection on %d not terminated properly", fd);
		reset();
	} else if (r != 0) reset(); //closed OK
	else if ( (timestamp() - last_ping) > timeout) {
		Log_warn ("%d timeouted disconnecting SSL", fd);
		reset();
	}
	//else just wait for another poll
}

/*
 * forced state changes
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
	if (alloc_ssl() ) {
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
	send_ping();
	route_report_to_connection (*this);
}

void connection::disconnect()
{
	if ( (state == cs_retry_timeout) && (! (address.length() ) ) ) {
		state = cs_inactive;
		return;
	}

	if ( (state == cs_inactive)
	        || (state == cs_retry_timeout)
	        || (state == cs_closing) ) return;

	last_ping = timestamp();
	state = cs_closing;
	try_close();
}

void connection::reset()
{
	send_q.clear();
	recv_q.clear();
	cached_header.type = 0;

	dealloc_ssl();

	poll_set_remove_write (fd);
	poll_set_remove_read (fd);

	tcp_close_socket (fd);
	unset_fd();

	if (address.length() )
		state = cs_retry_timeout;
	else state = cs_inactive;
}

int connection::handle_ssl_error (int ret)
{
	int e = SSL_get_error (ssl, ret);

	switch (e) {
	case SSL_ERROR_WANT_READ:
		poll_set_remove_write (fd);
		break;
	case SSL_ERROR_WANT_WRITE:
		poll_set_add_write (fd);
		break;
	case SSL_ERROR_ZERO_RETURN:
		return 1; //SSL closed correctly.
	default:
		Log_error ("Get SSL error %d, ret=%d!", e, ret);
		{
			int err;
			while (err = ERR_get_error() ) Log_error
				("on conn %d SSL_ERR %d: %s; func %s; reason %s",
				 id, err,
				 ERR_lib_error_string (err),
				 ERR_func_error_string (err),
				 ERR_reason_error_string (err) );
		}
		return e;
	}

	return 0;
}

/*
 * polls
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
	switch (state) {
	case cs_connecting:
		try_connect();
		break;
	case cs_closing:
		try_close();
		break;
	case cs_retry_timeout:
		if ( (timestamp() - last_retry) > retry) start_connect();
		break;
	case cs_active:
		if ( (timestamp() - last_ping) > timeout) disconnect();
		else if ( (timestamp() - sent_ping_time) > keepalive) send_ping();
		try_read();
	}
}

/*
 * SSL alloc/dealloc
 */

int connection::alloc_ssl()
{
	dealloc_ssl();

	bio = BIO_new_socket (fd, BIO_NOCLOSE);
	if (!bio) {
		Log_fatal ("creating SSL/BIO object failed, something's gonna die.");
		return 1;
	}

	ssl = SSL_new (ssl_ctx);
	SSL_set_bio (ssl, bio, bio);

	if (!ssl) {
		Log_fatal ("creating SSL object failed! something is gonna die.");
		dealloc_ssl(); //at least free the BIO
		return 1;
	}

	return 0;
}

void connection::dealloc_ssl()
{
	if (ssl) {
		SSL_free (ssl);
		ssl = 0;
		bio = 0;
	} else if (bio) {
		BIO_free (bio);
		bio = 0;
	}
}

/*
 * connection object must always be created with ID; if not, warn.
 */

connection::connection()
{
	Log_fatal ("connection at %p instantiated without ID", this);
	Log_fatal ("... That should never happen. Not terminating,");
	Log_fatal ("... but expect weird behavior and/or segfault.");

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

int comm_init()
{
	int t;

	if (!config_get_int ("max_connections", t) ) max_connections = 1024;
	else max_connections = t;
	Log_info ("max connections count is %d", max_connections);

	if (!config_get_int ("listen_backlog", t) ) listen_backlog_size = 32;
	else listen_backlog_size = t;
	Log_info ("listen backlog size is %d", listen_backlog_size);

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
	 * push those who shall connect to connect
	 */

	map<int, connection>::iterator i;
	list<int> to_delete;

	for (i = connections.begin();i != connections.end();++i) {
		i->second.periodic_update();
		if (i->second.state == cs_inactive)
			to_delete.push_back (i->first);
	}

	while (to_delete.size() ) {
		Log_info ("removing connection id %d", to_delete.front() );
		connections.erase (to_delete.front() );
		to_delete.pop_front();
	}
}

void comm_broadcast_route_update (uint8_t*data, int n)
{
	Log_info ("broadcasting route update, size %d", n);
	map<int, connection>::iterator i;
	for (i = connections.begin();i != connections.end();++i)
		if (i->second.state == cs_active)
			i->second.write_route_diff (data, n);
}

