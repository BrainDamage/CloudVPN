
#include "comm.h"

#include "conf.h"
#include "log.h"
#include "poll.h"

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
 * SSL stuff
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

//TODO, maybe signal(sigpipe) here? no idea why.

	meth = SSLv23_method();
	ssl_ctx = SSL_CTX_new (meth);
	SSL_CTX_set_options (ssl_ctx, SSL_OP_NO_SSLv2);

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

/*
 * connection creation helper
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
	while ( (i < max_connections) && ci != connections.end() ) {
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
	connections[i] = connection (i);
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

	c.try_accept(); //bump the thing

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

	connection&c = connections[cid];

	c.state = cs_retry_timeout;
	c.last_retry = 0;
	c.address = addr;

	return 0;
}

/*
 * class connection stuff
 */

void connection::index()
{
	conn_index[fd] = id;
}

void connection::deindex()
{
	conn_index.erase (fd);
}

void connection::handle_packet (void*buf, int len)
{
}

void connection::handle_broadcast_packet (uint32_t id, void*buf, int len)
{
}

void connection::handle_route_set()
{
}

void connection::handle_route_diff()
{
}

void connection::handle_ping (uint32_t id)
{
}

void connection::handle_pong (uint32_t id)
{
}

void connection::write_packet (void*buf, int len)
{
}

void connection::write_broadcast_packet (uint32_t id, void*buf, int len)
{
}

void connection::write_route_set()
{
}

void connection::write_route_diff()
{
}

void connection::write_ping (uint32_t id)
{
}

void connection::write_pong (uint32_t id)
{
}

void connection::try_read()
{
}

void connection::try_write()
{
}

void connection::try_accept()
{
}

void connection::try_connect()
{
}

void connection::try_close()
{
}

void connection::start_connect()
{
}

void connection::poll_read()
{
}

void connection::poll_write()
{
}

void connection::periodic_update()
{
}

/*
 * connection object must always be created with ID; if not, warn.
 */

connection::connection()
{
	Log_fatal ("connection at %p instantiated without ID", this);
	Log_fatal ("... That should never happen. Not terminating,");
	Log_fatal ("... but expect weird behavior and/or segfault.");
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
	//TODO maybe do something if this fails
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
	 * TODO: wait (with some timeout) for all connections to close.
	 * This involves calling disconnect() on every active connection,
	 * do some poll cycle, and periodically clean inactive connections.
	 */
}

/*
 * base comm_ stuff
 */

int comm_init()
{
	int t;

	if (!config_get_int ("max_connections", t) ) max_connections = 1024;
	Log_info ("max connections count is %d", max_connections);

	if (!config_get_int ("listen_backlog", t) ) listen_backlog_size = 32;
	Log_info ("listen backlog size is %d", listen_backlog_size);

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
}

