
#include "comm.h"

#include "conf.h"
#include "log.h"
#include "poll.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <string.h>

#include <list>
using namespace std;

list<connection> inactive_connections;
static map<int, connection> connections;
static set<int> listeners;

/*
 * NOTICE (FUKKEN IMPORTANT)
 * because of good pollability, connections MUST be IDed by their socket fds.
 */

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
	struct sockaddr sa;
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
	struct sockaddr sa;
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
 * This should accept a connection, and link it into the structure.
 * Generally, only these 2 functions really create connections.
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

	connection&c = connections[s];
	c.fd = s;
	c.state = cs_accepting;

	c.try_accept(); //bump the connection, so it sets its poll state
	
	return 0;
}

static int connect_connection (const string&addr)
{
	connection c;
	
	c.fd = -1;
	c.address = addr;
	c.state = cs_retry_timeout;
	c.last_retry = 0; //asap
	
	inactive_connections.push_back (c);
	
	Log_info ("connecting to `%s'", addr.c_str() );

	return 0;
}

/*
 * class connection stuff
 */

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

void connection::poll_read()
{
}

void connection::poll_write()
{
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
	string t;
	if (config_get ("listen_backlog", t) ) {
		if (sscanf (t.c_str(), "%d", &listen_backlog_size) != 1) {
			Log_error ("specified listen_backlog is not an integer");
			return 1;
		}
	} else listen_backlog_size = 32;

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
	if (ssl_destroy() )
		Log_warn ("SSL shutdown failed!");

	if (comm_listeners_close() )
		Log_warn ("closing of some listening sockets failed!");

	if (comm_connections_close() )
		Log_warn ("closing of some connections failed!");

	return 0;
}

