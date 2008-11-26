
#include "comm.h"
#include "conf.h"
#include "log.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <string.h>

#include <string>

using namespace std;

static map<int, connection> connections;
static list<int> listeners;

/*
 * NOTICE (FUKKEN IMPORTANT)
 * because of good pollability, connections shall be IDed by their socket fds.
 */

map<int, connection>& comm_connections()
{
	return connections;
}

list<int> comm_listeners()
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

int tcp_listen_socket (const string&addr)
{
	return -1;
}

int tcp_connect_socket (const string&addr)
{
	return -1;
}

int tcp_accept (int sock)
{
	return -1;
}

/*
 * class connection stuff
 */

int connection::flush()
{
	return 0;
}

int connection::write (void*buf, int len)
{
	return 0;
}

int connection::read (void*buf, int len)
{
	return 0;
}

int connection::write_packet (void*buf, int len)
{
	return 0;
}

int connection::write_broadcast_packet (uint32_t id, void*buf, int len)
{
	return 0;
}

void connection::update()
{

}

void connection::disconnect()
{

}

/*
 * comm_ stuff
 */

int comm_init()
{
	if (ssl_initialize() ) {
		Log_fatal ("SSL initialization failed");
		return 1;
	}
	return 0;
}

int comm_shutdown()
{
	if (ssl_destroy() )
		Log_warn ("SSL shutdown failed!");
	return 0;
}

/*
 * update_connections helper
 * When a connection gets reconnected, it usually has a new sockfd.
 * The operation reindexes only badly placed connections, so
 * it's generally fast enough. (O(n)+O(bad*log(n)))
 *
 * Should be called everytime a connection changes socket fd.
 *
 * Also checks for no-longer-active connections and deletes them.
 */

int comm_update_connections()
{

	return 0;
}
