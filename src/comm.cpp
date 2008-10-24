
#include "comm.h"
#include "conf.h"
#include "log.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <string.h>

#include <string>
using namespace std;

static map<int,connection> connections;
static set<int> listeners;

/*
 * NOTICE
 * because of good pollability, connections shall be IDed by their socket fds.
 */

const map<int,connection>& comm_connections()
{
	return connections;
}

const set<int> comm_listeners()
{
	return listeners;
}

/*
 * SSL stuff
 */

static SSL_CTX* ssl_ctx;
static string ssl_pass;

static int ssl_password_callback(char*buffer,int num, int rwflag, void*udata)
{
	if(num<ssl_pass.length()+1){
		Log_warn("ssl_pw_cb: supplied buffer too small");
		return 0;
	}
	strcpy(buffer,ssl_pass.c_str());
	return ssl_pass.length();
}

static int initialize_ssl()
{
	SSL_METHOD* meth;

	string keypath,certpath,capath;
	if( (!config_get("key",keypath)) ||
		(!config_get("cert",certpath)) ||
		(!config_get("ca_cert",capath)))
	{
		Log_fatal("init_ssl: you must correctly specify key, cert and ca_cert options");
		return 1;
	}
		

	SSL_library_init();
	SSL_load_error_strings();

	//TODO, maybe signal(sigpipe) here? no idea why.
	
	meth=SSLv23_method();
	ssl_ctx=SSL_CTX_new(meth);
	SSL_CTX_set_options(ssl_ctx,SSL_OP_NO_SSLv2); //stay as safe as we can

	SSL_CTX_set_default_passwd_cb(ssl_ctx,ssl_password_callback);

	return 0;
}

int comm_init()
{
}

int comm_shutdown()
{
}

int comm_update(int sockfd)
{
}

