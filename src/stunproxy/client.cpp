
/*
 * Stun Proxy, also known as stunconn. Part of CloudVPN.
 *
 * configuration:
 *
 * listen, forward: local addresses to connect
 * key: shared key to use for stunconn
 * stunconn: some address to stunconn server.
 */

#include "sq.h"
#include "log.h"
#include "conf.h"
#include "network.h"
#include "timestamp.h"

#include <stdint.h>

int udp_fd, proxy_fd;

class conn
{
public:
	int fd;
	int id;

	//sending part
	uint32_t next_send_packet;
	uint64_t last_send_time;
	map<uint32_t, pbuffer> waiting_acks;

	//receiving part
	uint32_t next_recv_packet;
	uint64_t last_recv_time;
	map<uint32_t, puffer>recvd;
};

map<int, conn>conns;


int handle_udp()
{

}

int handle_connect()
{

}

int handle_accept()
{

}

int stun_request()
{

}

int http_request()
{

}

int wait_and_poll()
{

}

int init()
{

}

int shutdown()
{

}

int main()
{
	return 0;
}
