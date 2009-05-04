
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

/*
 * Stun Proxy, also known as stunconn. Part of CloudVPN.
 *
 * configuration:
 *
 * listen, forward: local addresses to listen/connect. Pick only one.
 * key: shared key to use for stunconn
 * stunconn: some address to stunconn server.
 */

#include "sq.h"
#define LOGNAME "stunproxy"
#include "log.h"
#include "conf.h"
#include "network.h"
#include "timestamp.h"

#include <stdint.h>

#include <map>
#include <set>
using namespace std;

bool forwarder; //false if we are listener

int udp_fd = -1, local_fd = -1;
bool waiting_for_connect;
bool tunnel_up;
bool local_up; //otherwise local listening

sockaddr_type tunnel_addr;
uint64_t last_tunnel_activity;

map<uint32_t, pbuffer>sent_parts;
map<uint32_t, pbuffer>recvd_parts;
set<uint32_t>acks_to_send;
uint32_t send_head, recv_head;

void reset()
{
	udp_fd = -1;
	local_fd = -1;
	local_up = tunnel_up = waiting_for_connect = false;
	last_tunnel_activity = 0;
	sent_parts.clear();
	recvd_parts.clear();
	acks_to_send.clear();
	send_head = recv_head = 0;
}

void tunnel_establish()
{

}

void tunnel_send_keepalive()
{

}

int get_external_ip()
{

}

int get_peer_ip()
{

}

void start_local_accept()
{

}

void accept_local()
{

}

void connect_local()
{

}

void tunnel_try_start_transfer()
{

}

void process_data()
{

}

int wait_and_poll()
{

}

int init()
{
	reset();
}

int shutdown()
{
	reset();
}

int main()
{
	return 0;
}
