
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

#include "sq.h"
#define LOGNAME "eth-unix"
#include "log.h"
#include "conf.h"
#include "address.h"
#include "network.h"
#include "sighandler.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifdef __linux__
# include <linux/if.h>
# include <linux/if_tun.h>
#else
# include <net/if.h>
# include <net/if_arp.h>
# include <net/if_tun.h>
#endif

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CLEAR(x) memset(&(x),0,sizeof(x))

int tun = -1;
char iface_name[IFNAMSIZ] = "";
address cached_hwaddr (0, (const uint8_t*) "123456", 6); //no matter it doesnt work.

int iface_set_hwaddr (uint8_t*hwaddr);
int iface_retrieve_hwaddr (uint8_t*hwaddr);
void send_route();
void send_packet (uint8_t*data, int size);

void iface_command (int which)
{
	string cmd;
	const char*c;

	switch (which) {
	case 1:
		c = "iface_up_cmd";
		break;
	case 2:
		c = "iface_down_cmd";
		break;
	default:
		return;
	}

	if (config_get (c, cmd) ) {
		Log_info ("iface setup command returned %d",
		          system (cmd.c_str() ) );
	}
}

#if defined (__linux__)

int iface_create()
{
	struct ifreq ifr;

	string tun_dev = "/dev/net/tun";

	config_get ("tunctl", tun_dev);

	if ( (tun = open (tun_dev.c_str(), O_RDWR) ) < 0) {
		Log_error ("cannot open `%s'", tun_dev.c_str() );
		return 1;
	}

	CLEAR (ifr);

	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if (config_is_set ("iface_dev") ) {
		string d;
		config_get ("iface_dev", d);
		strncpy (ifr.ifr_name, d.c_str(), IFNAMSIZ);
		Log_info ("using interface name `%s'", d.c_str() );
	} else Log_info ("using default interface name");

	if (
	    (ioctl (tun, TUNSETIFF, &ifr) < 0) ||
	    (ioctl (tun, TUNSETPERSIST,
	            config_is_true ("iface_persist") ? 1 : 0) < 0) ) {
		Log_error ("cannot configure tap device");
		close (tun);
		tun = -1;
		return 2;
	}

	strncpy (iface_name, ifr.ifr_name, IFNAMSIZ); //store for later use

	CLEAR (ifr);

	//set nonblocking mode. Please note that failing this IS fatal.

	if (!sock_nonblock (tun) ) {
		Log_fatal ("iface: sock_nonblock failed on fd %d, probably terminating.", tun);
		close (tun);
		tun = -1;
		return 3;
	}

	if (config_is_set ("mac") ) { //set mac address
		address new_mac;
		string mac;
		config_get ("mac", mac);
		if (new_mac.scan_addr (mac.c_str() )
		        && (new_mac.addr.size() == 6) ) {

			Log_info ("setting hwaddr %s",
			          new_mac.format_addr().c_str() );

			if (iface_set_hwaddr (new_mac.addr.begin().base() ) )
				Log_error ("setting hwaddr failed, using default");
		} else Log_warn ("`%s' is not a valid mac address, using default", mac.c_str() );
	} else iface_retrieve_hwaddr (0); //only cache the mac

	Log_info ("iface initialized OK");

	send_route();

	iface_command (1);

	return 0;
}

#else

int iface_create()
{
	string device = "tap0";
	config_get ("iface_dev", device);
	Log_info ("using `%s' as interface", device.c_str() );

	tun = open ( ("/dev/" + device).c_str(), O_RDWR | O_NONBLOCK);
	if (tun < 0) {
		Log_error ("iface: cannot open tap device with %d: %s",
		           errno, strerror (errno) );
		return -1;
	}

#ifdef __OpenBSD__
	if (0 > ioctl (tun, FIONBIO) ) {
		Log_error ("iface: ioctl(FIONBIO) failed with %d: %s",
		           errno, strerror (errno) );
		close (tun);
		return -2;
	}
#endif

	strncpy (iface_name, device.c_str(), IFNAMSIZ);

	//from here it's just similar to linux.

	if (config_is_set ("mac") ) { //set mac address
		address new_mac;
		string mac;
		config_get ("mac", mac);
		if (new_mac.scan_addr (mac.c_str() )
		        && (new_mac.addr.size() == 6) ) {

			Log_info ("setting hwaddr %s",
			          new_mac.format_addr().c_str() );

			if (iface_set_hwaddr (new_mac.addr.begin().base() ) )
				Log_error ("setting hwaddr failed, using default");
		} else Log_warn ("`%s' is not a valid mac address, using default", mac.c_str() );
	} else iface_retrieve_hwaddr (0); //only cache the mac

	Log_info ("iface: initialized OK");

	send_route();

	iface_command (1);

	return 0;
}

#endif

/*
 * hwaddr set/get
 */

#if defined (__linux__)

int iface_set_hwaddr (uint8_t*hwaddr)
{
	struct ifreq ifr;

	int ctl = socket (AF_INET, SOCK_DGRAM, 0);

	if (ctl < 0) {
		Log_error ("iface_set_hwaddr: creating socket failed with %d (%s)", errno, strerror (errno) );
		return 1;
	}

	CLEAR (ifr);

	strncpy (ifr.ifr_name, iface_name, IFNAMSIZ);

	for (int i = 0;i < 6;++i)
		ifr.ifr_hwaddr.sa_data[i] = hwaddr[i];

	int ret = ioctl (ctl, SIOCSIFHWADDR, &ifr);

	close (ctl);

	if (ret < 0) {
		Log_error ("iface_set_hwaddr: ioctl failed with %d (%s)", errno, strerror (errno) );
		return 2;
	}

	iface_retrieve_hwaddr (0);

	return 0;
}

int iface_retrieve_hwaddr (uint8_t*hwaddr)
{

	struct ifreq ifr;

	int ctl = socket (AF_INET, SOCK_DGRAM, 0);

	if (ctl < 0) {
		Log_error ("iface_retrieve_hwaddr: creating socket failed with %d (%s)", errno, strerror (errno) );
		return 1;
	}

	CLEAR (ifr);

	strncpy (ifr.ifr_name, iface_name, IFNAMSIZ);
	int ret = ioctl (ctl, SIOCGIFHWADDR, &ifr);
	close (ctl);


	if (ret < 0) {
		Log_error ("iface_retrieve_hwaddr: ioctl failed with %d (%s)", errno, strerror (errno) );
		close (ctl);
		return 2;
	}

	for (int i = 0;i < 6;++i)
		cached_hwaddr.addr[i] = ifr.ifr_hwaddr.sa_data[i];

	Log_info ("iface has mac address %s", cached_hwaddr.format_addr().c_str() );

	if (!hwaddr) return 0;

	for (int i = 0;i < 6;++i)
		hwaddr[i] = ifr.ifr_hwaddr.sa_data[i];

	return 0;
}

#else //FreeBSD or OSX

#include <netinet/if_ether.h>

int iface_set_hwaddr (uint8_t*addr)
{
	// this function might work on linux too. Try to merge.

	union {
		struct ifreq ifr;
		struct ether_addr e;
	};

	int ctl = socket (AF_INET, SOCK_DGRAM, 0);

	if (ctl < 0) {
		Log_error ("iface_set_hwaddr: creating socket failed with %d (%s)", errno, strerror (errno) );
		return 1;
	}

	CLEAR (ifr);

	strncpy (ifr.ifr_name, iface_name, IFNAMSIZ);

	ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;
	ifr.ifr_addr.sa_family = AF_LINK;

	for (int i = 0;i < 6;++i)
#ifndef __OpenBSD__
		e.octet[i]
#else
		e.ether_addr_octet[i]
#endif
		= addr[i];

	int ret = ioctl (ctl, SIOCSIFLLADDR, &ifr);

	close (ctl);

	if (ret < 0) {
		Log_error ("iface_set_hwaddr: ioctl failed with %d (%s)", errno, strerror (errno) );
		return 2;
	}

	iface_retrieve_hwaddr (0);

	return 0;
}

#include <ifaddrs.h>
#include <net/if_dl.h>

int iface_retrieve_hwaddr (uint8_t*hwaddr)
{
	struct ifaddrs *ifap, *p;

	if (getifaddrs (&ifap) ) {
		Log_error ("getifaddrs() failed. expect errors");
		return 1;
	}

	for (p = ifap;p;p = p->ifa_next)
		if ( (p->ifa_addr->sa_family == AF_LINK) &&
		        (!strncmp (p->ifa_name, iface_name, IFNAMSIZ) ) ) {

			struct sockaddr_dl *sdp;
			sdp = (struct sockaddr_dl*) (p->ifa_addr);

			cached_hwaddr.set (0,
			                   (uint8_t*) (sdp->sdl_data + sdp->sdl_nlen), 6);

			Log_info ("iface has mac address %s", cached_hwaddr.format_addr().c_str() );

			if (hwaddr)
				memcpy (hwaddr, sdp->sdl_data + sdp->sdl_nlen, 6);

			freeifaddrs (ifap);
			return 0;
		}

	freeifaddrs (ifap);
	Log_error ("no link address found for interface. expect errors");
	return 1;
}

#endif

/*
 * releasing the interface
 */

int iface_destroy()
{
	if (tun < 0) return 0; //already closed
	int ret;

	iface_command (2);

	Log_info ("destroying local interface");

	if ( (ret = close (tun) ) ) {
		Log_error ("iface_destroy: close(%d) failed with %d (%s). this may cause trouble elsewhere.", tun, errno, strerror (errno) );
		return 1;
	}

	tun = -1;

	return 0;
}

/*
 * I/O
 */

int iface_write (void*buf, size_t len)
{
	if (tun < 0) return 0;
	int res = write (tun, buf, len);

	if (res < 0) {
		if (errno == EAGAIN) return 0;
		else {
			Log_warn ("iface: write failure %d (%s)",
			          errno, strerror (errno) );
			return -1;
		}
	}

	return res;
}

int iface_read (void*buf, size_t len)
{
	int res = read (tun, buf, len);

	if (res < 0) {
		if (errno == EAGAIN) return 0;
		else {
			Log_error ("iface: read failure %d (%s)",
			           errno, strerror (errno) );
			return -1;
		}
	}

	return res;
}

void iface_poll_read()
{
	if (tun < 0) {
		Log_error ("iface_update: tun not configured");
		return;
	}

	char buffer[4096];

	int ret;

	while (1) {
		ret = iface_read (buffer, 4096);

		if (ret <= 0) return;

		if (ret <= 2 + (2*6) ) {
			Log_debug ("iface_update: discarding packet too short for Ethernet");
			continue;
		}

		send_packet ( (uint8_t*) buffer, ret);
	}
}

/*
 * CloudVPN GATE part
 */

int gate = -1;
bool promisc = false;

uint16_t inst = 0xDEFA;
uint16_t proto = 0xE78A;

uint8_t cached_header_type = 0;
uint16_t cached_header_size = 0;


squeue recv_q;
squeue send_q;
#define send_q_max 1024*1024 //let this be enough for everyone

void send_route();
int gate_poll_write();
void gate_disconnect();

void gate_init()
{
	int t;
	if (config_get_int ("instance", t) ) inst = t;
	if (config_get_int ("proto", t) ) proto = t;
	if (config_is_true ("promisc") ) promisc = true;
}

int gate_connect()
{
	string s;
	if (!config_get ("gate", s) ) {
		Log_fatal ("please specify a gate");
		return -1;
	}

	gate = tcp_connect_socket (s.c_str() );
	if (gate < 0) {
		Log_fatal ("cannot open a connection to gate");
		gate = -1;
		return 1;
	}

	fd_set w;
	FD_ZERO (&w);
	FD_SET (gate, &w);
	struct timeval to;
	to.tv_sec = 30;
	to.tv_usec = 0;

	int r;

	if ( (r = select (gate + 1, 0, &w, 0, &to) ) <= 0) {
		Log_fatal ("Connection to gate timed out");
		gate_disconnect();
		return 2;
	}

	int err;
	if ( (err = sock_get_error (gate) ) != 0) {
		Log_fatal ("Connection to fd failed with %d", -err);
		gate_disconnect();
		return 3;
	}

	Log_info ("gate connected OK");
	send_route(); //announce our wishes

	return (gate > 0) ? 0 : 4;
}

void gate_disconnect()
{
	Log_info ("disconnecting gate");
	tcp_close_socket (gate);
	gate = -1;
	cached_header_type = 0;
	send_q.clear();
	recv_q.clear();
}

void send_route()
{
	if (gate < 0) return;
	if (send_q.len() > send_q_max) return;
	if (cached_hwaddr.addr.size() != 6) {
		Log_info ("bad hwaddr");
		return;
	}

	uint8_t*b = send_q.append_buffer (3);
	*b = 2;
	* (uint16_t*) (b + 1) = htons (12 + (promisc ? 6 : 0) );
	b = send_q.append_buffer (12 + (promisc ? 6 : 0) );
	* (uint16_t*) (b) = htons (6);
	* (uint32_t*) (b + 2) = htonl ( (proto << 16) | inst);
	copy (cached_hwaddr.addr.begin(),
	      cached_hwaddr.addr.end(), b + 6);
	if (promisc) {
		b += 12;
		* (uint16_t*) (b) = htons (0);
		* (uint32_t*) (b + 2) = htonl ( (proto << 16) | inst);
	}
	gate_poll_write();
}

void send_keepalive()
{
	if (gate < 0) return;
	if (send_q.len() > send_q_max) return;
	uint8_t*b = send_q.append_buffer (3);
	*b = 1;
	* (uint16_t*) (b + 1) = 0;
	gate_poll_write();
}

void send_packet (uint8_t*data, int size)
{
	if (gate < 0) return;
	if (send_q.len() > send_q_max) return;
	if (size < 14) return;
	uint8_t*b = send_q.append_buffer (3 + 14 + size);
	*b = 3;
	* (uint16_t*) (b + 1) = htons (14 + size);
	b += 3;
	* (uint32_t*) (b) = htonl ( (proto << 16) | inst);
	* (uint16_t*) (b + 4) = htons (0);//dof
	* (uint16_t*) (b + 6) = htons (6);//ds
	* (uint16_t*) (b + 8) = htons (6);//sof
	* (uint16_t*) (b + 10) = htons (6);//ss
	* (uint16_t*) (b + 12) = htons (size);
	memcpy (b + 14, data, size);
	gate_poll_write();
}

void handle_keepalive()
{
	send_keepalive();
}

void handle_packet (uint8_t*data, int size)
{
	uint32_t instance;
	uint16_t dof, ds, sof, ss, s;
	if (size < 28) return;
	instance = ntohl (* (uint32_t*) (data) );
	dof = ntohs (* (uint16_t*) (data + 4) );
	ds = ntohs (* (uint16_t*) (data + 6) );
	sof = ntohs (* (uint16_t*) (data + 8) );
	ss = ntohs (* (uint16_t*) (data + 10) );
	s = ntohs (* (uint16_t*) (data + 12) );

	if (instance != (uint32_t) ( (proto << 16) | inst) ) return;
	if ( (dof != 0) || (ds != 6) || (sof != 6) || (ss != 6) ) return;
	if (s < 14) return;
	iface_write (data + 14, s);
}

void try_parse_input()
{
	while (1) {
		if (!cached_header_type) {
			if (recv_q.len() < 3) return;
			recv_q.pop<uint8_t> (cached_header_type);
			recv_q.pop<uint16_t> (cached_header_size);
			cached_header_size = ntohs (cached_header_size);
		}
		switch (cached_header_type) {
		case 1: //keepalive
			handle_keepalive();
			recv_q.read (cached_header_size);
			cached_header_type = 0;
			break;
		case 3: //packet
			if (recv_q.len() < cached_header_size) //need more
				return;
			handle_packet (recv_q.begin(), cached_header_size);
			recv_q.read (cached_header_size);
			cached_header_type = 0;
			break;
		default:
			Log_error ("received invalid packet");
			gate_disconnect();
			return;
		}
	}
}

int gate_poll_read()
{
	int r;
	uint8_t*b;
	while (1) {
		if (gate < 0) return 1;

		b = recv_q.get_buffer (8192);
		if (!b) return 0; //out of memory, just wait with receiving.
		r = recv (gate, b, 8192, 0);
		if (r == 0) {
			gate_disconnect();
			return 1;
		}
		if (r < 0) {
			if (errno == EAGAIN) return 0;
			gate_disconnect();
			return 1;
		}
		recv_q.append (r);
		try_parse_input();
	}
}

int gate_poll_write()
{
	int r;
	while (send_q.len() ) {
		r = send (gate, send_q.begin(), send_q.len(), 0);
		if (r == 0) {
			gate_disconnect();
			return 1;
		}
		if (r < 0) {
			if (errno == EAGAIN) return 0;
			gate_disconnect();
			return 1;
		}
		send_q.read (r);
	}
	return 0;
}

/*
 * main part
 */

int do_poll()
{
	if (gate < 0) return 1;

	fd_set r, w, e;
	struct timeval to;

	to.tv_sec = 3;
	to.tv_usec = 141592;

	FD_ZERO (&r);
	FD_ZERO (&w);
	FD_ZERO (&e);
	FD_SET (gate, &r);
	if (send_q.len() ) FD_SET (gate, &w);
	FD_SET (gate, &e);
	FD_SET (tun, &r);
	FD_SET (tun, &e);

	int res = select (gate > tun ? gate + 1 : tun + 1, &r, &w, &e, &to);
	if (res <= 0) return res ? 1 : 0;

	if (FD_ISSET (tun, &r) ) iface_poll_read();
	if (FD_ISSET (gate, &w) ) gate_poll_write();
	if (FD_ISSET (gate, &r) || FD_ISSET (gate, &e) ) gate_poll_read();

	return 0;
}

int g_terminate = 0;
void kill_gate (int signum)
{
	Log_info ("killed by signal %d, will terminate", signum);
	g_terminate = 1;
}

int main (int argc, char**argv)
{
	setup_sighandler (kill_gate);

	if (!config_parse (argc, argv) ) {
		Log_error ("failed to parse config");
		return 1;
	}

	squeue_init();
	network_init();
	gate_init();

	if (iface_create() ) {
		Log_fatal ("cannot create tun/tap iface");
		return 2;
	}

	while (!g_terminate) {
		if (gate < 0) { //try connection
			if (gate_connect() ) {
				if (g_terminate) break;
				Log_info ("gate reconnection in 10s");
				struct timeval to = {10, 0};
				select (0, 0, 0, 0, &to); //reconnection timeout
			}
		} else { //try some work
			if (do_poll() ) {
				Log_error ("polling failed, reconnecting gate.");
				gate_disconnect();
			}
		}
	}

	iface_destroy();

	return 0;
}

