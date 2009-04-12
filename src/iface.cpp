
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


#include "iface.h"

#include "route.h"
#include "conf.h"
#include "poll.h"
#include "log.h"

#ifndef __WIN32__

//probable incompatibility notice
#include "utils.h"
#if ( ! defined (__BSD__) ) &&\
	( ! defined (__darwin__) ) &&\
	( ! defined (__linux__) )
# warning "Compiling with generic TAP driver usage."
# warning "This probably won't even work."
# warning "If you will be able to communicate via the TAP device using"
# warning "CloudVPN, a miracle has happened and you should report it to"
# warning "the developers, along with description of your configuration."
#endif

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

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CLEAR(x) memset(&(x),0,sizeof(x))

#define hwaddr_digits (2*hwaddr_size)

static uint8_t cached_hwaddr[hwaddr_size];

const uint8_t* iface_cached_hwaddr()
{
	return cached_hwaddr;
}

static bool read_mac_addr (const char*b, uint8_t*addr)
{
	int digits = 0, res;

	while ( (*b) && (digits < hwaddr_digits) ) {
		res = -1;

		if ( (*b >= '0') && (*b <= '9') ) res = *b - '0';
		else if ( (*b >= 'A') && (*b <= 'F') ) res = *b - 'A' + 10;
		else if ( (*b >= 'a') && (*b <= 'f') ) res = *b - 'a' + 10;

		if (res >= 0) {
			addr[digits/2] |= res << ( (digits % 2) ? 4 : 0);
			++digits;
		}

		++b;
	}

	if (digits == hwaddr_digits) return true;
	else return false;
}

/*
 * variables
 */

int tun = -1;
char iface_name[IFNAMSIZ] = "";

/*
 * initialization
 */

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
	if (!config_is_true ("iface") ) {
		Log_info ("not creating local interface");
		return 0; //no need
	}

	struct ifreq ifr;

	string tun_dev = "/dev/net/tun";

	config_get ("tunctl", tun_dev);

	if ( (tun = open (tun_dev.c_str(), O_RDWR) ) < 0) {
		Log_error ("iface: cannot open `%s'", tun_dev.c_str() );
		return 1;
	}

	CLEAR (ifr);

	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if (config_is_set ("iface_dev") ) {
		string d;
		config_get ("iface_dev", d);
		strncpy (ifr.ifr_name, d.c_str(), IFNAMSIZ);
		Log_info ("iface: using interface name `%s'", d.c_str() );
	} else Log_info ("iface: using default interface name");

	if (
	    (ioctl (tun, TUNSETIFF, &ifr) < 0) ||
	    (ioctl (tun, TUNSETPERSIST,
	            config_is_true ("iface_persist") ? 1 : 0) < 0) ) {
		Log_error ("iface: cannot configure tap device");
		close (tun);
		tun = -1;
		return 2;
	}

	strncpy (iface_name, ifr.ifr_name, IFNAMSIZ); //store for later use

	CLEAR (ifr);

	//set nonblocking mode. Please note that failing this IS fatal.

	if (!sock_nonblock (tun) ) {
		Log_fatal ("iface: sock_nonblock failed on fd %d, probably terminating.");
		close (tun);
		tun = -1;
		return 3;
	}

	if (config_is_set ("mac") ) { //set mac address
		uint8_t hwaddr[hwaddr_size];
		string mac;
		config_get ("mac", mac);

		if (read_mac_addr (mac.c_str(), hwaddr) ) {
			Log_info ("iface: setting hwaddr %s",
			          format_hwaddr (hwaddr).c_str() );

			if (iface_set_hwaddr (hwaddr) )
				Log_error ("iface: setting hwaddr failed, using default");
		} else Log_warn ("iface: `%s' is not a valid mac address, using default");
	} else iface_retrieve_hwaddr (0); //only cache the mac

	Log_info ("iface: initialized OK");

	poll_set_add_read (tun);

	route_set_dirty();

	iface_command (1);

	return 0;
}

#else

int iface_create()
{
	if (!config_is_true ("iface") ) {
		Log_info ("not creating local interface");
		return 0; //no need
	}

	string device = "tap0";
	config_get ("iface_device", device);
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
		uint8_t hwaddr[hwaddr_size];
		string mac;
		config_get ("mac", mac);

		if (read_mac_addr (mac.c_str(), hwaddr) ) {
			Log_info ("iface: setting hwaddr %s",
			          format_hwaddr (hwaddr).c_str() );

			if (iface_set_hwaddr (hwaddr) )
				Log_error ("iface: setting hwaddr failed, using default");
		} else Log_warn ("iface: `%s' is not a valid mac address, using default");
	} else iface_retrieve_hwaddr (0); //only cache the mac

	Log_info ("iface: initialized OK");

	poll_set_add_read (tun);

	route_set_dirty();

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

	for (int i = 0;i < hwaddr_size;++i)
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

	for (int i = 0;i < hwaddr_size;++i)
		cached_hwaddr[i] = ifr.ifr_hwaddr.sa_data[i];

	Log_info ("iface has mac address %02x:%02x:%02x:%02x:%02x:%02x",
	          cached_hwaddr[0],
	          cached_hwaddr[1],
	          cached_hwaddr[2],
	          cached_hwaddr[3],
	          cached_hwaddr[4],
	          cached_hwaddr[5]);

	if (!hwaddr) return 0;

	for (int i = 0;i < hwaddr_size;++i)
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

	for (int i = 0;i < hwaddr_size;++i)
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

			struct sockaddr_dl *sdp =
						    (struct sockaddr_dl*) (p->ifa_addr);

			memcpy (cached_hwaddr, sdp->sdl_data + sdp->sdl_nlen, 6);

			Log_info ("iface has mac address %02x:%02x:%02x:%02x:%02x:%02x",
			          cached_hwaddr[0],
			          cached_hwaddr[1],
			          cached_hwaddr[2],
			          cached_hwaddr[3],
			          cached_hwaddr[4],
			          cached_hwaddr[5]);

			if (hwaddr) memcpy (hwaddr,
				                    sdp->sdl_data + sdp->sdl_nlen, 6);

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

#include "route.h"

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

		if (ret <= 2 + (2*hwaddr_size) ) {
			Log_debug ("iface_update: discarding packet too short for Ethernet");
			continue;
		}

		route_packet (buffer, ret);
	}
}

void iface_poll_write()
{
	/*
	 * not used,
	 * if the OS tap queue somehow overflows, discarding packet is
	 * considered a good solution.
	 */
}

int iface_get_sockfd()
{
	return tun;
}


#else //__WIN32__

int iface_create()
{
	if (config_is_true ("iface") ) {
		Log_fatal ("Win32 doesn't support TAP interfaces yet!");
		return 1;
	}
	return 0;
}

int iface_destroy()
{
	return 0;
}

int iface_write (void*buf, size_t len)
{
	return 0;
}

int iface_read (void*buf, size_t maxlen)
{
	return 0;
}

int iface_set_hwaddr (uint8_t*hw)
{
	return 0;
}

int iface_retrieve_hwaddr (uint8_t*hw)
{
	return 0;
}

const uint8_t* iface_cached_hwaddr()
{
	return 0;
}

void iface_poll_read()
{
}

void iface_poll_write()
{
}

int iface_get_sockfd()
{
	return -1;
}


#endif
