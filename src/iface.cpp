
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
#include "utils.h"
#include "conf.h"
#include "poll.h"
#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
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

static string format_mac_addr (uint8_t*addr)
{
	string r;
	int t;
	r.reserve (hwaddr_size + hwaddr_digits - 1);

	for (int i = 0;i < hwaddr_digits;++i) {
		if (i && (! (i % 2) ) ) r.append (1, ':');

		t = (addr[i/2] >> ( (i % 2) ? 4 : 0) ) & 0xF;

		if (t < 10) r.append (1, '0' + t);
		else r.append (1, 'A' + t);
	}

	return r;
}

/*
 * variables
 */

int tun = -1;
char iface_name[IFNAMSIZ] = "";

/*
 * initialization
 */

#if defined (__linux__)

int iface_create()
{
	if (!config_is_true ("iface") ) {
		Log_info ("not creating local interface");
		return 0; //no need
	}

	struct ifreq ifr;

	int ctl_fd;

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
			          format_mac_addr (hwaddr).c_str() );

			if (iface_set_hwaddr (hwaddr) )
				Log_error ("iface: setting hwaddr failed, using default");
		} else Log_warn ("iface: `%s' is not a valid mac address, using default");
	} else iface_retrieve_hwaddr (0); //only cache the mac

	Log_info ("iface: initialized OK");

	poll_set_add_read (tun);

	route_set_dirty();

	return 0;
}

#elif defined (BSD) || defined (TARGET_DARWIN)

int iface_create()
{
	if (!config_is_true ("iface") ) {
		Log_info ("not creating local interface");
		return 0; //no need
	}

	string device = "/dev/tap0";
	config_get_string ("iface_device", device);
	Log_info ("using `%s' as interface device", device.c_str() );

	if ( (tun = open (device.c_str(), O_RDWR | O_NONBLOCK) ) < 0) {
		Log_error ("iface: cannot open tap device with %d: %s",
		           errno, strerror (errno) );
		return -1;
	}

	//from here it's just similar to linux.

	if (config_is_set ("mac") ) { //set mac address
		uint8_t hwaddr[hwaddr_size];
		string mac;
		config_get ("mac", mac);

		if (read_mac_addr (mac.c_str(), hwaddr) ) {
			Log_info ("iface: setting hwaddr %s",
			          format_mac_addr (hwaddr).c_str() );

			if (iface_set_hwaddr (hwaddr) )
				Log_error ("iface: setting hwaddr failed, using default");
		} else Log_warn ("iface: `%s' is not a valid mac address, using default");
	} else iface_retrieve_hwaddr (0); //only cache the mac

	Log_info ("iface: initialized OK");

	poll_set_add_read (tun);

	route_set_dirty();

	return 0;
}

#else

#warning "No tun/tap backend available for this platform."
#warning "Compiling without support for virtual network interface!"

int iface_create()
{
	return 0;
}

#endif

/*
 * hwaddr set/get
 */

//BSD compatibility
#ifndef SIOCSIFHWADDR
# define SIOCSIFHWADDR SIOCSIFLLADDR
#endif
#ifndef SIOCGIFHWADDR
# define SIOCGIFHWADDR SIOCGIFLLADDR
#endif

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

/*
 * releasing the interface
 */

int iface_destroy()
{
	if (tun < 0) return 0; //already closed
	int ret;

	Log_info ("destroying local interface");

	if (ret = close (tun) ) {
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

		if (ret <= 0) break;

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

