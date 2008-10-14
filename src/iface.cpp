
#include "iface.h"
#include "conf.h"
#include "log.h"

#include <errno.h>
#include <fcntl.h>
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

static bool read_mac_addr (const char*b, uint8_t*addr)
{
	int digits = 0, res;
	while ( (*b) && (digits < 12) ) {
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
	if (digits == 12) return true;
	else return false;
}

static string format_mac_addr (uint8_t*addr)
{
	string r;
	int t;
	r.reserve (17);
	for (int i = 0;i < 12;++i) {
		if (i && (! (i % 2) ) ) r.append (1, ':');
		t = (addr[i/2] >> ( (i % 2) ? 4 : 0) ) & 0xF;
		if (t < 10) r.append (1, '0' + t);
		else r.append (1, 'A' + t);
	}
	return r;
}

static bool set_nonblock (int fd)
{
	return fcntl (fd, F_SETFL, O_NONBLOCK) >= 0;
}

int tun = -1;
char iface_name[IFNAMSIZ] = "";

bool iface_create()
{
	if (!config_is_true ("iface") ) return true; //no need

	struct ifreq ifr;
	int ctl_fd;

	string tun_dev = "/dev/net/tun";
	config_get ("tunctl", tun_dev);

	if ( (tun = open (tun_dev.c_str(), O_RDWR) ) < 0) {
		Log_error ("iface: cannot open `%s'", tun_dev.c_str() );
		return false;
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
		return false;
	}

	strncpy (iface_name, ifr.ifr_name, IFNAMSIZ); //store for later use

	CLEAR (ifr);

	//set nonblocking mode. Please note that failing this IS fatal.
	if (!set_nonblock (tun) ) {
		Log_fatal ("iface: set_nonblock failed on fd %d, probably terminating.");
		close (tun);
		tun = -1;
		return false;
	}

	if (config_is_set ("mac") ) { //set mac address
		uint8_t hwaddr[6];
		string mac;
		config_get ("mac", mac);
		if (read_mac_addr (mac.c_str(), hwaddr) ) {
			Log_info ("iface: setting hwaddr %s",
				  format_mac_addr (hwaddr).c_str() );
			if (iface_set_hwaddr (hwaddr) )
				Log_error ("iface: setting hwaddr failed, using default");
		} else Log_warn ("iface: `%s' is not a valid mac address, using default");
	}

	Log_info ("iface: initialized OK");

	return true;
}

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
	if (ret < 0) Log_error ("iface_set_hwaddr: ioctl failed with %d (%s)", errno, strerror (errno) );
	return (ret >= 0) ? 0 : 2;
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
	int ret = ioctl (ctl, SIOCSIFHWADDR, &ifr);
	if (ret < 0) {
		Log_error ("iface_retrieve_hwaddr: ioctl failed with %d (%s)", errno, strerror (errno) );
		close (ctl);
		return 2;
	}
	close (ctl);

	for (int i = 0;i < hwaddr_size;++i)
		hwaddr[i] = ifr.ifr_hwaddr.sa_data[i];
	return 0;
}

void iface_destroy()
{
	if (tun >= 0) {
		int ret;
		if (ret = close (tun) )
			Log_error ("iface_destroy: close(%d) failed with %d (%s). this may cause errors later.", tun, errno, strerror (errno) );
	}
	tun = -1;
}

bool is_hwaddr_broadcast (uint8_t*hwaddr)
{
	/*
	 * According to the specification, ff:ff:ff:ff:ff:ff IS broadcast, but
	 * other (with least significant bit of first byte set to 1) are kind
	 * of multicast. For simplicity, we are handling them as broadcast too.
	 */
	return (hwaddr[0]&1);
}

int iface_write (void*buf, size_t len)
{
	int res = write (tun, buf, len);
	if (res < 0) {
		if (errno == EAGAIN) return 0;
		else {
			Log_error ("iface: write failure %d (%s)",
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

