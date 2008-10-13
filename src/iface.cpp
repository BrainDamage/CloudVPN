
#include "iface.h"
#include "conf.h"

#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>

#define CLEAR(x) memset(&(x),0,sizeof(x))

int tun = -1;
char iface_name[IFNAMSIZ]="";

bool iface_create()
{
	if (!config_is_true ("iface") ) return true; //no need

	struct ifreq ifr;
	int ctl_fd;

	string tun_dev = "/dev/net/tun";
	config_get ("tunctl", tun_dev);

	if ( (tun = open (tun_dev.c_str(), O_RDWR) ) < 0)
		return false;
	
	CLEAR (ifr);

	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if (config_is_set ("iface_dev") ) {
		string d;
		config_get ("iface_dev", d);
		strncpy (ifr.ifr_name, d.c_str(), IFNAMSIZ);
	}

	if (
		(ioctl (tun, TUNSETIFF, &ifr) < 0) ||
		(ioctl (tun, TUNSETPERSIST,
			config_is_true ("iface_persist") ? 1 : 0) < 0) ) {
		close (tun);
		tun = -1;
		return false;
	}

	strncpy(iface_name,ifr.ifr_name,IFNAMSIZ); //store for later use

	CLEAR (ifr);

	if(config_is_set("mac")) {
		//TODO set default HW address
	}

	//TODO set nonblocking mode

	return true;
}

int iface_set_hwaddr(uint8_t*hwaddr)
{
	struct ifreq ifr;
	
	int ctl=socket(AF_INET,SOCK_DGRAM,0);
	if(ctl<0)return 1;
	
	CLEAR(ifr);
	strncpy(ifr.ifr_name,iface_name,IFNAMSIZ);
	for(int i=0;i<hwaddr_size;++i)
		ifr.ifr_hwaddr.sa_data[i]=hwaddr[i];
	
	int ret=ioctl(ctl, SIOCSIFHWADDR, &ifr);
	close(ctl);
	return (ret>=0)?0:2;
}

int iface_retrieve_hwaddr(uint8_t*hwaddr)
{
	struct ifreq ifr;
	
	int ctl=socket(AF_INET,SOCK_DGRAM,0);
	if(ctl<0)return 1;
	
	CLEAR(ifr);
	strncpy(ifr.ifr_name,iface_name,IFNAMSIZ);
	int ret=ioctl(ctl, SIOCSIFHWADDR, &ifr);
	close(ctl);
	if(ret<0)return 2;
	for(int i=0;i<hwaddr_size;++i)
		hwaddr[i]=ifr.ifr_hwaddr.sa_data[i];
	return 0;
}

void iface_destroy()
{
	if (tun >= 0) close (tun);
}

/*
int main()
{
	struct ifreq ifr,netifr;
	int fd, err, res, ctl_fd, i;
	uint64_t addr;
	char buffer[8192];


	if( (fd = open("/dev/net/tun", O_RDWR)) < 0 )
		return 1;

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if( ((err = ioctl(fd, TUNSETIFF, (void *) &ifr))) < 0 ){
		close(fd);
		return err;
	}
	printf("%s\n",ifr.ifr_name);

	memset(&netifr,0,sizeof(netifr));
	strncpy(netifr.ifr_name, ifr.ifr_name, IFNAMSIZ);
	ctl_fd=socket(AF_INET,SOCK_DGRAM,0);
	if(ctl_fd<0)return 1;
	if(ioctl(ctl_fd,SIOCGIFHWADDR, &netifr)<0)return 2;
	addr=0;
	memcpy(&addr,&(netifr.ifr_hwaddr.sa_data[0]),6);
	printf("%06lx\n",addr);

	while(1) {
		res=read(fd,buffer,8192);
		if(res<=0) return 0;
		printf("got a packet, %d (%x) bytes\n---\n",res,res);
		write(STDOUT_FILENO,buffer,res);
		printf("\n---\n");
		for(i=0;i<res;++i)printf("%02hhx ",buffer[i]);
		printf("\n\n");
	}

	return 0;
}
*/
