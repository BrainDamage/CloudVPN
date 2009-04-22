
#include "network.h"


#include <fcntl.h>
#include <unistd.h>


bool sock_nonblock (int fd)
{
#ifndef __WIN32__
	return fcntl (fd, F_SETFL, O_NONBLOCK) >= 0;
#else
	u_long a = 1;
	return ioctlsocket (fd, FIONBIO, &a) >= 0;
#endif
}

