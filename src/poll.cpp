
#include "poll.h"

#include "log.h"
#include "timestamp.h"

/*
 * Polling implementations are conditionally compiled, usually the best one
 * available for given platform gets into.
 *
 * Available:
 *
 * epoll device
 * select()
 *
 * epoll is "default", to use select() please define CVPN_POLL_USE_SELECT
 */

/*
 * poll_handle_event()
 * function that poll implementations call on detected activity
 */

#define READ_READY 0
#define WRITE_READY 1
#define EXCEPTION_READY 2

static void poll_handle_event(int fd, int what)
{
	//TODO locate the fd, touch it in the right way.
}

/*
 * now the polling engines
 */

#ifdef CVPN_POLL_USE_SELECT

/*
 * select() polling engine
 */

#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <set>
using namespace std;
static set<int> fds_read, fds_write;

int poll_init()
{
	//not much
	return 0;
}

int poll_deinit()
{
	//also not much
	return 0;
}

int poll_set_add_read(int fd)
{
	fds_read.insert(fd);
	return 0;
}

int poll_set_remove_read(int fd)
{
	fds_read.erase(fd);
	return 0;
}

int poll_set_add_write(int fd)
{
	fds_write.insert(fd);
	return 0;
}

int poll_set_remove_write(int fd)
{
	fds_write.erase(fd);
	return 0;
}

int poll_set_clear(int fd)
{
	fds_read.clear();
	fds_write.clear();
	return 0;
}

int poll_wait_for_event (int timeout)
{
	fd_set read,write,except;
	set<int>::iterator i;
	
	FD_ZERO(&read);
	FD_ZERO(&write);
	FD_ZERO(&except);

	int n=1;
	for(i=fds_read.begin();i!=fds_read.end();++i) {
		FD_SET(*i,&read);
		FD_SET(*i,&except);
		++n;
	}
	for(i=fds_write.begin();i!=fds_write.end();++i) {
		FD_SET(*i,&write);
		if(!FD_ISSET(*i,&read))++n; //not very probable, but be sure.
	}

	struct timeval time={timeout/1000000,timeout%1000000};

	if(select(n,&read,&write,&except,&time)<0){
		int e=errno;
		if(e==EINTR){
			Log_info("select() interrupted");
			return 0;
		}

		Log_error("select() failed with errno %d",e);
		return 1;
	}

	timestamp_update(); //we probably waited some time here.

	/*
	 * Note that this order of write -> exception -> read
	 * operations is intended (prevents queue limit bumps a little better)
	 */

	for(i=fds_write.begin();i!=fds_write.end();++i) {
		if(FD_ISSET(*i,&write))
			poll_handle_event(*i,WRITE_READY);
	}
	for(i=fds_read.begin();i!=fds_read.end();++i) {
		if(FD_ISSET(*i,&except))
			poll_handle_event(*i,EXCEPTION_READY);
		if(FD_ISSET(*i,&read))
			poll_handle_event(*i,READ_READY);
	}

	timestamp_update(); //sending/receiving can also eat time.

	return 0;
}

#else

/*
 * epoll engine
 */

int poll_init()
{
	//not much
	return 0;
}

int poll_deinit()
{
	//also not much
	return 0;
}

int poll_set_add_read(int fd)
{
	return 0;
}

int poll_set_remove_read(int fd)
{
	return 0;
}

int poll_set_add_write(int fd)
{
	return 0;
}

int poll_set_remove_write(int fd)
{
	return 0;
}

int poll_set_clear(int fd)
{
	return 0;
}

int poll_wait_for_event (int timeout)
{
	return 0;
}

#endif

