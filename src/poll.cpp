
#include "poll.h"

#include "log.h"
#include "timestamp.h"

/*
 * Polling implementations are conditionally compiled, usually the best one
 * available for given platform gets into.
 *
 * Please note that epoll_set_remove_* should be called WAAAYYY before the
 * sock/fd is closed. otherwise data corruption may appear.
 *
 * Available backends:
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

static void poll_handle_event (int fd, int what)
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

int poll_set_add_read (int fd)
{
	fds_read.insert (fd);
	return 0;
}

int poll_set_remove_read (int fd)
{
	fds_read.erase (fd);
	return 0;
}

int poll_set_add_write (int fd)
{
	fds_write.insert (fd);
	return 0;
}

int poll_set_remove_write (int fd)
{
	fds_write.erase (fd);
	return 0;
}

int poll_set_clear (int fd)
{
	fds_read.clear();
	fds_write.clear();
	return 0;
}

int poll_wait_for_event (int timeout)
{
	fd_set read, write, except;
	set<int>::iterator i;

	FD_ZERO (&read);
	FD_ZERO (&write);
	FD_ZERO (&except);

	int n = 1;
	for (i = fds_read.begin();i != fds_read.end();++i) {
		FD_SET (*i, &read);
		FD_SET (*i, &except);
		++n;
	}
	for (i = fds_write.begin();i != fds_write.end();++i) {
		FD_SET (*i, &write);
		if (!FD_ISSET (*i, &read) ) ++n; //be sure
	}

	struct timeval time = {timeout / 1000000, timeout % 1000000};

	if (select (n, &read, &write, &except, &time) < 0) {
		int e = errno;
		if (e == EINTR) {
			Log_info ("select() interrupted");
			return 0;
		}

		Log_error ("select() failed with errno %d", e);
		return 1;
	}

	timestamp_update(); //we probably waited some time here.

	/*
	 * Note that this order of write -> exception -> read
	 * operations is intended (prevents queue limit bumps a little better)
	 */

	for (i = fds_write.begin();i != fds_write.end();++i) {
		if (FD_ISSET (*i, &write) )
			poll_handle_event (*i, WRITE_READY);
	}
	for (i = fds_read.begin();i != fds_read.end();++i) {
		if (FD_ISSET (*i, &except) )
			poll_handle_event (*i, EXCEPTION_READY);
		if (FD_ISSET (*i, &read) )
			poll_handle_event (*i, READ_READY);
	}

	return 0;
}

#else

/*
 * epoll engine
 */

#include <sys/epoll.h>
#include <errno.h>

int epfd = -1;

int poll_init()
{
	epfd = epoll_create (128);
	if (epfd < 0) return 1;
	return 0;
}

int poll_deinit()
{
	if (epfd < 0) {
		Log_warn ("trying to close uninitialized epoll");
		return 1;
	}
	if (close (epfd) ) {
		Log_error ("closing epoll failed");
		return 2;
	}
	epfd = -1;
	return 0;
}

#include <map>
using std::map;

static map<int, int> fdmap;

#define mask_read 1
#define mask_write 2

static int epoll_set_update (int fd, int mask)
{
	if (!mask) {
		fdmap.erase (fd);
		if (epoll_ctl (epfd, EPOLL_CTL_DEL, fd, 0) )
			if (errno != ENOENT) {
				Log_warn ("removing fd %d from epoll failed, forgetting it anyway", fd);
				return 1;
			}
		return 0;
	}

	struct epoll_event ev;

	memset (&ev, 0, sizeof (ev) );

	ev.data.fd = fd;
	ev.events = ( (mask & mask_read) ? (EPOLLIN | EPOLLERR | EPOLLHUP) : 0)
	            | ( (mask & mask_write) ? (EPOLLOUT) : 0);

	//try the more probable possibility of ctl_mod/add first, fallback.
	if (fdmap.count (fd) ) {
		if (epoll_ctl (epfd, EPOLL_CTL_MOD, fd, &ev) ) {
			if (errno != ENOENT) {
				Log_warn ("epoll ctl_mod on fd %d failed", fd);
				return 2;
			} else if (epoll_ctl (epfd, EPOLL_CTL_ADD, fd, &ev) ) {
				Log_warn ("fallback epoll ctl_add on fd %d failed", fd);
				return 3;
			}
		}
	} else {
		if (epoll_ctl (epfd, EPOLL_CTL_ADD, fd, &ev) ) {
			if (errno != EEXIST) {
				Log_warn ("epoll ctl_add on fd %d failed", fd);
				return 4;
			} else if (epoll_ctl (epfd, EPOLL_CTL_MOD, fd, &ev) ) {
				Log_warn ("fallback epoll ctl_mod on fd %d failed", fd);
				return 5;
			}
		}
	}

	fdmap[fd] = mask;
	return 0;
}

static int epoll_set_get (int fd)
{
	if (!fdmap.count (fd) ) return 0;
	return fdmap[fd];
}

int poll_set_add_read (int fd)
{
	int t = epoll_set_get (fd);
	if (t&mask_read) return 0;
	return epoll_set_update (fd, t | mask_read);
}

int poll_set_remove_read (int fd)
{
	int t = epoll_set_get (fd);
	if (t&mask_read) return epoll_set_update (fd, t& (~mask_read) );
	return 0;
}

int poll_set_add_write (int fd)
{
	int t = epoll_set_get (fd);
	if (t&mask_write) return 0;
	return epoll_set_update (fd, t | mask_write);
}

int poll_set_remove_write (int fd)
{
	int t = epoll_set_get (fd);
	if (t&mask_write) return epoll_set_update (fd, t& (~mask_write) );
	return 0;
}

int poll_set_clear (int fd)
{
	while (fdmap.size() > 0)
		epoll_set_update (fdmap.begin()->first, 0);
	return 0;
}

int poll_wait_for_event (int timeout)
{
	int n = fdmap.size(), ret;

	if (n < 8) n = 8;
	if (n > 128) n = 128;

	struct epoll_event ev[n];

	ret = epoll_wait (epfd, ev, n, timeout / 1000); //convert timeout to msec

	timestamp_update();

	if (ret < 0) {
		int e = errno;
		if (e == EINTR) Log_info ("epoll_wait() interrupted");
		else Log_error ("epoll_wait failed with errno %d", e);
		return 1;
	}

	int i;
	for (i = 0;i < ret;++i)
		if (ev[i].events & EPOLLOUT)
			poll_handle_event (ev[i].data.fd, WRITE_READY);
	for (i = 0;i < ret;++i) {
		if (ev[i].events & (EPOLLHUP | EPOLLERR) )
			poll_handle_event (ev[i].data.fd, EXCEPTION_READY);
		if (ev[i].events & EPOLLIN)
			poll_handle_event (ev[i].data.fd, READ_READY);
	}
	return 0;
}

#endif

