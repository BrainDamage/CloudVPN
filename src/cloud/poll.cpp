
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

#include "poll.h"

#define LOGNAME "cloud/poll"
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
 * USE_EPOLL epoll device on Linuxes
 * USE_KQUEUE kqueue on BSD
 * USE_POLL poll (if defined(HAVE_POLL))
 * USE_SELECT select()
 * USE_DUMB_POLL dumb poll (just try polling with some intervals)
 */

#if 	(!USE_EPOLL) && \
	(!USE_KQUEUE) && \
	(!USE_POLL) && \
	(!USE_SELECT) && \
	(!USE_DUMB_POLL)

#if defined(__linux__)
#undef USE_EPOLL
#define USE_EPOLL 1
#endif

#if (defined(__FreeBSD__)||defined(__OpenBSD__)||defined(__NetBSD__))
#undef USE_KQUEUE
#define USE_KQUEUE 1
#endif

#ifdef __darwin__ //this is suggested on MACs
#undef USE_SELECT
#define USE_SELECT 1
#endif

#endif //all USE_*

#ifdef __WIN32__
#undef USE_DUMB_POLL
#define USE_DUMB_POLL 1
#endif

/*
 * poll_handle_event()
 * function that poll implementations call on detected activity
 */

#define READ_READY (1<<0)
#define WRITE_READY (1<<1)
#define EXCEPTION_READY (1<<2)

#include "comm.h"
#include "gate.h"

static void poll_handle_event (int fd, int what)
{
	if (!what) return;

	map<int, int>::iterator id;

	/*
	 * gate&comm lookups have roughly the same frequency, but there's
	 * usually much smaller set of gates; so they go first.
	 *
	 * listener lookups can be solved last, because of low freq.
	 */

	id = gate_index().find (fd);

	if (id != gate_index().end() ) {
		map<int, gate>::iterator g = gate_gates().find (id->second);
		if (g == gate_gates().end() ) return;
		if (what&WRITE_READY) g->second.poll_write();
		if (what& (READ_READY | EXCEPTION_READY) ) g->second.poll_read();
		return;
	}

	id = comm_connection_index().find (fd);


	if (id != comm_connection_index().end() ) {
		map<int, connection>::iterator
		con = comm_connections().find (id->second);

		if (con == comm_connections().end() ) return;

		if (what&WRITE_READY)
			con->second.poll_write();
		if (what& (READ_READY | EXCEPTION_READY) )
			con->second.poll_write();
		return;
	}

	set<int>::iterator lis;

	lis = comm_listeners().find (fd);

	if (lis != comm_listeners().end() ) {
		comm_listener_poll (fd);
		return;
	}

	lis = gate_listeners().find (fd);
	if (lis != gate_listeners().end() ) {
		gate_listener_poll (fd);
		return;
	}

	Log_info ("polled a nonexistent fd %d!", fd);
}

/*
 * now the polling engines
 */

#if USE_DUMB_POLL

/*
 * The Dumb Fallback.
 * If no other engines are available, just use this.
 *
 * This backend doesn't really do any polling, just periodically
 * pokes given FDs.
 *
 * Note that it eats CPU, even if idle!
 */

#include "conf.h"

#ifdef __WIN32__
#include <windows.h>
#else
#include <unistd.h>
#endif

#include <set>
using std::set;
set<int>read_set, write_set;

static int interval = 5000;
/*
 * 5 ms is pretty good even for gamers,
 * and isn't-that-much-cpu-squeezing.
 */

int poll_init()
{
	bool r = config_get_int ("poll_interval", interval);
	Log_info ("poll interval %s to %d usec", r ? "set" : "defaults", interval);

	read_set.clear();
	write_set.clear();
	return 0;
}

int poll_deinit()
{
	return 0;
}

int poll_set_add_read (int fd)
{
	read_set.insert (fd);
	return 0;
}

int poll_set_add_write (int fd)
{
	write_set.insert (fd);
	return 0;
}

int poll_set_remove_read (int fd)
{
	read_set.erase (fd);
	return 0;
}

int poll_set_remove_write (int fd)
{
	write_set.erase (fd);
	return 0;
}

int poll_set_clear()
{
	read_set.clear();
	write_set.clear();
	return 0;
}

int poll_wait_for_event (int timeout_usec)
{
	/*
	 * Let's
	 * a] poke all active connections
	 * 	- we need to create copies, because
	 * 	  connections can invalidate our iterators
	 * b] sleep a little
	 * c] return
	 */

	vector<int>
	r (read_set.begin(), read_set.end() ),
	w (write_set.begin(), write_set.end() );

	vector<int>::iterator i;
	for (i = r.begin();i != r.end();++i)
		poll_handle_event (*i, READ_READY);
	for (i = w.begin();i != w.end();++i)
		poll_handle_event (*i, WRITE_READY);

#ifdef __WIN32__
	Sleep (interval / 1000);
#else
	usleep (interval);
#endif

	return 0;
}


#elif USE_EPOLL

/*
 * epoll engine
 */

#include <sys/epoll.h>
#include <errno.h>

int epfd = -1;

int poll_init()
{
	Log_info ("using epoll polling");
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

#include <string.h>

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
	for (i = 0;i < ret;++i) poll_handle_event (ev[i].data.fd,
		        ( (ev[i].events & EPOLLOUT) ? WRITE_READY : 0) |
		        ( (ev[i].events & EPOLLIN) ? READ_READY : 0) |
		        ( (ev[i].events & (EPOLLHUP | EPOLLERR) )
		          ? EXCEPTION_READY : 0) );

	return 0;
}

#elif USE_KQUEUE

/*
 * kqueue default for *BSD
 *
 * thanks to jmmv and his blog, I used it.
 *
 * This is untested an unusuable until someone wraps the iface for BSD
 */

#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>

static int kq = -1;

#include <vector>
#include <map>
using namespace std;

map<int, int> ev;

#define ev_read 1
#define ev_write 2

int poll_init()
{
	kq = kqueue();
	if (kq < 0) return 1;
	return 0;
}

int poll_deinit()
{
	close (kq);
	kq = -1;
	poll_set_clear();
	return 0;
}

static struct timespec timespec_zero = {0, 0};

#define kevent_set(kq,fd,flags,filter) \
({struct kevent k; EV_SET(&k,(fd),(filter),(flags),0,0,&timespec_zero);\
kevent((kq),&k,1,0,0,0);})

#define ke_filter(i) {int ke_filter_t=(i);\
	(((ke_filter_t&ev_read)?EVFILT_READ:0)\
	((ke_filter_t&ev_write)?EVFILT_WRITE:0))

int poll_set_add_read (int fd)
{
	int t = ev[fd] |= ev_read;
	return kevent_set (kq, fd, EV_ADD, EVFILT_READ) >= 0;
}

int poll_set_add_write (int fd)
{
	int t = ev[fd] |= ev_write;
	return kevent_set (kq, fd, EV_ADD, EVFILT_WRITE) >= 0;
}

int poll_set_remove_read (int fd)
{
	int t = ev[fd] &= ~ev_read;
	if (!t) ev.erase (fd);
	return (kevent_set (kq, fd, EV_DELETE, EVFILT_READ) >= 0);
}

int poll_set_remove_write (int fd)
{
	int t = ev[fd] &= ~ev_read;
	if (!t) ev.erase (fd);
	return kevent_set (kq, fd, EV_DELETE, EVFILT_WRITE) >= 0;
}

int poll_set_clear()
{
	int t;
	while (ev.size() ) {
		t = ev.begin()->second;
		if (t&ev_read)
			kevent_set (kq, ev.begin()->first, EV_DELETE, EVFILT_READ);
		if (t&ev_write)
			kevent_set (kq, ev.begin()->first, EV_DELETE, EVFILT_WRITE);
		ev.erase (ev.begin() );
	}
}

int poll_wait_for_event (int timeout_usec)
{
	vector<struct kevent> buf;
	int size = ev.size();
	struct timespec ts = {timeout_usec / 1000000,
		1000* (timeout_usec % 1000000)
	};  //it's {seconds,nanoseconds}

	buf.resize (size); //alloc space

	int ret = kevent (kq, 0, 0, buf.begin().base(), size, &ts);

	if (!ret) return 0;
	if (ret < 0) {
		if (errno == EINTR) {
			Log_info ("kevent() interrupted by a signal");
			return 0;
		} else {
			Log_info ("kevent() failed with errno %d", errno);
			return 1;
		}
	}

	//ok now we see that some events are present.

	vector<struct kevent>::iterator i = buf.begin(), e = i + ret;

	for (;i < e;++i) poll_handle_event
		(i->ident,
		 ( (i->filter&EVFILT_READ) ? READ_READY : 0) |
		 ( (i->filter&EVFILT_WRITE) ?  WRITE_READY : 0) );

	return 0;
}

#elif USE_POLL

/*
 * poll.h poll(), fallback number one.
 */

#include <sys/poll.h>
#include <errno.h>

#include <map>
#include <vector>
using namespace std;

static map<int, int> fdi;
static vector<struct pollfd> fds;

static struct pollfd* get_fd (int fd) {
	if (fdi.count (fd) )
		return & (fds[fdi[fd]]);

	struct pollfd tmp;
	fds.push_back (tmp);
	fds.back().fd = fd;
	fdi[fd] = fds.size() - 1;
	return & (fds.back() );
}

static void remove_fd (int fd)
{
	if (!fdi.count (fd) ) return;
	int p = fdi[fd];
	fdi.erase (fd);
	fds[p] = fds.back(); //overwrite by tail
	fds.pop_back(); //remove tail
}

int poll_init()
{
	Log_info ("using poll() polling");
	return 0;
}

int poll_deinit()
{
	return poll_set_clear();
}

int poll_set_add_read (int fd)
{
	get_fd (fd)->events |= POLLIN | POLLERR;
	return 0;
}

int poll_set_add_write (int fd)
{
	get_fd (fd)->events |= POLLOUT;
	return 0;
}

int poll_set_remove_read (int fd)
{
	struct pollfd* f = get_fd (fd);
	f->events &= ~ (POLLIN | POLLERR);
	if (! (f->events) ) remove_fd (fd);
	return 0;
}

int poll_set_remove_write (int fd)
{
	struct pollfd* f = get_fd (fd);
	f->events &= ~POLLOUT;
	if (! (f->events) ) remove_fd (fd);
	return 0;
}

int poll_set_clear()
{
	fds.clear();
	fdi.clear();
	return 0;
}

int poll_wait_for_event (int usec)
{
	int ret = poll (fds.begin().base(), fds.size(), usec / 1000);

	timestamp_update();

	if (ret < 0) {
		if (errno == EINTR) {
			Log_info ("poll() interrupted");
			return 0;
		} else {
			Log_info ("poll() failed with errno %d", errno);
			return 1;
		}
	}
	if (!ret) return 0; //nothing important happened

	vector<struct pollfd>::iterator i;
	for (i = fds.begin();i < fds.end();++i) if (i->revents)
			poll_handle_event (i->fd,
			                   ( (i->revents | POLLIN) ? READ_READY : 0) |
			                   ( (i->revents | POLLOUT) ? WRITE_READY : 0) |
			                   ( (i->revents | POLLERR) ? EXCEPTION_READY : 0) );

	return 0;
}

#elif USE_SELECT

/*
 * select() polling engine, fallback number two (last)
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
	Log_info ("using select() polling");
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
#error "no poll backend specified"
#endif
