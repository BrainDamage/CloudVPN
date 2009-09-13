
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

#ifdef DISABLE_LIBEV

/*
 * The Dumb Fallback.
 *
 * This backend doesn't really do any polling, just periodically
 * pokes all given FDs.
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
#include <vector>
using std::set;
using std::vector;
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


#else

/*
 * libev engine
 */

#include <ev.h>

int poll_init()
{
	return 0;
}

int poll_deinit()
{
	return 0;
}

int poll_set_add_read (int fd)
{
	return 0;
}

int poll_set_add_write (int fd)
{
	return 0;
}

int poll_set_remove_read (int fd)
{
	return 0;
}

int poll_set_remove_write (int fd)
{
	return 0;
}

int poll_set_clear()
{
	return 0;
}

int poll_wait_for_event (int timeout_usec)
{
	return 0;
}


#endif
