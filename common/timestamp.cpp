
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

#define __TIMESTAMP_CPP__
#include "timestamp.h"

#include <sys/time.h>

void timestamp_update()
{
	struct timeval tv;
	gettimeofday (&tv, 0);
	timestamp_lasttime =
	    (1000000 * (uint64_t) tv.tv_sec)
	    + (uint64_t) tv.tv_usec;
}

static struct ts_initializer_t {
	ts_initializer_t() {
		timestamp_update();
	}
} ts_initializer;

