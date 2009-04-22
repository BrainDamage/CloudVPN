
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

#include "timestamp.h"

#include <sys/time.h>

static uint64_t lasttime;

uint64_t timestamp()
{
	return lasttime;
}

void timestamp_update()
{
	struct timeval tv;
	gettimeofday (&tv, 0);
	lasttime = (1000000 * tv.tv_sec) + tv.tv_usec;
}

static struct ts_initializer_t {
	ts_initializer_t() {
		timestamp_update();
	}
} ts_initializer;

