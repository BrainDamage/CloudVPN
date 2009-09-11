
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

#include "sq.h"
#define LOGNAME "common/sq"
#include "log.h"
#include "conf.h"


/*
 * as the standard library doesnt seem to have a function with determinable
 * copying direction, we have this. No idea why bcopy() is marked deprecated.
 *
 * also: TURN OPTIMIZATION ON, everyone!
 * This WILL copy ALL your data, so we need it at least equal to assembler.
 */

uint8_t* sq_memcpy (uint8_t*dst, const uint8_t*src, size_t size)
{
	size_t i;
	if (dst < src) {
		for (i = 0;i < size;++i) dst[i] = src[i];
	} else {
		for (i = size - 1;i >= 0;--i) dst[i] = src[i];
	}
	return dst;
}

/*
 * pbuffer
 */

void pbuffer::push (const uint8_t*d, size_t size)
{
	uint8_t*dest = b.end().base();
	b.resize (b.size() + size);
	sq_memcpy (dest, d, size);
}

void pbuffer::shift (size_t len)
{
	if (len >= b.size() ) b.clear();
	else {
		sq_memcpy (b.begin().base(),
		           b.begin().base() + len,
		           b.size() - len);
		b.resize (b.size() - len);
	}
}

/*
 * pusher
 *
 * thing that is used only for filling bytestreams.
 */

void pusher::push (const uint8_t*p, size_t size)
{
	sq_memcpy (d, p, size);
	d += size;
}

/*
 * squeue stuff
 *
 * - fill the vector buffer, provide direct access to it
 * - pop things from the front, leave the space there
 * - if we think that realloc is feasible (when len() is zero)
 *   we remove the unused front.
 */

#define squeue_max_free_size 0x10000
#define squeue_back_free_space 0x1000

static int squeue_max_alloc = 0x1000000; //max allocated space, 16M

uint8_t* squeue::get_buffer (size_t size)
{
	if (d.size() < back + size) realloc (size);
	if (d.size() < back + size) return 0;
	return end();
}

void squeue::realloc (size_t size)
{
	if ( !len() ) {  //flush to begin
		front = back = 0;
	} else if (front > squeue_max_free_size) { //move closer to start
		sq_memcpy (d.begin().base(),
		           d.begin().base() + front,
		           back - front);
		back -= front;
		front = 0;
	}

	if (	(d.size() < back + size) || //too short
	        (d.size() > squeue_max_free_size + back + size) ) { //too long

		size_t t = back + size + squeue_back_free_space;
		if (t > (size_t) squeue_max_alloc) t = squeue_max_alloc;
		d.resize (t);  //resize
	}
}

void squeue_init()
{
	config_get_int ("max_input_queue_size", squeue_max_alloc);
	Log_info ("maximal input queue size is %d bytes", squeue_max_alloc);
}

