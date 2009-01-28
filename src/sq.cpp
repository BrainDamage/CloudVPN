
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
#include "log.h"
#include "conf.h"

#include <algorithm>
using namespace std;

/*
 * pbuffer
 */

void pbuffer::push (const uint8_t*d, size_t size)
{
	b.reserve (b.size() + size);
	copy (d, d + size, back_insert_iterator<vector<uint8_t> > (b) );
}

/*
 * squeue stuff
 *
 * - fill the vector buffer, provide direct access to it
 * - pop things from the front, leave the space there
 * - if we think that realloc is feasible (when len() is zero)
 *   we remove the unused front.
 */

#define squeue_max_free_size 4096
#define squeue_back_free_space 1024

static int squeue_max_alloc = 4194304;

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
		copy (d.begin() + front, d.begin() + back, d.begin() );
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

