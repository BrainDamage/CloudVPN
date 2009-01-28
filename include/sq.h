
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

#ifndef _CVPN_SQ_H
#define _CVPN_SQ_H

/*
 * Socket Queue
 */

#include <vector>
#include <deque>
using namespace std;

#include <stdint.h>


class pbuffer
{
public:
	vector<uint8_t> b;
	inline void clear() {
		b.clear();
	}
	inline int len() const {
		return b.size();
	}
	void push (const uint8_t*, size_t);
	void push (const pbuffer&);
	template<class T> inline void push (const T&a) {
		b.reserve (sizeof (a) + b.size() );
		push ( (uint8_t*) &a, sizeof (a) );
	}
};

void squeue_init();

class squeue
{
public:
	size_t front, back;
	vector<uint8_t> d;

	inline void clear() {
		front = back = 0;
		d.clear();
	}

	explicit inline squeue() {
		clear();
	}

	inline size_t len() {
		return back -front;
	}

	inline uint8_t*begin() {
		return d.begin().base() + front;
	}
	inline void read (size_t size) {
		front += size;
		if (front > back) front = back;
	}

	inline uint8_t*end() {
		return d.begin().base() + back;
	}

	uint8_t*get_buffer (size_t size);

	inline void append (size_t size) {
		back += size;
		if (back > d.size() ) back = d.size();
	};

	void realloc (size_t reserve_size = 0);

	template<class T> inline void pop (T&t) {
		if (len() < sizeof (T) ) return;
		t = * (T*) begin();
		read (sizeof (T) );
	}
};

#endif

