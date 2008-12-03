
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
	void push (const uint8_t*, int);
	void push (const pbuffer&);
	template<class T> inline void push (const T&a) {
		b.reserve (sizeof (a) + b.size() );
		push ( (uint8_t*) &a, sizeof (a) );
	}
};

class squeue
{
public:
	deque<uint8_t> q;

	bool push (const pbuffer&);
	bool push (const uint8_t*, int);

	int peek (pbuffer&);
	int peek (uint8_t*, int);
	template<class T> inline int peek (T&a) {
		return peek ( (uint8_t*) &a, sizeof (a) ) / sizeof (a);
	}

	int pop (uint8_t*, int);
	int pop (pbuffer&); //note that this *appends* to the pbuffer!
	template<class T> inline int pop (T&a) {
		return (len() < sizeof (a) ) ? 0 : pop ( (uint8_t*) &a, sizeof (a) );
	}

	inline void clear() {
		q.clear();
	}
	inline int len() const {
		return q.size();
	}

	static int max_len;
};

void sq_init();

#endif

