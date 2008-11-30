
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
	template<class T>void push (const T&);
	void push (const uint8_t*, int);
	void push (const pbuffer&);
};

class squeue
{
public:
	deque<uint8_t> q;

	bool push (const pbuffer&);
	bool push (const uint8_t*, int);

	int pop (uint8_t*, int);
	int pop (pbuffer&); //note that this *appends* to the pbuffer!

	inline void clear() {
		q.clear();
	}
	inline int len() const {
		return q.size();
	}

	squeue();
	~squeue();

	static int max_len;
};

int sq_init();
int sq_shutdown();

#endif

