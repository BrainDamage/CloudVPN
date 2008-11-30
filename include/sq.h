
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
	void clear();
	int len();
	template<class T>void push (const T&);
};

class squeue
{
public:
	deque<uint8_t> q;

	bool push (const pbuffer&);
	bool push (const void*, int);

	int pop (void*, int);
	int pop (pbuffer&);

	void clear();
	int len();

	squeue();
	~squeue();

	static int max_len;
};

int sq_init();
int sq_shutdown();

#endif

