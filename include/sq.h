
#ifndef _CVPN_SQ_H
#define _CVPN_SQ_H

/*
 * Socket Queue
 */

#include <vector>
#include <deque>
using namespace std;

class squeue
{
public:
	static int max_len;


	squeue();
	~squeue();
};

class pbuffer
{
};

int sq_init();
int sq_shutdown();

#endif

