
#include "sq.h"
#include "log.h"
#include "conf.h"

#include <algorithm>
using namespace std;

/*
 * pbuffer
 */

void pbuffer::push (const uint8_t*d, int size)
{
	b.reserve (b.size() + size);
	copy (d, d + size, back_insert_iterator<vector<uint8_t> > (b) );
}

/*
 * squeue stuff
 *
 * TODO find some kind of adaptor for deque pushing.
 */

bool squeue::push (const pbuffer& b)
{
	for (vector<uint8_t>::const_iterator i = b.b.begin();i < b.b.end();++i)
		q.push_back (*i);
	return true;
}

bool squeue::push (const uint8_t*d, int size)
{
	for (int i = 0;i < size;++i) q.push_back (d[i]);
	return true;
}

int squeue::pop (uint8_t*d, int size)
{
	int ret = size;
	if (ret > q.size() ) ret = q.size();
	if (!ret) return ret;

	if (d) copy (q.begin(), q.begin() + ret, d);

	q.erase (q.begin(), q.begin() + ret);

	return ret;
}

int squeue::pop (pbuffer&buf)
{
	int ret = q.size();
	if (!ret) return ret;

	buf.b.reserve (buf.b.size() + ret);

	copy (q.begin(), q.begin() + ret,
	      back_insert_iterator<vector<uint8_t> > (buf.b) );

	q.erase (q.begin(), q.begin() + ret);

	return 0;
}

int squeue::peek (uint8_t*d, int size)
{
	int ret = size;
	if (ret > q.size() ) ret = q.size();
	if (!ret) return ret;

	copy (q.begin(), q.begin() + ret, d);

	return ret;
}

int squeue::peek (pbuffer&buf)
{
	int ret = q.size();
	if (!ret) return ret;

	buf.b.reserve (buf.b.size() + ret);

	copy (q.begin(), q.begin() + ret,
	      back_insert_iterator<vector<uint8_t> > (buf.b) );

	return 0;
}

