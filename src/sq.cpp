
#include "sq.h"
#include "log.h"
#include "conf.h"

int squeue::max_len = (32 * 1024);

int sq_init()
{
	if (!config_get_int ("squeue_limit", squeue::max_len) )
		squeue::max_len = 32 * 1024;
	Log_info ("squeue size limit is %d", squeue::max_len);
	return 0;
}

int sq_shutdown()
{
	return 0;
	//no real idea what to do here.
}

/*
 * pbuffer
 */

template <class T> void pbuffer::push (const T& o)
{
	uint8_t*data = (uint8_t*) & o;

	b.reserve (b.size() + sizeof (o) );

	for (int i = 0;i < sizeof (o);++i) b.push_back (data[i]);
}

void pbuffer::push (const uint8_t*d, int size)
{
	b.reserve (b.size() + size);
	for (int i = 0;i < size;++i) b.push_back (d[i]);
}

/*
 * squeue stuff
 */

bool squeue::push (const pbuffer& b)
{
	if (b.len() + q.size() > max_len) return false;

	vector<uint8_t>::const_iterator i;

	for (i = b.b.begin();i < b.b.end();++i)
		q.push_back (*i);

	return true;
}

bool squeue::push (const uint8_t*d, int size)
{
	if (q.size() + size > max_len) return false;

	for (int i = 0;i < size;++i) q.push_back (d[i]);

	return true;
}

int squeue::pop (uint8_t*d, int size)
{
	int ret = size;
	if (ret > q.size() ) ret = q.size();
	if (!ret) return ret;

	deque<uint8_t>::iterator k;
	int i;

	for (i = 0, k = q.begin();i < ret;++i, ++k) {
		d[i] = *k;
	}
	q.erase (q.begin(), k);
	return ret;
}

int squeue::pop (pbuffer&buf)
{
	int ret = q.size();
	if (!ret) return ret;

	deque<uint8_t>::iterator k;
	buf.b.reserve (buf.b.size() + ret);
	int i;

	for (i = 0, k = q.begin();i < ret;++i, ++k) {
		buf.b.push_back (*k);
	}
	q.erase (q.begin(), k);
	return 0;
}

