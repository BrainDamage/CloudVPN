
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

