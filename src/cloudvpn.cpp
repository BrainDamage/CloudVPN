
#include "cloudvpn.h"
#include "conf.h"

int run_cloudvpn (int argc, char**argv)
{
	if(!config_parse(argc,argv)) return 1;
	return 0;
}
