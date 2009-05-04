
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

#include "status.h"

#include "timestamp.h"
#include "route.h"
#include "comm.h"
#include "conf.h"
#define LOGNAME "cloud/status"
#include "log.h"

#include <string>
using namespace std;

static string status_file = "";
static uint64_t last_export = 0;
static uint64_t start_time = 0;
static int status_interval = 30000000;
static bool verbose = false;

#include <stdio.h>

static string data_format (uint64_t a)
{
	char buffer[64];
	if (a < (1 << 10) ) snprintf (buffer, 63, "%g", (double) a);
	else if (a < (1l << 20) )
		snprintf (buffer, 63, "%.2fKi", a / (double) (1 << 10) );
	else if (a < (1l << 30) )
		snprintf (buffer, 63, "%.2fMi", a / (double) (1l << 20) );
	else if (a < (1ll << 40) )
		snprintf (buffer, 63, "%.2fGi", a / (double) (1l << 30) );
	else snprintf (buffer, 63, "%0.2fTi", a / (double) (1ll << 40) );

	return string (buffer);
}

static int status_to_file (const char*fn)
{
	FILE*outfile;

	uint64_t //for computing totals
	in_p_speed, in_s_speed,
	out_p_speed, out_s_speed;
	in_p_speed = in_s_speed = out_p_speed = out_s_speed = 0;

	outfile = fopen (fn, "w");
	if (!outfile) {
		Log_warn ("Couldn't open status file `%s' for writing", fn);
		return 1;
	}

#define output(x...) fprintf(outfile, ##x)

	output ("cloudvpn status\nuptime: %gs\n\n",
	        0.000001* (timestamp() - start_time) );

	output ("listening sockets: %zd\n\n", comm_listeners().size() );
	output ("connections: %zd\n", comm_connections().size() );

	map<int, connection>::iterator c;
	map<address, connection::remote_route>::iterator r;
	for (c = comm_connections().begin();c != comm_connections().end();++c) {
		if (c->second.state == cs_active)
			output ("connection %d \tping %u \troute count %zd \t(fd %d)\n",
			        c->first, c->second.ping,
			        c->second.remote_routes.size(), c->second.fd);
		else output ("connection %d inactive\n", c->first);

		if (c->second.connect_address.length() )
			output (" * assigned to host `%s'\n",
			        c->second.connect_address.c_str() );
		if (c->second.peer_addr_str.length() )
			output (" = connected to addr `%s'\n",
			        c->second.peer_addr_str.c_str() );
		if (c->second.peer_connected_since)
			output (" = connected for %g seconds\n", 0.000001 *
			        (timestamp() - c->second.peer_connected_since) );


		output (" >> in  %sB/s, %spkt/s; total %sB, %spkt\n",
		        data_format (c->second.in_s_speed).c_str(),
		        data_format (c->second.in_p_speed).c_str(),
		        data_format (c->second.in_s_total).c_str(),
		        data_format (c->second.in_p_total).c_str() );
		output (" << out %sB/s, %spkt/s; total %sB, %spkt\n",
		        data_format (c->second.out_s_speed).c_str(),
		        data_format (c->second.out_p_speed).c_str(),
		        data_format (c->second.out_s_total).c_str(),
		        data_format (c->second.out_p_total).c_str() );

		in_p_speed += c->second.in_p_speed;
		in_s_speed += c->second.in_s_speed;
		out_p_speed += c->second.out_p_speed;
		out_s_speed += c->second.out_s_speed;

		if (verbose) for (r = c->second.remote_routes.begin();
			                  r != c->second.remote_routes.end();++r)
				output (" `--route to %s \tdist %u \tping %u\n",
				        r->first.format().c_str(),
				        r->second.dist, r->second.ping);
	}

	output ("---\n\n");

	output (" >> total in  %sB/s, %spkt/s; total %sB, %spkt\n",
	        data_format (in_s_speed).c_str(),
	        data_format (in_p_speed).c_str(),
	        data_format (connection::all_in_s_total).c_str(),
	        data_format (connection::all_in_p_total).c_str() );
	output (" << total out %sB/s, %spkt/s; total %sB, %spkt\n",
	        data_format (out_s_speed).c_str(),
	        data_format (out_p_speed).c_str(),
	        data_format (connection::all_out_s_total).c_str(),
	        data_format (connection::all_out_p_total).c_str() );

	output ("---\n\n");

	output ("local route count: %zd\n", route_get().size() );

	map<address, route_info>::iterator i;
	for (i = route_get().begin();i != route_get().end();++i)
		output ("route to %s \tvia conn %d \tping %u \tdistance %u\n",
		        i->first.format().c_str(),
		        i->second.id, i->second.ping, i->second.dist);
	output ("---\n\n");


#undef output
	fclose (outfile);
	return 0;
}

int status_init()
{
	config_get ("status-file", status_file);
	config_get_int ("status-interval", status_interval);
	verbose = config_is_true ("status-verbose");

	if (!status_interval) return 0;

	if (status_file.length() )
		Log_info ("exporting status to file `%s'", status_file.c_str() );
	else status_interval = 0;

	start_time = timestamp();

	return 0;
}

int status_try_export()
{
	if (!status_interval) return 0;
	if (timestamp() < last_export + status_interval) return 0;
	last_export = timestamp();
	return status_to_file (status_file.c_str() );
}
