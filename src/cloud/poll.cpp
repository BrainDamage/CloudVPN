
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

#include "comm.h"
#include "gate.h"
#include "poll.h"
#include "log.h"

void poll_handle_event (int fd, int what)
{
	if (!what) return;

	map<int, int>::iterator id;

	/*
	 * gate&comm lookups have roughly the same frequency, but there's
	 * usually much smaller set of gates; so they go first.
	 *
	 * listener lookups can be solved last, because of low freq.
	 */

	id = gate_index().find (fd);

	if (id != gate_index().end() ) {
		map<int, gate>::iterator g = gate_gates().find (id->second);
		if (g == gate_gates().end() ) return;
		if (what&WRITE_READY) g->second.poll_write();
		if (what& (READ_READY | EXCEPTION_READY) ) g->second.poll_read();
		return;
	}

	id = comm_connection_index().find (fd);


	if (id != comm_connection_index().end() ) {
		map<int, connection>::iterator
		con = comm_connections().find (id->second);

		if (con == comm_connections().end() ) return;

		if (what&WRITE_READY)
			con->second.poll_write();
		if (what& (READ_READY | EXCEPTION_READY) )
			con->second.poll_write();
		return;
	}

	set<int>::iterator lis;

	lis = comm_listeners().find (fd);

	if (lis != comm_listeners().end() ) {
		comm_listener_poll (fd);
		return;
	}

	lis = gate_listeners().find (fd);
	if (lis != gate_listeners().end() ) {
		gate_listener_poll (fd);
		return;
	}

	Log_info ("polled a nonexistent fd %d!", fd);
}


