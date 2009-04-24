
#ifndef _CVPN_GATE_H
#define _CVPN_GATE_H

#include <stdint.h>
#include "sq.h"
#include "address.h"

#include <deque>
#include <list>
#include <map>
#include <set>
using namespace std;

class gate
{
public:
	int fd, id;

	void index();
	void deindex();

	void set_fd (int i) {
		if (i < 0) return;
		deindex();
		fd = i;
		index();
	}

	void unset_fd () {
		deindex();
		fd = -1;
	}

	explicit gate (int ID);
	explicit gate(); //<- never use this one!

	uint64_t last_activity;

	void try_parse_input();

	inline void try_write() {
		poll_write();
	}

	void poll_read();
	void poll_write();

	void periodic_update();

	list<address>promisc; //saves only proto/instance, and zerolen addr
	list<address>local;

	void start();
	void reset();

	squeue recv_q;
	deque<pbuffer> send_q;
};

int gate_init();
void gate_shutdown();
int gate_periodic_update();

void poll_gate_listener (int fd);

map<int, int>& gate_index();
map<int, gate>& gate_gates();
set<int>& gate_listeners();

#endif

