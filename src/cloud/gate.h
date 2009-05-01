
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

	//I/O handlers

	uint8_t cached_header_type;
	uint16_t cached_header_size;

	bool parse_packet_header();
	void add_packet_header (pbuffer&, uint8_t type, uint16_t size);

	void handle_keepalive();
	void handle_route (uint16_t size, const uint8_t*data);
	void handle_packet (uint16_t size, const uint8_t*data);

	void send_keepalive();
	void send_packet (uint32_t inst,
	                  uint16_t doff, uint16_t ds,
	                  uint16_t soff, uint16_t ss,
	                  uint16_t size, const uint8_t*data);

	void try_parse_input();

	inline void try_write() {
		poll_write();
	}

	void poll_read();
	void poll_write();

#define gate_max_send_q_len 1024
#define gate_max_recv_q_len 65536

	squeue recv_q;
	deque<pbuffer> send_q;

	inline bool can_send() {
		return send_q.size() < gate_max_send_q_len;
	}
	pbuffer& new_send();

	void periodic_update();

	list<address>local;
	set<address>instances;

	void start();
	void reset();
};

int gate_init();
void gate_shutdown();
int gate_periodic_update();

void gate_listener_poll (int fd);

map<int, int>& gate_index();
map<int, gate>& gate_gates();
set<int>& gate_listeners();

#endif
