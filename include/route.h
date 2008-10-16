
#ifndef _CVPN_ROUTE_H
#define _CVPN_ROUTE_H

#include "iface.h"

#include <stdint.h>
#include <stddef.h>

void route_init();
void route_shutdown();
void route_update();
void route_packet(void*buf, size_t len, int incoming_connection=-1);
void route_broadcast_packet(uint32_t id, void*buf, size_t len, int ic=-1);

#endif

