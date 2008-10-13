
#ifndef _CVPN_IFACE_H
#define _CVPN_IFACE_H

bool iface_create();
void iface_destroy();

#include <stddef.h>

int iface_write (void*buf, size_t len);
int iface_read (void*buf, size_t len);

#define hwaddr_size 6
#include <stdint.h>

int iface_set_hwaddr(uint8_t*hwaddr);
int iface_retrieve_hwaddr (uint8_t*hwaddr);
bool is_hwaddr_broadcast (uint8_t*hwaddr);

int iface_write_packet (uint8_t*from, uint8_t*to,
			uint16_t type, void*buf, size_t len);
int iface_read_packet (uint8_t*from, uint8_t*to,
		       uint16_t*type, void*buf, size_t maxlen);

#endif

