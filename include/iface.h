
#ifndef _CVPN_IFACE_H
#define _CVPN_IFACE_H

bool iface_create();
void iface_destroy();

#include <stddef.h>

int iface_write (void*buf, size_t len);
int iface_read (void*buf, size_t maxlen);

#define hwaddr_size 6
#include <stdint.h>

int iface_set_hwaddr (uint8_t*hw);
int iface_retrieve_hwaddr (uint8_t*hw);
const uint8_t* iface_cached_hwaddr();

void iface_update(); //reads things and routes them
int iface_get_sockfd();

#endif

