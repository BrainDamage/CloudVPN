
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

#ifndef _CVPN_IFACE_H
#define _CVPN_IFACE_H

int iface_create();
int iface_destroy();

#include <stddef.h>

int iface_write (void*buf, size_t len);
int iface_read (void*buf, size_t maxlen);

#define hwaddr_size 6
#include <stdint.h>

int iface_set_hwaddr (uint8_t*hw);
int iface_retrieve_hwaddr (uint8_t*hw);
const uint8_t* iface_cached_hwaddr();

void iface_poll_read();
void iface_poll_write();
int iface_get_sockfd();

#endif

