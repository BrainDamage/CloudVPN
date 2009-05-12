
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

#ifndef _CVPN_POLL_H
#define _CVPN_POLL_H

int poll_init();
int poll_deinit();
int poll_set_add_read (int fd);
int poll_set_add_write (int fd);
int poll_set_remove_read (int fd);
int poll_set_remove_write (int fd);
int poll_set_clear();
int poll_wait_for_event (int timeout_usec);

#define READ_READY (1<<0)
#define WRITE_READY (1<<1)
#define EXCEPTION_READY (1<<2)

void poll_handle_event (int fd, int what);

#endif

