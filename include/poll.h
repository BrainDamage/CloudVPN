
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

#endif

