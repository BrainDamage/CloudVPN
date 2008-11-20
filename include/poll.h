
#ifndef _CVPN_POLL_H
#define _CVPN_POLL_H

int poll_init();
int poll_deinit();
int poll_recreate_set();
int poll_wait_for_event (int timeout);

#endif

