
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

#ifndef _CVPN_UTILS_H
#define _CVPN_UTILS_H

#if defined(__FreeBSD__)||defined(__OpenBSD__)||defined(__NetBSD__)
# define __BSD__
#endif

#include "iface.h"

int setup_sighandler();

#endif

