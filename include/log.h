
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

#ifndef _CVPN_LOG_H
#define _CVPN_LOG_H

#include <string>

using namespace std;

void Log (int level, const char*fmt, ...);
void Log_full (int level, const char*file, int line,
               const char*fmt, ...);
void log_setlevel (int level);

#define DEBUG 0
#define INFO 1
#define WARN 2
#define ERROR 3
#define FATAL 4

#define Log_debug(fmt,params...) Log_full(DEBUG,__FILE__,__LINE__,fmt,##params)
#define Log_info(fmt,params...) Log_full(INFO,__FILE__,__LINE__,fmt,##params)
#define Log_warn(fmt,params...) Log_full(WARN,__FILE__,__LINE__,fmt,##params)
#define Log_error(fmt,params...) Log_full(ERROR,__FILE__,__LINE__,fmt,##params)
#define Log_fatal(fmt,params...) Log_full(FATAL,__FILE__,__LINE__,fmt,##params)

#endif

