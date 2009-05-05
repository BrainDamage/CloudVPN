
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

#define LOG_FATAL 1
#define LOG_ERROR 2
#define LOG_WARN 3
#define LOG_INFO 4
#define LOG_DEBUG 5

#ifndef LOGNAME
#define LOGNAME __FILE__
#endif

#define Log_debug(fmt,params...) Log_full(LOG_DEBUG,LOGNAME,__LINE__,fmt,##params)
#define Log_info(fmt,params...) Log_full(LOG_INFO,LOGNAME,__LINE__,fmt,##params)
#define Log_warn(fmt,params...) Log_full(LOG_WARN,LOGNAME,__LINE__,fmt,##params)
#define Log_error(fmt,params...) Log_full(LOG_ERROR,LOGNAME,__LINE__,fmt,##params)
#define Log_fatal(fmt,params...) Log_full(LOG_FATAL,LOGNAME,__LINE__,fmt,##params)

#endif

