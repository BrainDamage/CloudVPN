
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

#include "log.h"
#include <stdarg.h>
#include <time.h>

#define output_file stdout

/*
 * Log_info is verbose enough by default. Debug not shown.
 */
static int log_level = 1;

void log_setlevel (int l)
{
	log_level = l;
}

static const char* loglevel_mark (int level)
{
	switch (level) {
	case DEBUG:
		return "debug ";
	case INFO:
		return "(info) ";
	case WARN:
		return "* warning ";
	case ERROR:
		return "*** Error ";
	case FATAL:
		return "FATAL ";
	default:
		return "";
	}
}

void Log (int lvl, const char*fmt, ...)
{
	if (lvl < log_level) return;

	char date_buf[33];

	time_t t = time (0);

	strftime (date_buf, 32, "%c ", localtime (&t) );

	fprintf (output_file, date_buf);

	fprintf (output_file, loglevel_mark (lvl) );

	va_list ap;

	va_start (ap, fmt);

	vfprintf (output_file, fmt, ap);

	va_end (ap);

	fprintf (output_file, "\n");
}

void Log_full (int lvl, const char*file, int line,
               const char*fmt, ...)
{
	if (lvl < log_level) return;

	char date_buf[33];

	time_t t = time (0);

	strftime (date_buf, 32, "%c ", localtime (&t) );

	fprintf (output_file, date_buf);

	fprintf (output_file, loglevel_mark (lvl) );

	fprintf (output_file, "in `%s' line %d:\t", file, line);

	va_list ap;

	va_start (ap, fmt);

	vfprintf (output_file, fmt, ap);

	va_end (ap);

	fprintf (output_file, "\n");
}
