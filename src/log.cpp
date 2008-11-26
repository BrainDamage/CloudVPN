
#include "log.h"
#include <stdarg.h>
#include <time.h>

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

	fprintf (stderr, date_buf);
	
	fprintf (stderr, loglevel_mark (lvl) );

	va_list ap;

	va_start (ap, fmt);

	vfprintf (stderr, fmt, ap);

	va_end (ap);

	fprintf (stderr, "\n");
}

void Log_full (int lvl, const char*file, int line,
               const char*fmt, ...)
{
	if (lvl < log_level) return;

	char date_buf[33];

	time_t t = time (0);

	strftime (date_buf, 32, "%c ", localtime (&t) );

	fprintf (stderr, date_buf);

	fprintf (stderr, loglevel_mark (lvl) );

	fprintf (stderr, "in `%s' line %d: ", file, line);

	va_list ap;

	va_start (ap, fmt);

	vfprintf (stderr, fmt, ap);

	va_end (ap);

	fprintf (stderr, "\n");
}
