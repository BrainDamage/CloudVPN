
#include "log.h"
#include <stdarg.h>
#include <time.h>

static int log_level = 0;

void log_setlevel (int l)
{
	log_level = l;
}

void Log (int lvl, const char*fmt, ...)
{
	if (lvl < log_level) return;

	char date_buf[33];

	time_t t = time (0);

	strftime (date_buf, 32, "%c ", localtime (&t) );

	fprintf (stderr, date_buf);

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

	fprintf (stderr, "in `%s' line %d: ", file, line);

	va_list ap;

	va_start (ap, fmt);

	vfprintf (stderr, fmt, ap);

	va_end (ap);

	fprintf (stderr, "\n");
}
