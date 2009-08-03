
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

#include "security.h"

#ifndef __WIN32__
#include "conf.h"
#define LOGNAME "common/security"
#include "log.h"

#include <unistd.h>
#include <errno.h>
#include <string.h>
#endif

int do_chroot()
{
#ifndef __WIN32__
	string dir;
	if (!config_get ("chroot", dir) ) return 0;

	if (chroot (dir.c_str() ) ) {
		Log_error ("chroot failed with errno %d: %s",
		           errno, strerror (errno) );
		return 1;
	}

	if (chdir ("/") ) {
		Log_error ("cannot enter chrooted environment");
		return 2;
	}

#endif
	return 0;
}

#ifndef __WIN32__
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#endif

int do_switch_user()
{
#ifndef __WIN32__
	struct passwd*pw;
	struct group*gr;

	int gid = -1, uid = -1;

	string t;

	if (config_get ("user", t) ) {
		pw = getpwnam (t.c_str() );
		if (!pw) {
			Log_error ("unknown user `%s'", t.c_str() );
			return 1;
		}
		uid = pw->pw_uid;
		gid = pw->pw_gid;
	}

	if (config_get ("group", t) ) {
		gr = getgrnam (t.c_str() );
		if (!gr) {
			Log_error ("unknown group `%s'", t.c_str() );
			return 2;
		}
		gid = gr->gr_gid;
	}

	if (gid >= 0) if (setgid (gid) ) {
			Log_error ("setgid(%d) failed", gid);
			return 3;
		} else Log_info ("gid changed to %d", gid);

	if (uid >= 0) if (setuid (uid) ) {
			Log_error ("setuid(%d) failed", uid);
			return 4;
		} else Log_info ("uid changed to %d", uid);

#endif
	return 0;
}

#ifndef __WIN32__
#include <sys/mman.h>
#endif

int do_memlock()
{
#ifndef __WIN32__
	if (config_is_true ("mlockall") ) if (mlockall (MCL_CURRENT | MCL_FUTURE) ) {
			Log_error ("mlockall() failed with errno %d: %s",
			           errno, strerror (errno) );
			return 1;
		}
#endif
	return 0;
}

int fix_file_owner (const char*fn)
{
#ifndef __WIN32__
	struct passwd*pw;
	struct group*gr;

	int gid = -1, uid = -1;

	string t;

	if (config_get ("user", t) ) {
		pw = getpwnam (t.c_str() );
		if (!pw) {
			Log_error ("unknown user `%s'", t.c_str() );
			return 1;
		}
		uid = pw->pw_uid;
	}

	if (config_get ("group", t) ) {
		gr = getgrnam (t.c_str() );
		if (!gr) {
			Log_error ("unknown group `%s'", t.c_str() );
			return 2;
		}
		gid = gr->gr_gid;
	}

	if ( (uid >= 0) || (gid >= 0) ) if (chown (fn, uid, gid) ) {
			Log_warn ("cannot chown(\"%s\", %d, %d): %s", fn, uid, gid, strerror (errno) );
			return 3;
		}

#endif
	return 0;
}
