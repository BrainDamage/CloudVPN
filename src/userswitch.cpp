
#include "userswitch.h"

#include "conf.h"
#include "log.h"

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

int do_switch_user()
{
	struct passwd*pw;
	struct group*gr;

	int gid=-1,uid=-1;
	
	string t;
	
	if(config_get("user",t)) {
		pw=getpwnam(t.c_str());
		if(!pw) {
			Log_error("unknown user `%s'",t.c_str());
			return 1;
		}
		uid=pw->pw_uid;
		gid=pw->pw_gid;
	}

	if(config_get("group",t)) {
		gr=getgrnam(t.c_str());
		if(!gr) {
			Log_error("unknown group `%s'",t.c_str());
			return 2;
		}
		gid=gr->gr_gid;
	}

	if (gid>=0) if(setgid(gid)) {
		Log_error("setgid(%d) failed",gid);
		return 3;
	} else Log_info("gid changed to %d",gid);

	if (uid>=0) if(setuid(uid)) {
		Log_error("setuid(%d) failed",uid);
		return 4;
	} else Log_info("uid changed to %d",uid);

	return 0;
}
