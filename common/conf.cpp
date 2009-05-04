
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

#include "conf.h"
#define LOGNAME "common/conf"
#include "log.h"

#include <iostream>
#include <fstream>
#include <map>

using namespace std;

#include <string.h>

#define MAX_CONF_DEPTH 16 //avoid stack overflows

map<string, list<string> > data;


void config_set (const string&n, const string&v)
{
	Log_debug ("config: `%s' := `%s'", n.c_str(), v.c_str() );
	data[n].push_front (v);
}

bool config_is_set (const string&n)
{
	return data.count (n);
}

bool config_get (const string&n, string&res)
{
	if (!data.count (n) ) return false;

	res = data[n].front();

	return true;
}

void config_get_list (const string&n, list<string>&v)
{
	if (data.count (n) ) v = data[n];
	else v = list<string>();
}

bool config_is_true (const string&name)
{
	if (!data.count (name) ) return false;

	const string&v = data[name].front();

	if (!v.length() ) return false;

	return (v[0] == 'y') || (v[0] == 'Y') || (v[0] == '1');
}

#include <stdio.h>

bool config_get_int (const string&name, int&val)
{
	string t;
	if (config_get (name, t) ) {
		if (!t.length() ) {
			Log_warn ("config string `%s'empty", name.c_str() );
		}

		bool hex = (t[0] == 'x') || (t[0] == 'X');

		if (1 == sscanf (t.c_str() + (hex ? 1 : 0), hex ? "%x" : "%d", &val) )
			return true;
		else Log_warn ("could not parse value `%s' of `%s' to integer",
			               t.c_str(), name.c_str() );
	}
	Log_debug ("`%s' is not set", name.c_str() );
	return false;
}

static bool is_white (char c)
{
	return (c == ' ') || (c == '\t');
}

#define include_directive "@include"

bool parse_file (const string& name, int depth = 0)
{
	if (depth > MAX_CONF_DEPTH) return false;

	ifstream file (name.c_str() );

	if (!file.is_open() ) {
		Log_error ("config: opening file `%s' failed", name.c_str() );
		return false;
	} else Log_debug ("config: reading from file `%s'", name.c_str() );

	string l;

	while (getline (file, l) ) {
		int len = l.length();
		int value_start = 0;
		int name_end = 0;

		if (!len) continue; //empty line

		if (l[0] == '#') continue; //comment

		while ( (name_end < len) && (!is_white (l[name_end]) ) ) ++name_end;

		if ( (!name_end) || (name_end >= len) ) continue;

		value_start = name_end;

		while ( (value_start < len) && is_white (l[value_start]) ) ++value_start;

		if (value_start >= len) {
			Log_error ("config: value missing in file `%s'",
			           name.c_str() );
			return false;
		}

		string name (l, 0, name_end);

		string value (l, value_start, len);

		if (name == include_directive) {
			if (!parse_file (value, depth + 1) ) return false;
		} else config_set (name, value);
	}

	Log_debug ("config: file `%s' loaded OK", name.c_str() );

	return true;
}

bool config_parse (int argc, char**argv)
{
	//commandline syntax is -option_name value -another_option value
	++argv; //get rid of executable name

	while (*argv) {
		if (! (**argv) ) continue;

		if (*argv[0] == '-') {
			char* option_name = (*argv) + 1;
			++argv;

			if (! (*argv) ) {
				Log_error ("config: missing value for commandline option `%s'", option_name);
				return false;
			}

			if (!strcmp (option_name, include_directive) ) {
				if (!parse_file (*argv, 0) ) return false;
			} else config_set (option_name, *argv);
		} else {
			Log_error ("config: bad cmdline option at `%s'",
			           *argv);
			return false;
		}

		++argv;
	}

	Log_debug ("config: everything parsed OK");

	return true;
}
