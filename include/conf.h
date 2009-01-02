
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

#ifndef _CVPN_CONF_H
#define _CVPN_CONF_H

#include <string>
#include <list>
using std::string;
using std::list;

bool config_parse (int argc, char**argv);

void config_set (const string& name, const string&value);
bool config_get (const string& name, string&value);
bool config_is_true (const string&name);
bool config_get_int (const string&name, int&value);
void config_get_list (const string&name, list<string>&values);

bool config_is_set (const string&name);

#endif
