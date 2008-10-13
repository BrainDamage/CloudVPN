
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
void config_get_list (const string&name, list<string>&values);

bool config_is_set (const string&name);

#endif
