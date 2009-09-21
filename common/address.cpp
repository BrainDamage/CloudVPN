
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

#include "address.h"


int address::cmp (const address&a, bool prefix) const
{
	if (inst != a.inst) return (inst < a.inst) ? 1 : -1;

	vector<uint8_t>::const_iterator i, j;
	for (i = addr.begin(), j = a.addr.begin();
	        (i < addr.end() ) && (j < a.addr.end() ); ++i, ++j) {

		if (*i == *j) continue;
		return ( (int) *i) - ( (int) *j);
	}
	if (prefix) return 0;
	if (i == addr.end() )
		if (j == a.addr.end() ) return 0;
		else return -1;
	else return 1;
}

static char hexc (int i)
{
	if ( (i < 0) || (i >= 16) ) return '?';
	if (i < 10) return '0' + i;
	return 'a' + i - 10; //There I Selected Lowercase Lol!
}

string address::format_addr() const
{
	if (!addr.size() ) return string ("null");
	string t;
	vector<uint8_t>::const_iterator i;
	t.reserve (3*addr.size() - 1);
	for (i = addr.begin();i < addr.end();
	        ( { if ( (++i) != addr.end() ) t.append (1, ':'); }) ) {
			t.append (1, hexc (*i / 0x10) );
			t.append (1, hexc (*i % 0x10) );
		}

	return t;
}

string address::format() const
{
	string t = "        ." + format_addr();
	int i;
	for (i = 0;i < 8;++i) t[7-i] = hexc ( (inst >> (4 * i) ) % 16);
	return t;
}

static int hexval (char c)
{
	if ( (c >= 'a') && (c <= 'f') ) c -= 'a' -'A';

	if ( (c >= '0') && (c <= '9') ) c -= '0';
	else if ( (c >= 'A') && (c <= 'F') ) c = c + 10 - 'A';
	else return -1;
	return (int) c;
}

#include "log.h"

bool address::scan_addr (const char*s)
{
	addr.clear();
	bool half = false;
	char byte;
	int val;
	for (;*s;++s) {
		if ( (val = hexval (*s) ) < 0) continue;
		Log_info ("value now %d %x", val, val);

		if (half) {
			addr.push_back (val + (byte << 4) );
			byte = 0;
			half = false;
		} else {
			byte = val;
			half = true;
		}
	}
	Log_info ("it has %d bytes, remaining half is %s", addr.size(), half ? "present" : "NOT present");
	if (half) return false; //bad padding
	return true;
}

bool address::scan (const char*s)
{
	addr.clear();
	uint32_t prefix = 0;
	int i = 0, val;
	for (; (*s) && (i < 8);++s) {
		if ( (val = hexval (*s) ) < 0) continue;
		++i;
		prefix <<= 4;
		prefix |= val;
	}
	if (i < 8) return false;
	inst = prefix;
	return scan_addr (s);
}

