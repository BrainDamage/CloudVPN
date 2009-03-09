
import os
from glob import glob

output='cloudvpn'

env=Environment(ENV=os.environ)
env['CPPPATH']=['#include/']
env['LIBS']=['ssl','crypto']

for i in ['CFLAGS','CXXFLAGS','CPPFLAGS','LDFLAGS','CXX','CC']:
	if os.environ.has_key(i): env[i]=os.environ[i]

if os.environ.has_key('WIN32'):
	env['LIBS']+=['gdi32','ws2_32']
	output='cloudvpn.exe'

sources = glob('src/*.c') + glob('src/*.cpp')
env.Program(output,sources)


