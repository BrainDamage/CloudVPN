
import os
from glob import glob

env=Environment(ENV=os.environ)
env['CPPPATH']=['#include/']
env['LIBS']=['ssl','crypto']

for i in ['CFLAGS','CXXFLAGS','CPPFLAGS','LDFLAGS']:
	if os.environ.has_key(i): env[i]=os.environ[i]


sources = glob('src/*.c') + glob('src/*.cpp')
env.Program('cloudvpn',sources)


