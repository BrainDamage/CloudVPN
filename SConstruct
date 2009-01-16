
import os
from glob import glob

SetOption('num_jobs',3)

env=Environment(ENV=os.environ)
env['CPPPATH']=['#include/']
env['CXXFLAGS']=['-O3']
env['LIBS']=['ssl','crypto']

#enable this for debugging
#env['CXXFLAGS']=['-g','-pg']
#env['LINKFLAGS']=['-pg']

sources = glob('src/*.c') + glob('src/*.cpp')
env.Program('cloudvpn',sources)


