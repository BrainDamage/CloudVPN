
import os
from glob import glob

env=Environment(ENV=os.environ)
env['CPPPATH']=['#include/']
env['CXXFLAGS']=['-g']

sources = glob('src/*.c') + glob('src/*.cpp')
env.Program('cloudvpn',sources)


