
import os
from glob import glob

SetOption('num_jobs',3)

env=Environment(ENV=os.environ)
env['CPPPATH']=['#include/']
env['CXXFLAGS']=['-g']

sources = glob('src/*.c') + glob('src/*.cpp')
env.Program('cloudvpn',sources)


