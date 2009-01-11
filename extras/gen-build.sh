#!/bin/sh
echo '#!/bin/sh'
echo 'while read line; do echo $line ; $line ; done << EOFBUILDSH'
scons -Qn
echo 'EOFBUILDSH'

