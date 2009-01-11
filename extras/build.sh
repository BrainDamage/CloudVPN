#!/bin/sh
while read line; do echo $line ; $line ; done << EOFBUILDSH
g++ -o src/route.o -c -O3 -Iinclude src/route.cpp
g++ -o src/cloudvpn.o -c -O3 -Iinclude src/cloudvpn.cpp
g++ -o src/poll.o -c -O3 -Iinclude src/poll.cpp
g++ -o src/iface.o -c -O3 -Iinclude src/iface.cpp
g++ -o src/log.o -c -O3 -Iinclude src/log.cpp
g++ -o src/main.o -c -O3 -Iinclude src/main.cpp
g++ -o src/comm.o -c -O3 -Iinclude src/comm.cpp
g++ -o src/conf.o -c -O3 -Iinclude src/conf.cpp
g++ -o src/timestamp.o -c -O3 -Iinclude src/timestamp.cpp
g++ -o src/sq.o -c -O3 -Iinclude src/sq.cpp
g++ -o src/security.o -c -O3 -Iinclude src/security.cpp
g++ -o src/status.o -c -O3 -Iinclude src/status.cpp
g++ -o src/utils.o -c -O3 -Iinclude src/utils.cpp
g++ -o cloudvpn src/route.o src/cloudvpn.o src/poll.o src/iface.o src/log.o src/main.o src/comm.o src/conf.o src/timestamp.o src/sq.o src/security.o src/status.o src/utils.o -lssl
EOFBUILDSH
