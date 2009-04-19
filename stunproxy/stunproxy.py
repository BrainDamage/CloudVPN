#!/usr/bin/env python

DOCS="""

StunConn client
(part of stunproxy)

Connect 2 clients using a shared secret.

Written by [exa] 2009, license is GPLv3, so please behave.

FUNCTION:

1] Get mapped address using STUN
2] Send it to server. On negative answer, wait some time and go to 1
3] Receive a initiation packet from the other half. On timeout go to 1
4] Open local sockets, do conversation. On timeout close all sockets and
   jump to 1.
5] Exit only on signal

RUNNING:

stunproxy <shared-key-with-server-id> <recv-addr:recv-port> <send-addr:send-port> <stunserver>

shared-key-with-server-id is in format:

base64key+base64key+base64key@some-server:maybe-port/path

recv-addr and recv-port is the address/port that proxy listens on

send-addr and send-port is the address/port to that proxy forwards all incoming traffic.

stunserver is a domain name (:port) of STUN server to use. (say, stunserver.org)

"""

from socket import *
from binascii import *
import sys,time,urllib,random


def create_udp_socket():
	a=socket(AF_INET,SOCK_DGRAM,0)
	a.settimeout(5)
	return a
	
def get_peer(key):
	pass


request_packet=unhexlify('0001'+
	''.join([random.choice('ABCDEF0123456789') for i in range(32)]))

def query_stun(stunserver,port,sock):
	sock.sendto(request_packet,(stunserver,port))
	while True:
		r=sock.recvfrom(1526)

def stunproxy(key,recv,send,stun):
	usock=create_udp_socket()
	print query_stun(stun,usock)
	


if __name__=='__main__':
	if(len(sys.argv)<5):
		print DOCS
		raise "not enough parameters."
	stunproxy(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4])
	

