#!/usr/bin/env python
#coding=utf-8

'''
	BigBro [github.com/hiyouthinker] @ 2021.04/05
'''

from scapy.all import *
import sys
import getopt
import thread

import utils
import handler

SYN_PROXY_VERSION = "1.0.0 BigBro @ 2021.04/05"

def recv_from_client_thread(port, iface):
	filter = "tcp dst port %d" % port
	print "capture TCP packet of port %d from client on %s" % (port, iface)

	sniff(filter = filter, prn = handler.tcp_packet_handler_from_client, store = 0, iface = iface, count = 0)

def recv_from_server_thread(threadName, port, iface):
	filter = "tcp src port %d" % port
	print "capture TCP packet of port %d from server on %s" % (port, iface)

	sniff(filter = filter, prn = handler.tcp_packet_handler_from_server, store = 0, iface = iface, count = 0)

def show_session_thread(threadName):
	while True:
		time.sleep(5)
		utils.show_tcp_all_sessions()

if __name__ == "__main__":
	port = 8080
	iface1 = "eth1"
	iface2 = "eth2"

	opts, args = getopt.getopt(sys.argv[1:], 'hc:s:v', ['help', 'filename=', 'version'])
	for opt, arg in opts:
		if opt in ('-h', '--help'):
			print("-h\t--help\t\tshow this help")
			print("-c\t--fromclient\tinput interface of packet from client")
			print("-s\t--fromserver\tinput interface of packet from backend")
			print("-v\t--version\tshow version info")
			exit()
		elif opt in ('-v', '--version'):
			print("%s" % SYN_PROXY_VERSION)
			exit()
		elif opt in ('-c', '--fromclient'):
			iface1 = arg
		elif opt in ('-s', '--fromserver'):
			iface2 = arg

	try:
		thread.start_new_thread(show_session_thread, ("",))
		thread.start_new_thread(recv_from_server_thread, ("", port, iface2))
	except:
		print "Error: unable to start thread"

	recv_from_client_thread(port, iface1)
