#!/usr/bin/env python
#coding=utf-8

'''
	BigBro @ 2021.04
'''

from scapy.all import *
import thread

import utils
import handler

def recv_from_client_thread():
	cap_port = 8080
	cap_if = "eth1"
	filter = "tcp dst port %d" % cap_port
	print "capture TCP packet of port %d on %s" % (cap_port, cap_if)

	sniff(filter = filter, prn = handler.tcp_packet_handler_from_client, store = 0, iface = "eth1", count = 0)

def recv_from_server_thread(threadName):
	cap_port = 8080
	cap_if = "eth2"
	filter = "tcp src port %d" % cap_port
	print "capture TCP packet of port %d on %s" % (cap_port, cap_if)

	sniff(filter = filter, prn = handler.tcp_packet_handler_from_server, store = 0, iface = "eth2", count = 0)

def show_session_thread(threadName):
	while True:
		time.sleep(10)
		utils.show_tcp_all_sessions()

try:
	thread.start_new_thread(show_session_thread, ("",))
	thread.start_new_thread(recv_from_server_thread, ("",))
except:
   print "Error: unable to start thread"

# start to capture pkts
recv_from_client_thread()