#!/usr/bin/env python
#coding=utf-8

'''
	BigBro [github.com/hiyouthinker] @ 2021.04/05
'''

from scapy.all import *
import sys
import getopt
import threading
import string

import utils
import handler
import tcp_state

SYN_PROXY_VERSION = "2.0.0 BigBro @ 2021.04/05"

def recv_from_client_thread(port, iface):
	filter = "inbound and tcp dst port %d" % port
	print("capture TCP packet of port %d from client on %s" % (port, iface))

	sniff(filter = filter, prn = handler.tcp_packet_handler_from_client, store = 0, iface = iface, count = 0)

def recv_from_server_thread(threadName, port, iface):
	filter = "inbound and tcp src port %d" % port
	print("capture TCP packet of port %d from server on %s" % (port, iface))

	sniff(filter = filter, prn = handler.tcp_packet_handler_from_server, store = 0, iface = iface, count = 0)

def show_session_thread(threadName):
	while True:
		time.sleep(5)
		utils.show_tcp_all_sessions()

if __name__ == "__main__":
	port = 8080
	iface1 = "eth1"
	iface2 = "eth2"

	opts, args = getopt.getopt(sys.argv[1:], 'hc:s:t:m:p:v', ['help', 'fromclient=', 'fromserver=', 'timeout=', 'mode=', 'port=', 'version'])
	for opt, arg in opts:
		if opt in ('-h', '--help'):
			print("-h\t--help\t\tshow this help")
			print("-c\t--fromclient\tinput interface of packet from client")
			print("-s\t--fromserver\tinput interface of packet from backend")
			print("-t\t--timeout\ttimeout of ESTABLISHED")
			print("-m\t--mode\t\tSYN Proxy (s) or Delayed Binding (d), default is SYN Proxy")
			print("-p\t--port\t\tlisten on the port")
			print("-v\t--version\tshow version info")
			exit()
		elif opt in ('-c', '--fromclient'):
			iface1 = arg
		elif opt in ('-s', '--fromserver'):
			iface2 = arg
		elif opt in ('-t', '--timeout'):
			utils.tcp_session_timeout[tcp_state.TCP_ESTABLISHED][0] = string.atoi(arg)
		elif opt in ('-m', '--mode'):
			if (arg[0] == 'd'):
				handler.mode = 1
			else :
				handler.mode = 0
		elif opt in ('-p', '--port'):
			try:
				port = string.atoi(arg)
				if (port <= 0):
					print("invalid input, please use help")
					exit()
			except ValueError:
				print("invalid input, please use help")
				exit()
		elif opt in ('-v', '--version'):
			print("%s" % SYN_PROXY_VERSION)
			exit()

	mode_string = ["SYN Proxy", "Delayed Binding"]
	print("mode: %s" % mode_string[handler.mode])

	try:
		thread1 = threading.Thread(target=show_session_thread, args=("",))
		thread2 = threading.Thread(target=recv_from_server_thread, args=("", port, iface2))

		thread1.start()
		thread2.start()

#		thread1.join()
#		thread2.join()
	except:
		print("Error: unable to start thread")

	recv_from_client_thread(port, iface1)
