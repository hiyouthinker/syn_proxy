#!/usr/bin/env python
#coding=utf-8

'''
	BigBro @ 2021.04/05
'''
from scapy.all import *
import time

import tcp_state
import utils

'''
	dir = 0 : from client
	dir = 1 : from server
'''
def tcp_packet_handler(pkt, dir):
	sip = pkt[IP].src
	dip = pkt[IP].dst
	sport = pkt[TCP].sport
	dport = pkt[TCP].dport
	flags = pkt[TCP].flags
	type = tcp_state.tcp_flags_check(flags)
	found = False
	ack_list = ["", " + ACK"]

	print "\n[%s:%d => %s:%d], flags: %s%s" % (sip, sport, dip, dport, tcp_state.tcp_pkt_flags[type[0]], ack_list[type[1]])

	if ((dir == 0) and (sport == 80 and dport != 80)):
		# local -> client, ignore
		return
	elif ((dir == 1) and (dport == 80 and sport != 80)):
		# local -> server, ignore
		return

	if ((type[0] == tcp_state.TCP_TYPE_SYN) and (dir == 1)):
		print "recv SYN from server, drop the packet"
		return

	if (dir == 0):
		key = (sip, sport, dip, dport)
	else :
		key = (dip, dport, sip, sport)

	if (tcp_state.sessions.has_key(key)) :
		found = True

	if (found == False) :
		print "Session was not found, pkt: %s" % tcp_state.tcp_pkt_flags[type[0]]
		if (type[0] == tcp_state.TCP_TYPE_SYN):
			utils.send_synack_to_client(pkt)
		else :
			if (type[0] == tcp_state.TCP_TYPE_ACK):
				if (dir == 1):
					print "recv ACK from server without session, drop the packet"
					return
				if (utils.tcp_syn_cookie_check(pkt[TCP].ack) == False):
					print "Invalid ACK, drop the packet"
				else :
					print "TCP 3-way handshake with client was completed successfully"
					print "I will conect to backend"
					# seq is initial seq of Client -> Proxy
					seq = pkt[TCP].seq - 1
					# ack is initial seq of Proxy -> Client
					ack = pkt[TCP].ack - 1
					# OK, this is a valid client, create the session
					value = [tcp_state.TCP_SYN_SENT, ack, time.time(), 0, 0, pkt[TCP].window, 0]
					tcp_state.sessions[key] = value
					utils.send_syn_to_server(sip, dip, sport, dport, seq, pkt[TCP].window)
			# PSH
			elif (type[0] == tcp_state.TCP_TYPE_PSH):
				str = pkt.load.replace('\n', '\\n')
				print "invalid packet (%s), drop the packet" % str
			else :
				print "invalid packet, drop the packet"
	else :
		value = tcp_state.sessions.get(key)
		state = value[0]
		offset = value[6]
		now = value[2]
		session_flags = value[3]
		print "current state of session: %s" % (tcp_state.tcp_session_states[state])
		# SYN
		if (type[0] == tcp_state.TCP_TYPE_SYN):
			if (time.time() - now > utils.tcp_session_timeout[state][0]) :
				print "session timeout"
				utils.send_synack_to_client(pkt)
				value[3] = tcp_state.TCP_SESSION_FLAG_SEEN_SYN
				tcp_state.sessions[key] = value
			else :
				print "session isn't expired, drop the SYN"
		# SYN + ACK
		elif (type[0] == tcp_state.TCP_TYPE_SYNACK):
			if (dir == 0):
				print "invalid packet, INGORE!!!"
			else :
				seq = pkt[TCP].seq
				ack = pkt[TCP].ack
				if (state == tcp_state.TCP_ESTABLISHED):
					print "received retransmitted SYN + ACK"
				else :
					# value[1] is initial seq number from SYN Proxy to Client
					offset = seq - value[1]
				# update the session
				value = [tcp_state.TCP_ESTABLISHED, value[1], time.time(), 0, 0, value[5], offset]
				tcp_state.sessions[key] = value
				print "TCP 6-way handshake with client/server was completed successfully"
				print "send ACK to backend"
				utils.send_ack_to_server(dip, sip, dport, sport, ack, seq+1, value[5])
		# ACK
		elif (type[0] == tcp_state.TCP_TYPE_ACK):
			if ((dir == 0) and ((session_flags & tcp_state.TCP_SESSION_FLAG_SEEN_SYN) or (state == tcp_state.TCP_SYN_SENT))):
				if (utils.tcp_syn_cookie_check(pkt[TCP].ack) == False):
					if (session_flags & tcp_state.TCP_SESSION_FLAG_SEEN_SYN) :
						print "ACK verification failed, forward the packet to backend"
						value[3] &= ~tcp_state.TCP_SESSION_FLAG_SEEN_SYN
						tcp_state.sessions[key] = value
						utils.forwar_pkt_to_client_server(key, value, dir, pkt, offset)
						return
					print "Invalid ACK, drop the packet"
				else :
					# This is 0 window probe packet
					# therefore we need to add 1 to make the SYN sequence number match the one of first SYN.
					seq = pkt[TCP].seq - 1 + 1
					ack = pkt[TCP].ack - 1
					# update state and seq of SYN Proxy and time
					# value[6] is offset, the value MUST NOT be changed before receiving the SYN+ ACK from the server
					value = [tcp_state.TCP_SYN_SENT, ack, time.time(), 0, 0, pkt[TCP].window, value[6]]
					tcp_state.sessions[key] = value
					print "Valid ACK, I will reconect to backend"
					utils.send_syn_to_server(sip, dip, sport, dport, seq, pkt[TCP].window)
			elif ((dir == 1) and (state == tcp_state.TCP_SYN_SENT)):
				# server's old connection is still active
				# try to forward the packet
				print "server's old connection is still active? forwad the pkt to client"
			# ESTABLISHED or FIN_WAIT
			else :
				utils.forwar_pkt_to_client_server(key, value, dir, pkt, offset)
		# FIN/PSH/RST
		else :
			if (state == tcp_state.TCP_SYN_SENT) :
				if (dir == 0):
					# This is invalid packet, because window size is 0
					print "This is invalid packet, because window size is 0, DROP it"
					return
				else :
					print "server's old connection is still active? forwad the pkt to client"
			utils.forwar_pkt_to_client_server(key, value, dir, pkt, offset)

def tcp_packet_handler_from_client(pkt):
	tcp_packet_handler(pkt, 0)

def tcp_packet_handler_from_server(pkt):
	tcp_packet_handler(pkt, 1)
