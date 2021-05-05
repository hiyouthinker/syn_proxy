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
	index = tcp_state.tcp_flags_check(flags)
	found = False

	print "\n[%s:%d => %s:%d], flags: %s" % (sip, sport, dip, dport, tcp_state.tcp_pkt_flags[index])

	if ((dir == 0) and (sport == 80 and dport != 80)):
		# local -> client, ignore
		return
	elif ((dir == 1) and (dport == 80 and sport != 80)):
		# local -> server, ignore
		return

	if ((index == 1) and (dir == 1)):
		print "recv SYN from server, drop the packet"
		return

	if (dir == 0):
		key = (sip, sport, dip, dport)
	else :
		key = (dip, dport, sip, sport)

	if (tcp_state.sessions.has_key(key)) :
		found = True

	if (found == False) :
		print "Session was not found, pkt: %s" % tcp_state.tcp_pkt_flags[index]
		if (index == 1):
			utils.send_synack_to_client(pkt)
		else :
			if (index == 6):
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
#					value = (tcp_state.TCP_SYN_SENT, ack, time.time(), 0, 0)
#					tcp_state.sessions.update({key : value})
					value = [tcp_state.TCP_SYN_SENT, ack, time.time(), 0, 0]
					tcp_state.sessions[key] = value
				utils.send_syn_to_server(sip, dip, sport, dport, seq)
			else :
				print "invalid packet, drop the packet"
	else :
		value = tcp_state.sessions.get(key)
		state = value[0]
		offset = value[1]
		now = value[2]
		session_flags = value[3]
		print "current state of session: %s" % (tcp_state.tcp_session_states[state])
		# SYN
		if (index == 1):
			if (time.time() - now > tcp_session_timeout[state]) :
				print "session timeout"
				send_synack_to_client(pkt)
#				value = (value[0], value[1], value[2], tcp_state.TCP_SESSION_FLAG_SEEN_SYN, value[4])
#				tcp_state.sessions.update({key : value})
				value[3] = tcp_state.TCP_SESSION_FLAG_SEEN_SYN
				tcp_state.sessions[key] = value
			else :
				print "session isn't expired, drop the SYN"
		# SYN + ACK
		elif (index == 2):
			if (dir == 0):
				print "invalid packet, INGRE!!!"
			else :
				seq = pkt[TCP].seq
				ack = pkt[TCP].ack
				offset = seq - value[1]
				# update the session
#				value = (tcp_state.TCP_ESTABLISHED, offset, time.time(), 0, 0)
#				tcp_state.sessions.update({key : value})
				value = [tcp_state.TCP_ESTABLISHED, offset, time.time(), 0, 0]
				tcp_state.sessions[key] = value
				print "TCP 6-way handshake with client/server was completed successfully"
				print "send ACK to backend"
				utils.send_ack_to_server(dip, sip, dport, sport, seq=ack, ack=seq+1)
		# ACK
		elif (index == 6):
			if ((dir == 0) and ((session_flags & tcp_state.TCP_SESSION_FLAG_SEEN_SYN) or (state == tcp_state.TCP_SYN_SENT))):
				if (utils.tcp_syn_cookie_check(pkt[TCP].ack) == False):
					print "Invalid ACK, drop the packet"
				else :
					seq = pkt[TCP].seq - 1
					ack = pkt[TCP].ack - 1
#					value = (tcp_state.TCP_SYN_SENT, ack, time.time(), 0, 0)
					value = [tcp_state.TCP_SYN_SENT, ack, time.time(), 0, 0]
					print "Valid ACK, I will reconect to backend"
					utils.send_syn_to_server(sip, dip, sport, dport, seq)
			elif ((dir == 1) and (state == tcp_state.TCP_SYN_SENT)):
				print "What packet is it, IGNORE"
			# ESTABLISHED or FIN_WAIT
			else :
				utils.forwar_pkt_to_client_server(key, value, dir, pkt, value[1])
		# FIN/PSH/RST
		else :
			# This is invalid packet, because window size is 0
			if (state == tcp_state.TCP_SYN_SENT) :
				print "This is invalid packet, because window size is 0, DROP it"
				return
			utils.forwar_pkt_to_client_server(key, value, dir, pkt, value[1])

def tcp_packet_handler_from_client(pkt):
	tcp_packet_handler(pkt, 0)

def tcp_packet_handler_from_server(pkt):
	tcp_packet_handler(pkt, 1)
