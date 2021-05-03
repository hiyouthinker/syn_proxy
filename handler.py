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

	print "[%s:%d => %s:%d], flags: %s" % (sip, sport, dip, dport, tcp_state.tcp_pkt_flags[index])

	if ((dir == 0) and (sport == 80 and dport != 80)):
		# local -> client, ignore
		return
	elif ((dir == 1) and (dport == 80 and sport != 80)):
		# local -> server, ignore
		return

#	print "[%s:%d => %s:%d], flags: %s" % (sip, sport, dip, dport, tcp_state.tcp_pkt_flags[index])

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
					return
				else :
					print "TCP 3-way handshake with client was completed successfully"
					print "I will conect to backend"
					# seq is initial seq of Client -> Proxy
					seq = pkt[TCP].seq - 1
					# ack is initial seq of Proxy -> Client
					ack = pkt[TCP].ack - 1
					value = (tcp_state.TCP_SYN_SENT, ack, time.time(), 0)
					# OK, this is a valid client, create the session
					tcp_state.sessions.update({key : value})
					utils.send_syn_to_server(sip, dip, sport, dport, seq)
			else :
				print "invalid packet, drop the packet"
		return
	else :
		value = tcp_state.sessions.get(key)
		state = value[0]
		offset = value[1]
		now = value[2]
		session_flags = value[3]
		print "current state of session: %s/%s" % (tcp_state.tcp_session_states[state], tcp_state.tcp_pkt_flags[index])
		# SYN
		if (index == 1):
			if (time.time() - now > tcp_session_timeout[state]) :
				print "session timeout"
				send_synack_to_client(pkt)
				value = (value[0], value[1], value[2], tcp_state.TCP_SESSION_FLAG_SEEN_SYN)
				tcp_state.sessions.update({key : value})
			else :
				print "session isn't expired, drop the SYN"
			return
		elif (index == 2):
			if (dir == 0):
				print "invalid packet, INGRE!!!"
				return
			else :
				seq = pkt[TCP].seq
				ack = pkt[TCP].ack
				offset = seq - value[1]
				value = (tcp_state.TCP_ESTABLISHED, offset, time.time(), 0)
				# update state
				tcp_state.sessions.update({key : value})
				print "send ACK to backend"
				print "TCP 6-way handshake with client/server was completed successfully"
				utils.send_ack_to_server(dip, sip, dport, sport, seq=ack, ack=seq+1)
				return
		# ACK
		elif (index == 6):
			if ((dir == 0) and ((session_flags & tcp_state.TCP_SESSION_FLAG_SEEN_SYN) or (state == tcp_state.TCP_SYN_SENT))):
				if (utils.tcp_syn_cookie_check(pkt[TCP].ack) == False):
					print "Invalid ACK, drop the packet"
				else :
					seq = pkt[TCP].seq - 1
					ack = pkt[TCP].ack - 1
					value = (tcp_state.TCP_SYN_SENT, ack, time.time(), 0)
					print "Valid ACK, I will reconect to backend"
					utils.send_syn_to_server(sip, dip, sport, dport, seq)
				return
			elif ((dir == 1) and (state == tcp_state.TCP_SYN_SENT)):
				print "What packet is it, IGNORE"
				return
			# ESTABLISHED or FIN_WAIT
			else :
			#	pkt1 = pkt.payload
			#	if (dir == 0):
			#		pkt1[TCP].ack = pkt[TCP].ack + value[1]
			#	else :
			#		pkt1[TCP].seq = pkt[TCP].seq - value[1]
			#	tcp.checksum needs to be modified
			#	send(pkt1)
				if (dir == 0):
					print "forward the ACK packet to backend"
					l3 = IP(src=sip, dst=dip)/TCP(sport=sport, dport=dport, flags=flags, seq=pkt[TCP].seq, ack=pkt[TCP].ack + value[1])
				else :
					print "forward the ACK packet to client"
					l3 = IP(src=sip, dst=dip)/TCP(sport=sport, dport=dport, flags=flags, seq=pkt[TCP].seq - value[1], ack=pkt[TCP].ack)
				send(l3, verbose=False)
				return
		# FIN/PSH/RST
		else :
			# This is invalid packet, because window size is 0
			if (state == tcp_state.TCP_SYN_SENT) :
				print "This is invalid packet, because window size is 0, DROP it"
				return
			# RST or FIN
			if (index == 4 or index == 5):
				value = (tcp_state.TCP_FIN_WAIT, value[1], value[2], value[3])
				tcp_state.sessions.update({key : value})

			if (index == 3):
				str = pkt.load
				if ((len(str) >= 1) and (str[len(str) - 1] == '\n')):
					str = str[0 : len(str) - 1] + "\\n"

				if (dir == 0):				
					print "forward the PSH packet [%s] to backend" % str
					l3 = IP(src=sip, dst=dip)/TCP(sport=sport, dport=dport, flags=flags, seq=pkt[TCP].seq, ack=pkt[TCP].ack + value[1])/pkt.load
				else :
					print "forward the PSH packet [%s] to client" % str
					l3 = IP(src=sip, dst=dip)/TCP(sport=sport, dport=dport, flags=flags, seq=pkt[TCP].seq - value[1], ack=pkt[TCP].ack)/pkt.load
			else :
				if (dir == 0):
					print "forward the FIN/RST packet to backend"
					l3 = IP(src=sip, dst=dip)/TCP(sport=sport, dport=dport, flags=flags, seq=pkt[TCP].seq, ack=pkt[TCP].ack + value[1])
				else :
					print "forward the FIN/RST packet to client"
					l3 = IP(src=sip, dst=dip)/TCP(sport=sport, dport=dport, flags=flags, seq=pkt[TCP].seq - value[1], ack=pkt[TCP].ack)
			send(l3, verbose=False)
			return

def tcp_packet_handler_from_client(pkt):
	tcp_packet_handler(pkt, 0)

def tcp_packet_handler_from_server(pkt):
	tcp_packet_handler(pkt, 1)
