#!/usr/bin/env python
#coding=utf-8

'''
	BigBro @ 2021.04/05
'''
from scapy.all import *
import signal
import os

import tcp_state

tcp_session_timeout = {
	tcp_state.TCP_SYN_SENT : 10,
	tcp_state.TCP_SYN_RECV : 10,
	tcp_state.TCP_ESTABLISHED : 1800,
	tcp_state.TCP_FIN_WAIT : 10,
}

def tcp_syn_cookie_get(flag):
	if (flag == 0):
		seq = random.randint(0, 4294967295)
	else :
		seq = time.time()
	return seq

def tcp_syn_cookie_check(ack):
	if (os.path.exists("/tmp/syn_cookie_test")):
		return False
	else :
		return True

'''
	reconstruct the packet instead of modifying the packet
	because the TCP checksum needs to be modified
'''
def forwar_pkt_to_client_server(key, value, dir, pkt, offset):
	sip = pkt[IP].src
	dip = pkt[IP].dst
	sport = pkt[TCP].sport
	dport = pkt[TCP].dport
	flags = pkt[TCP].flags
	index = tcp_state.tcp_flags_check(flags)
	target = "ACK"
	state = value[0]
	substate = value[4]
	window = pkt[TCP].window

	# fresh the time
	value[2] = time.time()
	tcp_state.sessions[key] = value

	# PSH
	if (index == 3):
		str = pkt.load.replace('\n', '\\n')

		if (dir == 0):
			print "forward the PSH packet [%s] to backend" % str
			l3 = IP(src=sip, dst=dip)/TCP(sport=sport, dport=dport, flags=flags, seq=pkt[TCP].seq, ack=pkt[TCP].ack + offset, window=window)/pkt.load
		else :
			print "forward the PSH packet [%s] to client" % str
			l3 = IP(src=sip, dst=dip)/TCP(sport=sport, dport=dport, flags=flags, seq=pkt[TCP].seq - offset, ack=pkt[TCP].ack, window=window)/pkt.load
		send(l3, verbose=False)
		return
	# ACK/FIN
	elif (index == 5 or index == 6):
		# FIN usually carry the ACK flag
		if (state == tcp_state.TCP_FIN_WAIT):
			if ((dir == 0) and (substate & tcp_state.TCP_SESSION_SUBSTATE_SERVER_FIN)):
				substate |= tcp_state.TCP_SESSION_SUBSTATE_CLIENT_ACK
			elif ((dir == 1) and (substate & tcp_state.TCP_SESSION_SUBSTATE_CLIENT_FIN)):
				substate |= tcp_state.TCP_SESSION_SUBSTATE_SERVER_ACK

		# FIN
		if (index == 5):
			target = "FIN"
			if (dir == 0):
				if (substate == 0):
					substate = tcp_state.tcp_session_client_fin
				substate |= tcp_state.TCP_SESSION_SUBSTATE_CLIENT_FIN
			else :
				if (substate == 0):
					substate = tcp_state.tcp_session_server_fin
				substate |= tcp_state.TCP_SESSION_SUBSTATE_SERVER_FIN
	# RST
	else :
		target = "RST"
		if (dir == 0):
			if (substate == 0):
				substate = tcp_state.tcp_session_client_rst
			substate = tcp_state.TCP_SESSION_SUBSTATE_CLOSED | tcp_state.tcp_session_client_rst
		else :
			if (substate == 0):
				substate = tcp_state.tcp_session_server_rst
			substate = tcp_state.TCP_SESSION_SUBSTATE_CLOSED | tcp_state.tcp_session_server_rst

	if (substate != value[4]):
		value = [tcp_state.TCP_FIN_WAIT, value[1], value[2], value[3], substate]
		tcp_state.sessions[key] = value

	if (dir == 0):
		print "forward the %s packet to backend" % target
		l3 = IP(src=sip, dst=dip)/TCP(sport=sport, dport=dport, flags=flags, seq=pkt[TCP].seq, ack=pkt[TCP].ack + offset, window=window)
	else :
		print "forward the %s packet to client" % target
		l3 = IP(src=sip, dst=dip)/TCP(sport=sport, dport=dport, flags=flags, seq=pkt[TCP].seq - offset, ack=pkt[TCP].ack, window=window)
	send(l3, verbose=False)

def send_syn_to_server(sip, dip, sport, dport, seq, window):
	flags = tcp_state.tcp_flags_syn
	l3 = IP(src=sip, dst=dip)/TCP(sport=sport, dport=dport, flags=flags, seq=seq, window=window)
	send(l3, verbose=False)
	return

def send_ack_to_server(sip, dip, sport, dport, seq, ack, window):
	flags = tcp_state.tcp_flags_ack
	l3 = IP(src=sip, dst=dip)/TCP(sport=sport, dport=dport, flags=flags,seq=seq, ack=ack, window=window)
	send(l3, verbose=False)
	return

def send_synack_to_client(pkt):
	sip = pkt[IP].src
	dip = pkt[IP].dst
	sport = pkt[TCP].sport
	dport = pkt[TCP].dport
	flags = tcp_state.tcp_flags_synack
	seq = tcp_syn_cookie_get(0)
	ack = pkt[TCP].seq + 1

	l3 = IP(src=dip, dst=sip)/TCP(sport=dport, dport=sport, flags=flags,seq=seq,ack=ack, window = 0)
	send(l3, verbose=False)
	print "receive SYN, send SYN + ACK to client"

def show_tcp_all_sessions():
	keys = tcp_state.sessions.keys()
	print "\nsession table: %d item(s)" % len(keys)
	for key in keys :
		value = tcp_state.sessions.get(key)
		state = value[0]
		status = "Active"

		if (value[3] & tcp_state.TCP_SESSION_FLAG_EXPIRED):
			status = "Expired"
		if (value[3] & tcp_state.TCP_SESSION_FLAG_SEEN_SYN):
			status += " & SEEN SYN"

		if (state == tcp_state.TCP_FIN_WAIT):
			print ("\t[%s:%d => %s:%d], last_time: %d, offset: %d, status: %s, state: %s/0x%02x (first %s)"
				% (key[0], key[1], key[2], key[3], value[2], value[1], status,
				tcp_state.tcp_session_states[state],
				(value[4] & 0x0f),
				tcp_state.tcp_session_destroy_first_pkt_dir[value[4] & 0xf0]))
		else :
			print ("\t[%s:%d => %s:%d], last_time: %d, offset: %s, status: %s, state: %s"
				% (key[0], key[1], key[2], key[3], value[2], value[1], status, tcp_state.tcp_session_states[state]))

		if ((time.time() - value[2]) > tcp_session_timeout[state]):
			if (0):
				print "\t\t(this session was expired, will be removed)"
				del tcp_state.sessions[key]
			else :
				value[3] |= tcp_state.TCP_SESSION_FLAG_EXPIRED
				tcp_state.sessions[key] = value
		else :
			value[3] &= ~tcp_state.TCP_SESSION_FLAG_EXPIRED
			tcp_state.sessions[key] = value