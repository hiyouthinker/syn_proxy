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
	tcp_state.TCP_SYN_SENT : [10, 60],
	tcp_state.TCP_SYN_RECV : [10, 60],
	tcp_state.TCP_ESTABLISHED : [1800, 3600],
	tcp_state.TCP_FIN_WAIT : [10, 60],
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

def get_tcp_payload_length(pkt):
	ip_hdr_len = pkt[IP].len - pkt[IP].ihl * 4
	tcp_hdr_len = pkt[TCP].dataofs * 4
	return (ip_hdr_len - tcp_hdr_len)

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
	type = tcp_state.tcp_flags_check(flags)
	state = value["state"]
	substate = value["substate"]
	window = pkt[TCP].window
	target = tcp_state.tcp_pkt_flags[type[0] + type[1]]

	len = get_tcp_payload_length(pkt)

	# fresh the time
	value["time"] = time.time()
	tcp_state.sessions[key] = value

	# ACK/FIN
	if (type[0] == tcp_state.TCP_TYPE_FIN or type[0] == tcp_state.TCP_TYPE_ACK):
		# FIN usually carry the ACK flag
		if (state == tcp_state.TCP_FIN_WAIT):
			if ((dir == 0) and (substate & tcp_state.TCP_SESSION_SUBSTATE_SERVER_FIN)):
				substate |= tcp_state.TCP_SESSION_SUBSTATE_CLIENT_ACK
			elif ((dir == 1) and (substate & tcp_state.TCP_SESSION_SUBSTATE_CLIENT_FIN)):
				substate |= tcp_state.TCP_SESSION_SUBSTATE_SERVER_ACK

		# FIN
		if (type[0] == tcp_state.TCP_TYPE_FIN):
			if (dir == 0):
				# xx00 0000, xx is FIN bit field
				if ((substate & 0xc0) == 0):
					substate |= tcp_state.tcp_session_client_fin
				substate |= tcp_state.TCP_SESSION_SUBSTATE_CLIENT_FIN
			else :
				if ((substate & 0xc0) == 0):
					substate |= tcp_state.tcp_session_server_fin
				substate |= tcp_state.TCP_SESSION_SUBSTATE_SERVER_FIN
	# RST
	elif (type[0] == tcp_state.TCP_TYPE_RST) :
		if (dir == 0):
			# 00xx 0000, xx is RST bit field
			if ((substate & 0x30) == 0):
				substate |= tcp_state.tcp_session_client_rst
			substate |= tcp_state.TCP_SESSION_SUBSTATE_CLOSED
		else :
			if ((substate & 0x30) == 0):
				substate |= tcp_state.tcp_session_server_rst
			substate |= tcp_state.TCP_SESSION_SUBSTATE_CLOSED

	if (substate != value["substate"]):
		value["state"] = tcp_state.TCP_FIN_WAIT
		value["substate"] = substate
		tcp_state.sessions[key] = value

	if (dir == 0):
		ack = pkt[TCP].ack
		if ((type[0] == tcp_state.TCP_TYPE_RST) and (type[1] == 0)):
			# should be zero
			print "ack number of RST is %d" % ack
			if (ack != 0):
				print "Please note: Unknown packet was found!"
		else :
			ack += offset
			if ((ack < 0) or (ack > 4294967295)):
				print "Invalid ACK Number (%d), attack packet? drop the packet" % (pkt[TCP].ack)
				return

		if (len > 0) :
			str = pkt.load.replace('\n', '\\n')
			print "forward the %s packet [%s] to backend" % (target, str)
			l3 = IP(src=sip, dst=dip)/TCP(sport=sport, dport=dport, flags=flags, seq=pkt[TCP].seq, ack=ack, window=window)/pkt.load
		else :
			print "forward the %s packet to backend" % (target)
			l3 = IP(src=sip, dst=dip)/TCP(sport=sport, dport=dport, flags=flags, seq=pkt[TCP].seq, ack=ack, window=window)
	else :
		seq = pkt[TCP].seq
		if (type[0] == tcp_state.TCP_TYPE_RST):
			if (state == tcp_state.TCP_SYN_SENT):
				print "The port of server is not open? (seq: %d)" % seq
				# This is a RST + ACK for syn
				# seq (value["isn"]) is 0, need to correct the seq number
				seq = value["isn"] + 1
			else :
				# for example: When the connection has been closed, the server received the data from the client
				seq -= offset
		else :
			seq -= offset

		if ((seq < 0) or (seq > 4294967295)):
			print "Please note: Unknown packet was found!"
			print "seq from server is invalid (%d/%d), change the seq to 0x123456" % (pkt[TCP].seq, offset)
			seq = 0x123456

		if (len > 0) :
			str = pkt.load.replace('\n', '\\n')
			print "forward the %s packet [%s] to backend" % (target, str)
			l3 = IP(src=sip, dst=dip)/TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=pkt[TCP].ack, window=window)/pkt.load
		else :
			print "forward the %s packet to client" % (target)
			l3 = IP(src=sip, dst=dip)/TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=pkt[TCP].ack, window=window)
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
		state = value["state"]
		status = "Active"

		if (value["flags"] & tcp_state.TCP_SESSION_FLAG_EXPIRED):
			status = "Expired"
		if (value["flags"] & tcp_state.TCP_SESSION_FLAG_SEEN_SYN):
			status += " & SEEN SYN"

		if (state == tcp_state.TCP_FIN_WAIT):
			substate = ""
			if (value["substate"] & 0xc0):
				substate = tcp_state.tcp_session_destroy_first_pkt_dir[value["substate"] & 0xc0]
			if (value["substate"] & 0x30):
				if (len(substate) != 0):
					substate += "/" + tcp_state.tcp_session_destroy_first_pkt_dir[value["substate"] & 0x30]
				else :
					substate = tcp_state.tcp_session_destroy_first_pkt_dir[value["substate"] & 0x30]
			print ("\t[%s:%d => %s:%d], last_time: %d, offset: %d, status: %s, state: %s/0x%02x (%s)"
				% (key[0], key[1], key[2], key[3], value["time"], value["offset"], status,
				tcp_state.tcp_session_states[state],
				(value["substate"] & 0x0f), substate))
		else :
			print ("\t[%s:%d => %s:%d], last_time: %d, offset: %s, status: %s, state: %s"
				% (key[0], key[1], key[2], key[3], value["time"], value["offset"], status, tcp_state.tcp_session_states[state]))

		if ((time.time() - value["time"]) > tcp_session_timeout[state][1]):
			print "\t\t(this session was expired, will be removed)"
			del tcp_state.sessions[key]
		elif ((time.time() - value["time"]) > tcp_session_timeout[state][0]):
			value["flags"] |= tcp_state.TCP_SESSION_FLAG_EXPIRED
			tcp_state.sessions[key] = value
		elif (value["flags"] & tcp_state.TCP_SESSION_FLAG_EXPIRED):
			value["flags"] &= ~tcp_state.TCP_SESSION_FLAG_EXPIRED
			tcp_state.sessions[key] = value