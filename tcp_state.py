#!/usr/bin/env python
#coding=utf-8

'''
	BigBro @ 2021.04/05
'''

TCP_TYPE_NONE = 0
TCP_TYPE_SYN = 1
TCP_TYPE_SYNACK = 2
TCP_TYPE_RST = 3
TCP_TYPE_FIN = 4
TCP_TYPE_ACK = 5
TCP_TYPE_PSH = 6

tcp_flags_fin=0x01
tcp_flags_syn=0x02
tcp_flags_rst=0x04
tcp_flags_psh=0x08
tcp_flags_ack=0x10

tcp_flags_synack=(tcp_flags_syn|tcp_flags_ack)
tcp_flags_pshack=(tcp_flags_psh|tcp_flags_ack)
tcp_flags_finack=(tcp_flags_fin|tcp_flags_ack)
tcp_flags_rstack=(tcp_flags_rst|tcp_flags_ack)

TCP_SYN_SENT = 1
TCP_SYN_RECV = 2
TCP_ESTABLISHED = 3
TCP_FIN_WAIT = 4

# packet & direction
tcp_session_client_rst = 0x10
tcp_session_server_rst = 0x20
tcp_session_client_fin = 0x40
tcp_session_server_fin = 0x80

# recv fin from client
TCP_SESSION_SUBSTATE_CLIENT_FIN = 0x01
# recv ack from client
TCP_SESSION_SUBSTATE_CLIENT_ACK = 0x02
# recv fin from server
TCP_SESSION_SUBSTATE_SERVER_FIN = 0x04
# recv ack from server
TCP_SESSION_SUBSTATE_SERVER_ACK = 0x08
# recv RST or 2 FINs & 2 ACKs
TCP_SESSION_SUBSTATE_CLOSED = 0x0f

'''
	key
		sip, sport, dpi, dport
	value
		state		=>	TCP State
		isn 		=>	initial seq number of Proxy -> Client
		time		=>	last updated time
		flags		=>	seen syn ?
		substate	=>	substate state while state is TCP_FIN_WAIT
		window		=>	window of 3-way handshake ACK from client
		offset		=>	the offset of seq/ack number between the client and the server
'''
sessions = {}
tcp_pkt_flags = {
	TCP_TYPE_NONE : "No Flags",
	TCP_TYPE_SYN : "SYN",
	TCP_TYPE_SYNACK : "SYN + ACK",
	TCP_TYPE_RST : "RST",
	TCP_TYPE_FIN : "FIN",
	TCP_TYPE_ACK : "ACK",
	TCP_TYPE_PSH : "PSH",

	TCP_TYPE_RST + TCP_TYPE_ACK : "RST + ACK",
	TCP_TYPE_FIN + TCP_TYPE_ACK : "FIN + ACK",
	TCP_TYPE_PSH + TCP_TYPE_ACK : "PSH + ACK",
}

tcp_session_states = {
	TCP_SYN_SENT 	: "SYN_SENT",
	TCP_SYN_RECV 	: "SYN_RECV",
	TCP_ESTABLISHED : "ESTABLISHED",
	TCP_FIN_WAIT 	: "FIN_WAIT",
}

TCP_SESSION_FLAG_SEEN_SYN = 0x01
TCP_SESSION_FLAG_EXPIRED = 0x02

tcp_session_destroy_first_pkt_dir = {
	tcp_session_client_rst : "first RST is from Client",
	tcp_session_server_rst : "first RST is from Server",
	tcp_session_client_fin : "first FIN is from Client",
	tcp_session_server_fin : "first FIN is from server",
}

def tcp_flags_check(flags):
	ack = 0
	if (flags & tcp_flags_ack):
		ack = TCP_TYPE_ACK
	if (flags & tcp_flags_syn):
		if (flags & tcp_flags_ack):
			return [TCP_TYPE_SYNACK, 0]
		return [TCP_TYPE_SYN, 0]
	elif (flags & tcp_flags_rst):
		return [TCP_TYPE_RST, ack]
	elif (flags & tcp_flags_fin):
		return [TCP_TYPE_FIN, ack]
	elif (flags & tcp_flags_ack):
		if (flags & tcp_flags_psh):
			return [TCP_TYPE_ACK, TCP_TYPE_PSH]
		else :
			return [TCP_TYPE_ACK, 0]
	elif (flags & tcp_flags_psh):
		return [TCP_TYPE_PSH, 0]
	else :
		return [TCP_TYPE_NONE, 0]
