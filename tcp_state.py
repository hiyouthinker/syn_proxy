#!/usr/bin/env python
#coding=utf-8

'''
	BigBro @ 2021.04/05
'''

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
tcp_session_client_fin = 0x30
tcp_session_server_fin = 0x40

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
		offset 		=>	seq1 of Proxy -> Client - seq2 of Serevr -> Proxy
		time		=>	last updated time
		flags		=>	seen syn ?
		substate	=>	substate state while state is TCP_FIN_WAIT
		window		=>	window of 3-way handshake ACK from client
'''
sessions = {}
tcp_pkt_flags = {0 : "No Flags", 1 : "SYN", 2 : "SYN + ACK", 3 : "PSH", 4 : "RST", 5 : "FIN", 6 : "ACK"}
tcp_session_states = {
	TCP_SYN_SENT 	: "SYN_SENT",
	TCP_SYN_RECV 	: "SYN_RECV",
	TCP_ESTABLISHED : "ESTABLISHED",
	TCP_FIN_WAIT 	: "FIN_WAIT",
}

TCP_SESSION_FLAG_SEEN_SYN = 0x01
TCP_SESSION_FLAG_EXPIRED = 0x02

tcp_session_destroy_first_pkt_dir = {
	tcp_session_client_rst : "RST is from Client",
	tcp_session_server_rst : "RST is from Server",
	tcp_session_client_fin : "FIN is from Client",
	tcp_session_server_fin : "FIN is from server",
}

def tcp_flags_check(flags):
	if (flags & tcp_flags_syn):
		if (flags & tcp_flags_ack):
			return 2
		return 1
	elif (flags & tcp_flags_psh):
		return 3
	elif (flags & tcp_flags_rst):
		return 4
	elif (flags & tcp_flags_fin):
		return 5
	elif (flags & tcp_flags_ack):
		return 6
	else :
		return 0
