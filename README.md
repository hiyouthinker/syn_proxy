# SYN Proxy
TCP SYN Proxy
## 1 Introduction
```
This is a Scapy-based TCP SYN Proxy, its function is similar to ipatbles SYNPROXY
```
## 2 test
### 2.1 environment
```
   client    <-->   SYN Proxy	<->		server
172.50.1.65       172.50.1.66			172.50.2.67

client
    None
SYN Proxy

server
	iptables -t filter -A FORWARD -i eth1 -p tcp -m tcp --dport 8080 -j DROP
    iptables -t filter -A FORWARD -i eth2 -p tcp -m tcp --sport 8080 -j DROP
```
### 2.2 start testing
```
client
    root@lab1:~# nc 172.50.2.67 8080

SYN Proxy
    root@lab2:~/syn_proxy# python main.py

server
	root@lab3:~# nc -l 8080
```
### 2.3 results
```
root@lab2:~/syn_proxy# python main.py
capture TCP packet of port 8080 from client on eth1
capture TCP packet of port 8080 from server on eth2

[172.50.1.65:60668 => 172.50.2.67:8080], flags: SYN
Session was not found, pkt: SYN
receive SYN, send SYN + ACK to client

[172.50.1.65:60668 => 172.50.2.67:8080], flags: ACK
Session was not found, pkt: ACK
TCP 3-way handshake with client was completed successfully
I will conect to backend

[172.50.2.67:8080 => 172.50.1.65:60668], flags: SYN + ACK
current state of session: TCP_SYN_SENT
send ACK to backend
TCP 6-way handshake with client/server was completed successfully

[172.50.1.65:60668 => 172.50.2.67:8080], flags: ACK
current state of session: TCP_ESTABLISHED
forward the ACK packet to backend

[172.50.2.67:8080 => 172.50.1.65:60668], flags: ACK
current state of session: TCP_ESTABLISHED
forward the ACK packet to client

[172.50.1.65:60668 => 172.50.2.67:8080], flags: PSH
current state of session: TCP_ESTABLISHED
forward the PSH packet [123456\n] to backend

[172.50.2.67:8080 => 172.50.1.65:60668], flags: ACK
current state of session: TCP_ESTABLISHED
forward the ACK packet to client

session table: 1 item(s)
	[172.50.1.65:60668 => 172.50.2.67:8080], state: TCP_ESTABLISHED
```
## 3 Limits
```
	does not support NAT (snat/dnat)
```
