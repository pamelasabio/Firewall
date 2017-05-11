#!/bin/bash
#Script to set up ip tables rules.
#Eryk Szlachetka & Caoimhe Harvey 18/04/17 

echo Setting SSH INPUT..
#Allow established input SSH connection
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT


echo Setting SSH OUTPUT..
#Allow NEW,ESTABLISHED output SSH connection
iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

echo Setting HTTP/S INPUT..
#Allow NEW,ESTABLISHED,RELATED http and https output connections
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

echo Setting HTTP/S OUTPUT..
#Allow ESTABLISHED,RELATED http and https input connections
iptables -A OUTPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT

echo Setting UDP/TCP OUTPUT..
#Allow NEW udp/tcp output connections
iptables -A OUTPUT -m state --state NEW -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -m state --state NEW -p tcp --dport 53 -j ACCEPT

echo Setting UDP/TCP INPUT..
#Allow ESTABLISHED udp/tcp input connections
iptables -A INPUT -m state --state ESTABLISHED -p udp --sport 53 -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED -p tcp --sport 53 -j ACCEPT

echo Setting SMTP INPUT..
#Allow SMTP connections INPUT
iptables -A INPUT -p tcp --dport 25 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

echo Setting SMTP OUTPUT..
#Allow SMTP connection OUTPUT
iptables -A OUTPUT -p tcp --sport 25 -m conntrack --ctstate ESTABLISHED -j ACCEPT

echo Done
echo 
echo New Rules:
iptables -L
