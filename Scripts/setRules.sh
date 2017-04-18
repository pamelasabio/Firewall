#!/bin/bash
#Script to set up ip tables rules.
#Eryk Szlachetka 18/04/17

interface=$1
echo Interface: $interface. 
echo Setting SSH INPUT..

#Allow established input SSH connection
iptables -A INPUT -i $interface -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

echo Setting SSH OUTPUT..

#Allow new and established output SSH connection
iptables -A OUTPUT -o $interface -p tcp --sport 22 -m state --state NEW,ESTABLISHED -j ACCEPT 

echo Setting HTTP/S OUTPUT
#Allow new,established and related http and https output connections
iptables -A OUTPUT -j ACCEPT -m state --state NEW,ESTABLISHED,RELATED -o $interface -p tcp -m multiport --dports 80,443

echo Setting HTTP/S INPUT
#Allow established,related http and https input connections
iptables -A INPUT -j ACCEPT -m state --state ESTABLISHED,RELATED -i $interface -p tcp -m multiport --sports 80,443

echo Done
echo 
echo New Rules:
iptables -L
