#!/bin/bash
#Script to set up ip tables policy to drop.
#Eryk Szlachetka 18/04/17

echo Setting INPUT to ACCEPT.
iptables --policy INPUT ACCEPT
echo Setting OUTPUT to ACCEPT.
iptables --policy OUTPUT ACCEPT
echo Setting FORWARD to ACCEPT.
iptables --policy FORWARD ACCEPT
echo 
echo DONE.
echo 
echo New rules:
iptables -S
