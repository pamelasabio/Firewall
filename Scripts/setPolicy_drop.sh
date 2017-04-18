#!/bin/bash
#Script to set up ip tables policy to drop.
#Eryk Szlachetka 18/04/17

echo Setting INPUT to drop.
iptables --policy INPUT DROP
echo Setting OUTPUT to drop.
iptables --policy OUTPUT DROP
echo Setting FORWARD to drop.
iptables --policy FORWARD DROP
echo 
echo DONE.
echo 
echo New rules:
iptables -S
