#!/bin/bash

# Inserts module to the kernel
#insmod drop.ko
insmod firewall.ko
# Will display init function
dmesg | tail -1

# Removes the module from the kernel
#rmmod drop.ko
#rmmod firewall.ko
# Will display exit function
#dmesg | tail -1
