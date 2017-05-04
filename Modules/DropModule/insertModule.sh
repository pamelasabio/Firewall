#!/bin/bash

# Inserts module to the kernel
insmod drop.ko
# Will display init function
dmesg | tail -1

# Removes the module from the kernel
rmmod drop.ko
# Will display exit function
dmesg | tail -1
