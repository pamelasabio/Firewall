#!/bin/bash
# This is necessary (Only needs to be done once.)
# If cannot execute, then set privilages e.g. chmod 777 headers.sh


echo Installing Headers.. 
apt-get install build-essential linux-headers-$(uname -r)

