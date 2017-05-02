# Firewall Guide

## Table Of Contents

* <a href="#installation">Installation</a>
* <a href="#commands">Commands</a>
  * <a href="#list">List</a>
  * <a href="#accept">Accept</a>
  * <a href="#drop">Drop</a>
  * <a href="#save">Save</a>
  * <a href="#flush">Flush</a>
* <a href="#kernel">Kernel</a>
  * <a href="#kernelUtitilies">Commands</a>
* <a href="#resources">Resources</a>
  


<a id ="#installation"></a>
## Installation
IP Tables almost always comes pre-installed on linux, if that is not the case then it can be installed using:

```command line
sudo apt-get install iptables
```

<a id ="#commands"></a>
## Commands

<a id ="#list"></a>
#### List
To see what your policy chains are currently configured to do with unmatched traffic.

```cmd
iptables -L
```

To display detailed information (show the interface name, the rule options, the TOS masks and the packet and byte counters) **-v** can be added.</br>
To display IP address and port in numeric format. Do not use DNS to resolve names. This will speed up listing. Use **-n**.

```cmd
iptables -L -v -n --line-numbers
```

To display incomming and outgoing connection rules.

```cmd
# iptables -L INPUT -n -v
# iptables -L OUTPUT -n -v --line-numbers
```


<a id ="#accept"></a>
#### Accept
The command to accept connections by default.

```cmd
iptables --policy INPUT ACCEPT
iptables --policy OUTPUT ACCEPT
iptables --policy FORWARD ACCEPT
```

SSH connections FROM 10.10.10.10 are permitted, but SSH connections TO 10.10.10.10 are not. However, the system is permitted to send back information over SSH as long as the session has already been established, which makes SSH communication possible between these two hosts.

```
iptables -A INPUT -p tcp --dport ssh -s 10.10.10.10 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -d 10.10.10.10 -m state --state ESTABLISHED -j ACCEPT
```

<a id ="#drop"></a>
#### Drop
The command to drop connections by default.

```cmd
iptables --policy INPUT DROP
iptables --policy OUTPUT DROP
iptables --policy FORWARD DROP
```

Example of dropping a connection:

```cmd
iptables -A INPUT -s 10.10.10.10 -j DROP      // SINGLE IP
iptables -A INPUT -s 10.10.10.0/24 -j DROP    // RANGE OF IPS
```

Example for dropping specific port:

```cmd
iptables -A INPUT -p tcp --dport ssh -j DROP                    // DROPS ANY SSH CONNECTION
iptables -A INPUT -p tcp --dport ssh -s 10.10.10.10 -j DROP     // DROPS SSH CONNECITON FROM SPECIFIED IP
```

<a id ="#saving"></a>
#### Save
To save on ubuntu:

```cmd
sudo /sbin/iptables-save
```

<a id ="#flush"></a>
#### Flush
To clear the current rules, flush command can be used.

```cmd
iptables -F
```

<a id ="#kernel"></a>

## Kernel Module

<a id = "#kernelUtitilies"> </a>

### Utilities to Manipulate Kernel Modules

#### lsmod
Lsmod will show currentely loaded modules into the kernel.

```cmd
# lsmod
Module                  Size  Used by
dm_crypt               24803  1 
hid_generic            16545  0
usb_hid                24265  1 
..
```

#### insmod
Insmod inserts new module into the Kernel Modules.

```cmd
# insmod /lib/modules/3.5.0-19-generic/kernel/fs/squashfs/squashfs.ko

# lsmod | grep "squash"
squashfs               24214  1
```

#### modinfo
Modinfo will display information about the module.

```cmd
# modinfo /lib/modules/3.5.0-19-generic/kernel/drivers/net/fjes/fjes.ko

filename:       /lib/modules/3.5.0-19-generic/kernel/drivers/net/fjes/fjes.ko
version:        1.1
license:        GPL
author:         Taku Izumi
description:    Socket Network Device Driver
srcversion:     3411C5E01C7BDA50105EEE7
depends:        
intree:         Y
vermagic:       3.5.0-19-generic SMP mod_unload modversions 686
```

#### rmmod
Removes module from the kernel

```cmd
rmmod fjes.ko
```

<a id ="#resources"></a>
## Resources

### <a href="https://www.howtogeek.com/177621/the-beginners-guide-to-iptables-the-linux-firewall/">The Beginner’s Guide to iptables, the Linux Firewall</a>

### <a href="https://www.cyberciti.biz/tips/linux-iptables-examples.html">Linux: 20 Iptables Examples For New SysAdmins</a>

### <a href="https://www.digitalocean.com/community/tutorials/iptables-essentials-common-firewall-rules-and-commands">Iptables Essentials: Common Firewall Rules and Commands</a>

