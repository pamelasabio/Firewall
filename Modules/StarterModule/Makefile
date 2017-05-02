obj-m += starterModule.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

# Make file 

#make -C /lib/modules/3.5.0-19-generic/build M=/Home/Desktop/Beihang/Security/Modules/StarterModule #removed modules
#make[1]: Entering directory `/usr/src/linux-headers-3.5.0-19-generic'
#	CC [M]  /home/Desktop/Beihang/Security/Modules/StarterModule/starterModule.o
#  	Building modules, stage 2.
#	MODPOST 1 modules
#	CC      /home/Desktop/Beihang/Security/Modules/StarterModule/starterModule.mod.o
#	LD [M]  /home/Desktop/Beihang/Security/Modules/StarterModule/starterModule.ko
#make[1]: Leaving directory `/usr/src/linux-headers-3.5.0-19-generic'
