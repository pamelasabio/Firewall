#!/bin/bash

# Remove the kernel files
rm .*
rm modules.order Module.symvers *.ko *.mod.c *.o 
rm -r .tmp_versions
