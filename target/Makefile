MODULE_NAME=dm_ephemeral
KERNEL_SOURCE_PATH=/lib/modules/$(shell uname -r)/build

obj-m += $(MODULE_NAME).o

all:
	make -C $(KERNEL_SOURCE_PATH) M=$(PWD) modules

clean:
	make -C $(KERNEL_SOURCE_PATH) M=$(PWD) clean

##==============================================================================
##
## manage installation of module
##
##==============================================================================

MODULE_NAME=dm_ephemeral

up:
	@ ( sudo insmod $(MODULE_NAME).ko || /bin/true )
	@ $(MAKE) -s ls

down:
	@ ( sudo rmmod $(MODULE_NAME) || /bin/true )

ls:
	@ sudo lsmod | ( grep $(MODULE_NAME) || /bin/true )

re:
	- $(MAKE) rmmod 2> /dev/null
	- $(MAKE) up
