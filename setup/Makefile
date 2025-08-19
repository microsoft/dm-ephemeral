##==============================================================================
##
## build rules for ephemeralsetup
##
## Example:
## 	dmsetup create xyz --table '0 3905536 dm_ephemeral /dev/loop4'}
##
##==============================================================================

.PHONY: fill

TARGET = ephemeralsetup
LDFLAGS = -ldevmapper
SOURCES = main.c dmsetup.c eraise.c

all:
	gcc -Wall -o $(TARGET) $(SOURCES) $(LDFLAGS)
	gcc -Wall -o fill fill.c

clean:
	rm $(TARGET)

install:
	sudo cp $(TARGET) /usr/local/bin

uninstall:
	sudo rm -f /usr/local/bin/$(TARGET)

##==============================================================================
##
## disk:
##
##==============================================================================

# create a sparse disk file
disk:
	dd if=/dev/zero of=disk bs=1 count=1 seek=16G status=none
	truncate disk --size=4G

##==============================================================================
##
## ciphers:
##
##==============================================================================

ciphers:
	cryptsetup benchmark

##==============================================================================
##
## tests:
##
##==============================================================================

DEVICE = /dev/sdb2
NAME=/dev/mapper/ephem

ifndef NOCRYPT
OPTIONS += --crypt
endif
#OPTIONS += --cipher=aes-xts-plain64 --key-size=512
#OPTIONS += --block-size=4096
#OPTIONS += --cipher=aes-cbc-plain64 --key-size=256

create:
	sudo ./$(TARGET) create $(OPTIONS) $(DEVICE) ephem
	@ sudo ./$(TARGET) status ephem

remove:
	sudo ./$(TARGET) remove ephem

status:
	sudo ./$(TARGET) status ephem

tests:
	sudo dmesg -c
	$(MAKE) create
	sudo mke2fs -q -F $(NAME)
	sudo mount $(NAME) /mnt
	sudo umount /mnt
	$(MAKE) remove

format:
	time -p sudo mkfs.ext4 -q -F $(FORMAT_OPTIONS) $(NAME)

mount:
	sudo mkfs.ext4 -q -F $(NAME)
	sudo mount $(NAME) /mnt

umount:
	sudo umount /mnt

blkid:
	sudo blkid -i /dev/mapper/ephem

mount-device:
	sudo mke2fs -q -F $(DEVICE)
	sudo mount $(DEVICE) /mnt

SIZE=$(shell sudo blockdev --getsize64 $(NAME))
BS=4096
__COUNT=$$(($(SIZE) / $(BS)))
COUNT=$(shell echo $(__COUNT))

zeros:
	time -p sudo dd if=/dev/zero of=$(NAME) bs=4096 count=$(COUNT) status=progress

rand:
	time -p sudo dd if=/dev/urandom of=$(NAME) bs=4096 count=$(COUNT) status=progress

fill1:
	time -p sudo ./fill $(NAME) 1

fill0:
	time -p sudo ./fill $(NAME) 0


count:
	echo $(COUNT)

fio:
	time -p sudo fio --name=/mnt --filename=testfile --ioengine=libaio --readwrite=randrw --size 1G --direct=1 --numjobs=4 --iodepth=16 --exitall_on_error

BENCH_RULE=fill1

bench:
	$(MAKE) -s __bench

__bench:
	@ -$(MAKE) -s remove 2> /dev/null
	@ $(MAKE) -s create NOCRYPT=1 > /dev/null
	@ clear
	@ echo ">>>>>>>> dm-emphemeral"
	@ $(MAKE) -s $(BENCH_RULE)
	@ -$(MAKE) -s remove 2> /dev/null > /dev/null
	@ $(MAKE) -s create > /dev/null
	@ echo ">>>>>>>> dm-emphemeral+dm-crypt"
	@ $(MAKE) -s $(BENCH_RULE)
	@ sudo dmsetup remove ephem 2> /dev/null > /dev/null
	@ echo ">>>>>>>> dm-crypt"
	@ $(MAKE) -s $(BENCH_RULE) NAME=/dev/mapper/ephem.dm-crypt-9cae35b4b3d7c2db
	@ sudo dmsetup remove ephem.dm-crypt-9cae35b4b3d7c2db
	@ echo ">>>>>>>> raw"
	@ $(MAKE) -s $(BENCH_RULE) NAME=$(DEVICE)

##==============================================================================
##
## sha256 module:
##
##==============================================================================

insmod:
	@ sudo insmod /usr/lib/modules/5.15.0-47-generic/kernel/arch/x86/crypto/sha256-ssse3.ko

rmmod:
	@ sudo rmmod /usr/lib/modules/5.15.0-47-generic/kernel/arch/x86/crypto/sha256-ssse3.ko

lsmod:
	@ $(MAKE) -s __lsmod

__lsmod:
	-@ sudo lsmod | grep sha256
