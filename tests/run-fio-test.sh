#!/bin/bash
#set -x
set -e
rm -f top.img
truncate -s 4G top.img
dev=$(sudo losetup -f --show top.img)
echo "Created loop device $dev"
bsz=$(sudo blockdev --getbsz $dev)
echo "bsz "$bsz
ls /dev/mapper/
setup=$(which ephemeralsetup)
sudo "$setup" create --crypt "$dev" top-ep1
sudo mkfs.ext4 /dev/mapper/top-ep1
mkdir -p test
sudo mount /dev/mapper/top-ep1 test
cd test
sudo fio --name=test --filename=testfile --ioengine=libaio --readwrite=randrw --size 1G --direct=1 --numjobs=4 --iodepth=16 --exitall_on_error
cd ..
sudo umount test
sudo "$setup" remove top-ep1
sudo losetup -d "$dev"
