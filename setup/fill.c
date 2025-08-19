// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/fs.h>

ssize_t get_device_size(int fd)
{
    struct stat st;
    size_t size;

    if (fstat(fd, &st) != 0)
        return -errno;

    if (S_ISREG(st.st_mode))
        size = st.st_size;
    else if (ioctl(fd, BLKGETSIZE64, &size) != 0)
        return -errno;

    return size;
}

int main(int argc, const char* argv[])
{
    int fd;
    ssize_t size;
    const size_t block_size = 4096;
    unsigned char block[block_size];
    size_t num_blocks;

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <device> <fill-character>\n", argv[0]);
        exit(1);
    }

    /* open the file */
    if ((fd = open(argv[1], O_WRONLY)) < 0)
    {
        fprintf(stderr, "%s: cannot open: %s\n", argv[0], argv[1]);
        exit(1);
    }

    /* get the device size */
    if ((size = get_device_size(fd)) < 0)
    {
        fprintf(stderr, "%s: cannot get size: %s\n", argv[0], argv[1]);
        exit(1);
    }

    /* calculate the number of blocks */
    num_blocks = size / block_size;

#if 1
    num_blocks /= 64;
#endif

    /* initialize the block */
    memset(block, atoi(argv[2]), sizeof(block));

    /* write all the blocks */
    for (size_t i = 0; i < num_blocks; i++)
    {
        if (write(fd, block, sizeof(block)) != sizeof(block))
        {
            fprintf(stderr, "%s: cannot write block: %s\n", argv[0], argv[1]);
            exit(1);
        }
    }

    return 0;
}
