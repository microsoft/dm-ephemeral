// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _DMSETUP_H
#define _DMSETUP_H

#include <stdint.h>
#include <stdbool.h>

/* activate dm_ephemeral target over the given file or device */
int dmsetup_create_emphemeral(
    const char* name,           /* /dev/mapper/<name> */
    const char* pathname,       /* pathname of underlying file or device */
    uint64_t num_sectors,       /* number of sectors of pathname */
    uint64_t block_size);       /* the block size for underlying device */

/* create crypt target over the given file or device */
int dmsetup_create_crypt(
    const char* name,
    const char* pathname,
    uint64_t num_sectors,
    const char* cipher,
    size_t key_size); /* key size in bits */

/* deactivate the given dev-mapper name */
int dmsetup_remove(
    const char* name); /* /dev/mapper/<name> */

/* invoke status function of dev-mapper device */
int dmsetup_status(const char* name, char* buf, size_t bufsize);

static inline bool dmsetup_valid_block_size(uint64_t block_size)
{
    const uint64_t n = block_size;
    return (n == 512 || n == 1024 || n == 2048 || n == 4096);
}

#endif /* _DMSETUP_H */
