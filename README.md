# dm-ephemeral

The **dm-ephemeral** device-mapper target provides an ephemeral block-device
with a tamper-proof backing store, which may be optionally encrypted. An
**ephemeral device** is a non-persistent device that has no content before
instantiation and no content after termination. All content is produced and
consumed during the lifetime of the dm-ephemeral target and discarded during
termination. One example of an ephemeral device is the Linux **ramfs** file
system. The dm-ephemeral target by comparison uses substantially less memory
due to its backing store.

The dm-ephemeral target calculates and caches a cryptographic hash whenever
a block is written to the backing store. When a block is read from the backing
store, it is rehashed and the hash is compared with its cached counterpart. If
the hashes do not match, the read request fails and an **ephemeral corruption**
error is written to the system log.

The underlying device (the backing store) may be a disk partition or flat
file. This device is uninitialized when the dm-ephemeral target is first
instantiated. It might then be initialized as a file system (e.g., ``mke2fs``),
a database, or other block-oriented format.

The ``ephemeralsetup`` tool is used to instantiate (create) and terminate
(remove) dm-ephemeral targets. The following example instantiates a
dm-ephemeral target (and an associated dm-crypt target), formats the new
device as an ext4 filesystem, and mounts the file system.

```console
$ sudo ephemeralsetup create --crypt /dev/sdb4 ephem
created /dev/mapper/ephem.dm-crypt-9cae35b4b3d7c2db
created /dev/mapper/ephem
$ sudo mke2fs -q -F /dev/mapper/ephem
$ sudo mkdir -p /mnt/ephem
$ sudo mount /dev/mapper/ephem /mnt/ephem
```

The ``--crypt`` option injects a **dm-crypt** target between the underlying
device and the dm-ephemeral target. This dm-crypt target is instantiated with
an ephemeral key, which is used to encrypt blocks that are written to the
backing store.

The hierarchy of created devices may be listed using the ``lsblk`` tool.

```console
$ lsblk /dev/sdb4
NAME                              MAJ:MIN RM SIZE RO TYPE MOUNTPOINTS
sdb4                                8:20   0   4G  0 part
└─ephem.dm-crypt-9cae35b4b3d7c2db 253:0    0   4G  0 dm
  └─ephem                         253:1    0   4G  0 dm
```

## Theory of operation

The **dm-ephemeral** target supports reading and writing blocks to and from an
underlying block device called a **backing store**. The backing store is
initialized when the dm-ephemeral device is created. The implementation
maintains a hash of every block that it writes, called a **write-hash**.
When a block is read, a **read-hash** is computed. If the
read-hash and the write-hash do not match, then the read request fails and the
implementation logs an **ephemeral corruption error** to the system log.

The dm-ephemeral implementation employs a **write-before-read policy**, whereby
it only reads blocks that it has previously written. If an attempt is made to
read a block before it has been written, the implementation returns a
zero-filled block and the request succeeds. This behavior makes the underlying
device appear to have been zero initialized, which eliminates any need to
preinitialize the backing store. Therefore, the original contents of the
backing store are ignored and will appear to be zero from the perspective of
the dm-ephemeral target consumer. All this enforces a **trusted origination**
policy, whereby all block content originates from the consumer, with the
exception of zero-blocks, which are discussed below.

The handling of zero-blocks is a special case. As mentioned above, an attempt
to read a block that has never been written produces a zero-filled block. An
attempt to write a zero-block updates the corresponding write-hash with the
zero-block-hash value (without writing through to the backing store). An
attempt to read a block whose write-hash is zero, produces a zero-filled block
(without reading from the backing store). The handling of zero-blocks present
the underlying device as having been zero-initialized. Further, reading and
writing of zero-blocks only updates internal data structures and never incurs
disk activity.

## Implementation

The dm-ephemeral target employs a sparse three-level tree whose bottom layer
contains hash blocks.

```console
                                 +----------------------+
 ROOT                            |                      |
                                 +----------------------+
                                 /                      \
                      +----------+                      +----------+
 NODES                |    0     |          ...         |   65535  |
                      +----------+                      +----------+
                      /          \                      /          \
              +----------+     +----------+     +----------+     +----------+
 HASH BLOCKS  |    0     | ... |   512    | ... |  65408   | ... | 33554431 |
              +----------+     +----------+     +----------+     +----------+
```

In the current implementation,

- the **root** contains R pointers (where **R** = 65,536)
- each **node** contains N pointers (where **N** = 512)
- each **hash block** contains H hashes (where **H** = 128)

So the maximum number of hashes in the tree is given below.

```
    total-hashes = R * N * H
    total-hashes = 4,294,967,296
```

The data block size can be configured as 512, 1024, 2048, or 4096. For a block
size of 4096, the tree can accommodate 16 terabytes of data as shown below.

```
   total-bytes = R * N * H * 4096
   total-bytes = 17,592,186,044,416 (16TB)
```

The implementation could be modified to dynamically adjust the root size to
accommodate larger backing stores, but 16 terabytes seems adequate for known
applications.

The tree is sparse and initially empty with a single root node. Nodes and hash
blocks are added on demand as blocks are written. Reads do not modify the
the tree. A null pointer at any level indicates that the block is zero-valued.
The tree supports **PUT** and **GET** operations as shown below.

```
    PUT(BLKNO, HASH)
    HASH = GET(BLKNO)
```

During either operation, the block number is converted into indices for each
of the three levels in the tree as shown below.

```
    I = BLKNO / (N * H);
    J = (BLKNO / H) % N;
    K = BLKNO % H;
```

The **GET** operation is defined as follows (where if any pointer along the
path is null, the hash of the zero-block is returned).

```
    HASH = TREE[I][J][K]
```

The **PUT** operation is defined as follows (where if any pointer along the
path is null, the corresponding node or hash block is allocated and
initialized).

```
    TREE[I][J][K] = HASH
```

When allocated, nodes are are zero-initialized whereas hash blocks are filled
with the hash of the zero-block.

## Cryptographic operations

The dm-ephemeral implementation computes hash blocks as shown below.

```
    HASH = SHA-256(SALT + BLOCK)
```

Where:
- **SALT** is a randomly-generated 32-byte array
- **BLOCK** is the data content of a block of size 512, 1024, 2048, or 4096

The implementation employs the following Linux kernel cryptographic functions.
- ``get_random_bytes()``
- ``crypto_alloc_shash()``
- ``crypto_free_shash()``
- ``crypto_shash_init()``
- ``crypto_shash_update()``
- ``crypto_shash_final()``

Also, the dm-ephemeral target may be optionally stacked over a dm-crypt target
to provide privacy for the backing store.

The ``ephemeralsetup`` tool supports the following cipher specifications and
key sizes. The default is ``aes-xts-plain64`` with a key size of ``512``.

| cipher specification  | key sizes |
| --------------------- | --------- |
| aes-xts-benbi         | 256/512   |
| aes-xts-null          | 256/512   |
| aes-xts-plain         | 256/512   |
| aes-xts-plain64       | 256/512   |
| aes-cbc-benbi         | 128/256   |
| aes-cbc-null          | 128/256   |
| aes-cbc-plain         | 128/256   |
| aes-cbc-plain64       | 128/256   |
| aes-cbc-essiv:sha256  | 128/256   |
| aes-ecb-benbi         | 128/256   |
| aes-ecb-null          | 128/256   |
| aes-ecb-plain         | 128/256   |
| aes-ecb-plain64       | 128/256   |

## Memory utilization

The memory utilization is a function of the block size and the utilization of
the backing store. The memory utilization will be low initially (since the tree
is sparse) and will grow with the number of non-zero written blocks. With a
block size of 4096 the ratio of the data size to hash size will be roughly 128
to 1. For example, the worst case for a completely full 16 gigabyte backing
store is approximately 128 megabytes as shown below.


```
    backing-store-size = 16GB
    memory-utilization = (backing-store-size / 128) = 128MB
```

But recall that if the backing store utilization is only 10%, then the memory
utilization will be ten times less.

The above estimate ignores the middle nodes in the tree, which add less than a
percent to this figure. It also ignores the fact that although the tree is
sparse, some hash blocks may not be fully utilized yet still occupy memory.
The worst case could be attained by writing every 128th block which would fully
populate the tree. This case is unlikely but is noted to emphasize that the
above calculations are a rough estimate.

Compared with using **ramfs** as an ephemeral device, you can expect the
**dm-ephemeral** target to use roughly 128 times less memory.

## dmsetup parameters

One may use ``dmsetup`` directly rather than ``ephemeralsetup``. The following
commands are equivalent.

```console
$ sudo ephemeralsetup /dev/sdb4 ephem
$ sudo dmsetup create ephem --table "0 8388608 dm_ephemeral /dev/sdb4 4096"
```

The format of the table string is given below.

```console
<start-sector> <number-sectors> dm_ephemeral <device-path> <block-size>
```

Where:
- ``<start-sector>`` is zero
- ``<number-sectors>`` is expressed in 512-byte sectors
- ``<device-path>`` is the path of a disk partition or a flat file
- ``<block-size>`` must be 512, 1024, 2048, or 4096

## Examples

Creating a non-encrypted dm-ephemeral target.

```console
$ sudo ephemeralsetup /dev/sdb4 ephem
created /dev/mapper/ephem
```

Creating a dm-ephemeral target over a dm-crypt target.

```console
$ sudo ephemeralsetup --crypt /dev/sdb4 ephem
created /dev/mapper/ephem.dm-crypt-9cae35b4b3d7c2db
created /dev/mapper/ephem
```

Removing a dm-ephemeral target.

```console
$ sudo ephemeralsetup remove ephem
removed /dev/mapper/ephem
removed /dev/mapper/ephem.dm-crypt-9cae35b4b3d7c2db
```

Getting status from an ephemeral target.

```console
$ sudo ./ephemeralsetup status /dev/mapper/ephem
0 8388608 dm_ephemeral block_size=4096 pages=24 bytes=98304
```

Creating a dm-ephem target over a sparse flat file.

```console
$ dd if=/dev/zero of=disk bs=1 count=1 seek=4G status=none
$ truncate disk --size=4G
$ sudo ephemeralsetup create --crypt disk ephem
created /dev/mapper/ephem.dm-crypt-9cae35b4b3d7c2db
created /dev/mapper/ephem
```

The following example uses an overlay file system to add an ephemeral-writable
layer over a read-only file system (``/dev/sdb2``).

```console
# setup the lower directory
$ sudo mkdir -p /mnt/lower
$ sudo mount /dev/sdb2 /mnt/lower

# setup the upper/work directories
$ sudo ephemeralsetup create --crypt /dev/sdb4 ephem
created /dev/mapper/ephem.dm-crypt-9cae35b4b3d7c2db
created /dev/mapper/ephem
$ sudo mke2fs -q -F /dev/mapper/ephem
$ sudo mkdir -p /mnt/ephem
$ sudo mount /dev/mapper/ephem /mnt/ephem
$ sudo mkdir /mnt/ephem/upper /mnt/ephem/work

# perform the overlay mount
$ sudo mkdir -p /mnt/root
$ sudo mount -t overlay overlay -o rw -o lowerdir=/mnt/lower -o upperdir=/mnt/ephem/upper -o workdir=/mnt/ephem/work  /mnt/root
```

The next example builds on the previous by adding verity protection to the lower
layer.

```console
# create lower-layer hash-device
$ sudo veritysetup format /dev/sdb2 hashdev --root-hash-file=roothash
VERITY header information for hashdev
UUID:                   06199e22-5df8-4f6d-8aed-7f6833bcc451
Hash type:              1
Data blocks:            524288
Data block size:        4096
Hash block size:        4096
Hash algorithm:         sha256
Salt:                   18fb807a759864d3e6af22f8c513b8b8dee74edd088c9dcc2b8820959105d3e5
Root hash:              117a1197cbab83e246a07a262ba902663fb6697882a1da91efde0b05e1a7fb57

# setup the lower directory
$ sudo veritysetup open /dev/sdb2 verity hashdev --root-hash-file=roothash
$ sudo mkdir -p /mnt/lower
$ sudo mount /dev/mapper/verity /mnt/lower

# setup the upper/work directories
$ sudo ephemeralsetup create --crypt /dev/sdb4 ephem
created /dev/mapper/ephem.dm-crypt-9cae35b4b3d7c2db
created /dev/mapper/ephem
$ sudo mke2fs -q -F /dev/mapper/ephem
$ sudo mkdir -p /mnt/ephem
$ sudo mount /dev/mapper/ephem /mnt/ephem
$ sudo mkdir /mnt/ephem/upper /mnt/ephem/work

# perform the overlay mount
$ sudo mkdir -p /mnt/root
$ sudo mount -t overlay overlay -o rw -o lowerdir=/mnt/lower -o upperdir=/mnt/ephem/upper -o workdir=/mnt/ephem/work  /mnt/root
```

## Questions

- **Why not just use dm-crypt?** When dm-crypt is used as an ephemeral backing
  store, it is vulnerable to block-level replay attacks. Whereas dm-ephemeral
  detects replay attacks. The best solution is to use dm-crypt and dm-ephemeral
  in conjunction, where dm-crypt provides privacy and dm-ephemeral supports
  full-device integrity against replay attacks.

- **Why not use dm-integrity?** Like the dm-crypt target, the dm-integrity
  target is also vulnerable to block-level replay attacks.

- **Why was dm-ephemeral created?** The dm-ephemeral target was created to
  support ephemeral devices in **confidential computing** environments. The
  dm-ephemeral target is intended to run in a **trusted execution environment**
  while the backing store may reside on the disk of an **untrusted execution
  environment**. The main purpose is to provide immunity from untrusted replay
  attacks.

- **Are there any suggested use cases?** We intend to use dm-ephemeral to
  extend read-only integrity-protected file systems into writable ephemeral
  file systems using the overlay file system. The lower layer will be a
  dm-verity protected read-only file system and the upper layer will be
  a dm-crypt/dm-ephemeral file system.

- **Which block size should I use?** Use the biggest block size you can to
  reduce memory usage. Most file systems support 4096 blocks. By default ext4
  does, which is what we tested with.

## Future considerations

The following might be considered as future enhancements.

- Encryption might be built directly into the dm-ephemeral target rather than
  relying on the dm-crypt target. This would simplify the usage and might
  improve performance.

- The number of tree root entries might be dynamically grown to remove the
  static 16 terabyte backing store limitation.

- The tree data structure could be partially swapped out to a disk device to
  reduce memory usage even further. Probably least-recently-used hash blocks
  would be swapped out to disk. This would require adding a hash of the hash
  block to the parent node (so the hash block could be verified if swapped
  back in).
