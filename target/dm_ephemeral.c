// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <linux/module.h>
#include <linux/device-mapper.h>
#include <linux/random.h>
#include <linux/spinlock.h>
#include <linux/rwsem.h>
#include <linux/wait.h>
#include <crypto/internal/hash.h>

_Static_assert(SECTOR_SIZE == 512);
_Static_assert(PAGE_SIZE == 4096);

/* the name of this target */
#define TARGET_NAME "dm_ephemeral"

#define USE_SALT

#define USE_ZERO_HASH_OPTIMIZATION

#define ENABLE_LEAK_DETECTOR

// #define TRACE_RETRIES

#define SYNCHRONIZE_OVERLAPPED_REQUESTS

// #define DISABLE_HASH_OVERHEAD

/*
**==============================================================================
**
** TRACE/DEBUG macros
**
**==============================================================================
*/

#ifdef TRACE
#error "unexpected definition of TRACE"
#endif

#ifdef TRACE
# define T(EXPR) EXPR
#else
# define T(EXPR) /* empty */
#endif

/*
**==============================================================================
**
** debug allocator functions
**
**==============================================================================
*/

#ifdef ENABLE_LEAK_DETECTOR

static atomic_t _num_allocations;

static void* _debug_kzalloc(size_t size, gfp_t flags)
{
    void* ptr = kzalloc(size, flags);

    if (ptr)
        atomic_inc(&_num_allocations);

    return ptr;
}

static void* _debug_kmalloc(size_t size, gfp_t flags)
{
    void* ptr = kmalloc(size, flags);

    if (ptr)
        atomic_inc(&_num_allocations);

    return ptr;
}

static void _debug_kfree(void* ptr)
{
    if (ptr)
    {
        atomic_dec(&_num_allocations);
        kfree(ptr);
    }
}

# define kmalloc _debug_kmalloc
# define kzalloc _debug_kzalloc
# define kfree _debug_kfree

#endif /* ENABLE_LEAK_DETECTOR */

/*
**==============================================================================
**
** block_t
**
**==============================================================================
*/

typedef struct
{
    /* maximum block size is 4096 bytes */
    u8 buf[PAGE_SIZE];
}
block_t;

static inline bool _valid_block_size(u64 size)
{
    return (size == 512 || size == 1024 || size == 2048 || size == 4096);
}

/*
**==============================================================================
**
** sha256_t -- hash definition and associated functions
**
**==============================================================================
*/

#define SHA256_SIZE 32

typedef struct
{
    char buf[SHA256_SIZE];
}
sha256_t;

typedef struct
{
    char buf[SHA256_SIZE];
}
salt_t;

static int _hash_create_desc(struct shash_desc** desc_out)
{
    int ret = 0;
    struct crypto_shash* shash = NULL;
    struct shash_desc* desc = NULL;
    u64 descsize;

    BUG_ON(!desc_out);

    shash = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(shash))
    {
        ret = -ENOMEM;
        goto done;
    }

    descsize = crypto_shash_descsize(shash);

    if (!(desc = kzalloc(sizeof(struct shash_desc) + descsize, GFP_KERNEL)))
    {
        ret = -ENOMEM;
        goto done;
    }

    desc->tfm = shash;
    *desc_out = desc;
    desc = NULL;
    shash = NULL;

done:

    if (shash)
        crypto_free_shash(shash);

    if (desc)
        kfree(desc);

    return ret;
}

static void _hash_release_desc(struct shash_desc* desc)
{
    if (desc)
    {
        if (desc->tfm)
            crypto_free_shash(desc->tfm);

        kfree(desc);
    }
}

static int _hash_compute(
    sha256_t* hash,
    const sha256_t* zero_hash,
    bool* is_zero_hash,
    struct shash_desc* desc,
    const salt_t* salt,
    const void* s,
    u64 n)
{
    int ret = 0;

#ifdef DISABLE_HASH_OVERHEAD
    /* disable hashing for comparative performance purposes */
    {
        if (is_zero_hash)
            *is_zero_hash = false;

        memset(hash, 0, sizeof(sha256_t));
        goto done;
    }
#endif

#ifdef USE_ZERO_HASH_OPTIMIZATION
    /* optimize the zero-hash case */
    if (zero_hash)
    {
        typedef __uint128_t u128;
        const u128* p = s;
        const u128* end = (const u128*)((const u8*)s + n);

        /* fail if pointer not 16-byte alignement */
        if (((u64)s % sizeof(u128)))
        {
            ret = -EINVAL;
            goto done;
        }

        /* skip over zero words */
        while(p != end && *p == 0)
            p++;

        /* if no non-zero words found */
        if (p == end)
        {
            *hash = *zero_hash;

            if (is_zero_hash)
                *is_zero_hash = true;

            goto done;
        }
    }
#endif

    if (is_zero_hash)
        *is_zero_hash = false;

    if (crypto_shash_init(desc) != 0)
    {
        ret = -EINVAL;
        goto done;
    }

#ifdef USE_SALT
    if (crypto_shash_update(desc, salt->buf, sizeof(salt_t)) != 0)
    {
        ret = -EINVAL;
        goto done;
    }
#endif

    if (crypto_shash_update(desc, s, n) != 0)
    {
        ret = -EINVAL;
        goto done;
    }

    if (crypto_shash_final(desc, hash->buf) != 0)
    {
        ret = -EINVAL;
        goto done;
    }

done:
    return ret;
}

/*
**==============================================================================
**
** _hexdump()
**
**==============================================================================
*/

#ifdef NEED_HEXDUMP

static void _format_hex_byte(char buf[3], unsigned char byte)
{
    unsigned char hi = ((byte >> 4) & 0x0f);
    unsigned char lo = (byte & 0x0f);

    if (hi >= 0 && hi <= 9)
        buf[0] = '0' + hi;
    else if (hi >= 10 && hi <= 15)
        buf[0] = 'a' + (hi - 10);

    if (lo >= 0 && lo <= 9)
        buf[1] = '0' + lo;
    else if (lo >= 10 && lo <= 15)
        buf[1] = 'a' + (lo - 10);

    buf[2] = '\0';
}

static void _hexdump(const char* label, const void* s, u64 n)
{
    u64 i;
    char* buf;
    const size_t buf_size = (2 * n) + 1;
    const u8* p = s;

    if (!label)
        label = "_hexdump()";

    if (!(buf = kmalloc(buf_size, GFP_KERNEL)))
        return;

    for (i = 0; i < n; i++)
        _format_hex_byte(&buf[i * 2], p[i]);

    printk(KERN_CRIT "%s: %s\n", label, buf);

    kfree(buf);
}

#endif /* NEED_HEXDUMP */

/*
**==============================================================================
**
** hashtree_t -- three-level hash tree
**
**                                 +----------------------+
** ROOT                            |                      |
**                                 +----------------------+
**                                 /                      \
**                      +----------+                      +----------+
** NODES                |    0     |          ...         |   65535  |
**                      +----------+                      +----------+
**                      /          \                      /          \
**              +----------+     +----------+     +----------+     +----------+
** HASH BLOCKS  |    0     | ... |   512    | ... |  65408   | ... | 33554431 |
**              +----------+     +----------+     +----------+     +----------+
**
**
** The ROOT contains 65536 pointers to NODES
** Each NODE contains 512 pointers to HASH BLOCKS
** Each HASH BLOCK contains 128 hashes
**
** The maximum device size that can be represented by this tree is 16TB with
** a block size of 4096.
**
**     65536 * 512 * 128 * 4096 = 17,592,186,044,416
**
**==============================================================================
*/

#define NUM_NODES 65536UL
#define NUM_HASH_BLOCKS 512UL
#define NUM_HASHES 128UL
#define MAX_BLOCKS (NUM_NODES * NUM_HASH_BLOCKS * NUM_HASHES)

typedef struct hash_block hash_block_t;
typedef struct node node_t;
typedef struct root root_t;

typedef struct
{
    root_t* root; /* the root node */
    struct spinlock lock; /* for locking the hash tree */
    u64 num_pages_allocated; /* the number of pages allocated by hashtree_t */
    sha256_t zero_hash; /* precalculated hash of zero block */
}
hashtree_t;

struct root
{
    node_t* nodes[NUM_NODES];
};

struct node
{
    hash_block_t* hash_blocks[NUM_HASH_BLOCKS];
};

struct hash_block
{
    sha256_t hashes[NUM_HASHES];
};

_Static_assert(sizeof(root_t) == NUM_NODES * sizeof(node_t*));
_Static_assert((sizeof(root_t) % PAGE_SIZE) == 0);
_Static_assert(sizeof(node_t) == PAGE_SIZE);
_Static_assert(sizeof(hash_block_t) == PAGE_SIZE);

/* get i: the index of the node for blkno */
static inline u64 _hashtree_get_i(u64 blkno)
{
    return blkno / (NUM_HASH_BLOCKS * NUM_HASHES);
}

/* get j: the index of the hash_block for blkno */
static inline u64 _hashtree_get_j(u64 blkno)
{
    return (blkno / NUM_HASHES) % NUM_HASH_BLOCKS;
}

/* get k: the index of the hash for blkno */
static inline u64 _hashtree_get_k(u64 blkno)
{
    return blkno % NUM_HASHES;
}

static int _hashtree_get(
    hashtree_t* self,
    u64 blkno,
    sha256_t* hash)
{
    int ret = 0;
    const u64 i = _hashtree_get_i(blkno);
    const u64 j = _hashtree_get_j(blkno);
    const u64 k = _hashtree_get_k(blkno);
    unsigned long flags = 0;

    if (i >= NUM_NODES)
    {
        printk(KERN_CRIT "%s(): block number too large: %llu\n",
            __FUNCTION__, blkno);
        ret = -EINVAL;
        goto done;
    }

    spin_lock_irqsave(&self->lock, flags);

    if (!self->root->nodes[i] || !self->root->nodes[i]->hash_blocks[j])
        *hash = self->zero_hash;
    else
        *hash = self->root->nodes[i]->hash_blocks[j]->hashes[k];

    spin_unlock_irqrestore(&self->lock, flags);

done:

    return ret;
}

static int _hashtree_put(
    hashtree_t* self,
    u64 blkno,
    const sha256_t* hash,
    bool is_zero_hash,
    bool* modified)
{
    int ret = 0;
    const u64 i = _hashtree_get_i(blkno);
    const u64 j = _hashtree_get_j(blkno);
    const u64 k = _hashtree_get_k(blkno);
    unsigned long flags = 0;
    bool need_node = false;
    bool need_hash_block = false;
    node_t* node = NULL;
    hash_block_t* hash_block = NULL;

    if (modified)
        *modified = false;

    /* if block number is beyond the end of the device */
    if (i >= NUM_NODES)
    {
        printk(KERN_CRIT "%s(): block number too large: %llu\n",
            __FUNCTION__, blkno);
        ret = -EINVAL;
        goto done;
    }

    // Lock the hash tree and then determine which nodes must be allocated.
    // Set need_node and need_hash_block as needed. Finally, release
    // the lock. These nodes are allocated up front to avoid having to call
    // kmalloc() while holding the lock below (note that kmalloc() can sleep
    // unless using GFP_ATOMIC, which is undesireable).
    spin_lock_irqsave(&self->lock, flags);
    {
        if (!self->root->nodes[i])
        {
            need_node = true;
            need_hash_block = true;
        }
        else if (!self->root->nodes[i]->hash_blocks[j])
        {
            need_hash_block = true;
        }
    }
    spin_unlock_irqrestore(&self->lock, flags);

    /* avoid unecessary hash node allocation for zero-block case */
    if (need_hash_block && is_zero_hash)
    {
        ret = 0;
        goto done;
    }

    // Allocate nodes that were determined to be null above. Since the lock
    // has been released, another thread might also be creating node(s) for
    // these same indices. If so, then whichever thread is the last to
    // obtain the lock below will free its node(s), whithout adding them to
    // the hash tree. In practice, this condition is very rare.
    {
        if (need_node)
        {
            if (!(node = kzalloc(sizeof(node_t), GFP_KERNEL)))
            {
                ret = -ENOMEM;
                goto done;
            }
        }

        if (need_hash_block)
        {
            u64 i;

            if (!(hash_block = kmalloc(sizeof(hash_block_t), GFP_KERNEL)))
            {
                ret = -ENOMEM;
                goto done;
            }

            /* fill the hash block with zero hashes */
            for (i = 0; i < NUM_HASHES; i++)
                hash_block->hashes[i] = self->zero_hash;
        }
    }

    /* handle insertion of hash and possibly one or two nodes */
    spin_lock_irqsave(&self->lock, flags);
    {
        /* if still null, assign the preallocated node */
        if (self->root->nodes[i] == NULL)
        {
            self->num_pages_allocated++;
            self->root->nodes[i] = node;
            node = NULL;
        }

        /* if still null, assign the preallocated hash block */
        if (self->root->nodes[i]->hash_blocks[j] == NULL)
        {
            self->num_pages_allocated++;
            self->root->nodes[i]->hash_blocks[j] = hash_block;
            hash_block = NULL;
        }

        /* set the hash for this block */
        self->root->nodes[i]->hash_blocks[j]->hashes[k] = *hash;
        *modified = true;
    }
    spin_unlock_irqrestore(&self->lock, flags);

done:

    if (node)
        kfree(node);

    if (hash_block)
        kfree(hash_block);

    return ret;
}

static int _hashtree_init(hashtree_t* self, const sha256_t* zero_hash)
{
    int ret = 0;

    if (!self || !zero_hash)
    {
        ret = -EINVAL;
        goto done;
    }

    memset(self, 0, sizeof(hashtree_t));

    if (!(self->root = kzalloc(sizeof(root_t), GFP_KERNEL)))
    {
        ret = -ENOMEM;
        goto done;
    }

    spin_lock_init(&self->lock);
    self->zero_hash = *zero_hash;
    self->num_pages_allocated += sizeof(root_t) / PAGE_SIZE;

done:
    return ret;
}

static void _hashtree_release(hashtree_t* self)
{
    u64 i;
    u64 num_pages_freed = 0;

    if (self && self->root)
    {
        for (i = 0; i < NUM_NODES; i++)
        {
            node_t* node = self->root->nodes[i];

            if (node)
            {
                u64 j;

                for (j = 0; j < NUM_HASH_BLOCKS; j++)
                {
                    if (node->hash_blocks[j])
                    {
                        num_pages_freed++;
                        kfree(node->hash_blocks[j]);
                    }
                }

                num_pages_freed++;
                kfree(node);
            }
        }

        kfree(self->root);
        num_pages_freed += sizeof(root_t) / PAGE_SIZE;

        if (self->num_pages_allocated != num_pages_freed)
        {
            printk(KERN_CRIT "%s: leaked hash tree pages: %llu\n",
                TARGET_NAME, self->num_pages_allocated);
        }

        memset(self, 0, sizeof(hashtree_t));
    }
}

/*
**==============================================================================
**
** ephemeral_t -- the "ephemeral" target and associated functions
**
**==============================================================================
*/

typedef struct _ephemeral ephemeral_t;

typedef struct _request request_t;

#define EXTENT_INITIALIZER { U64_MAX, 0 }

typedef struct extent
{
    u64 first_blkno;
    u64 last_blkno;
}
extent_t;

struct _request
{
    struct list_head base;
    ephemeral_t* e;
    struct bio* bio;
    bio_end_io_t* end_io;
    extent_t extent;

    void* bi_private; /* original bio->bi_private field */
    bio_end_io_t* bi_end_io; /* original bio->bi_end_io field */
    struct bvec_iter bi_iter;
};

struct _ephemeral
{
    struct dm_dev* dev;

    /* randomly generated salt, which is included in computed hashes */
    salt_t salt;

    /* the hash of a zero-filled block */
    sha256_t zero_hash;

    /* the block size passed to ctr function */
    u64 block_size;

    /* three-level tree leading to block hashes */
    hashtree_t hashtree;

    /* list of outstanding requests */
    struct list_head requests;
    extent_t global_extent;
    bool global_extent_dirty;

    /* queue where overlapped requests wait */
    wait_queue_head_t wait_queue;

    /* work delayed by _write_endio() */
    struct delayed_work delayed_work;

    /* work queue for delayed work */
    struct workqueue_struct* workqueue;

    /* list of bios to be processed by the delayed work queue */
    struct bio_list bios;
};

static inline u64 _ephemeral_blocking_factor(ephemeral_t* e)
{
    return e ? (e->block_size / SECTOR_SIZE) : 0;
}

static inline bool _extent_contains(const extent_t* extent, u64 blkno)
{
    return blkno >= extent->first_blkno && blkno <= extent->last_blkno;
}

static inline bool _extent_overlap(const extent_t* x, const extent_t* y)
{
    return
        _extent_contains(x, y->first_blkno) ||
        _extent_contains(x, y->last_blkno) ||
        _extent_contains(y, x->first_blkno) ||
        _extent_contains(y, x->last_blkno);
}

static inline bool _extent_empty(const extent_t* extent)
{
    return extent->first_blkno == U64_MAX && extent->last_blkno == 0;
}

static int _extent_compute(
    ephemeral_t* e,
    struct bio* bio,
    extent_t* extent)
{
    int ret = 0;
    u64 total_blocks = 0;
    u64 first_blkno;
    u64 last_blkno;

    if (extent)
        memset(extent, 0, sizeof(extent_t));

    /* reject null parameters */
    if (!e || !bio || !extent)
    {
        ret = -EINVAL;
        goto done;
    }

    /* calculate the first block number */
    first_blkno = (bio->bi_iter.bi_sector / _ephemeral_blocking_factor(e));

    /* iterate segments to find the total number of blocks */
    {
        struct bio_vec bvec;
        struct bvec_iter iter;

        bio_for_each_segment(bvec, bio, iter)
        {
            u64 rem; /* number of remaining blocks */

            /* the offset must be a multiple of the block size */
            if (bvec.bv_offset % e->block_size)
            {
                ret = -EINVAL;
                goto done;
            }

            /* the length must be a multiple of the block size */
            if (bvec.bv_len % e->block_size)
            {
                ret = -EINVAL;
                goto done;
            }

            /* calculate the number of blocks in this page */
            rem = bvec.bv_len / e->block_size;

            /* while more blocks */
            while (rem > 0)
            {
                rem--;
                total_blocks++;
            }
        }
    }

    /* expect at least one block */
    if (total_blocks < 1)
    {
        ret = -EINVAL;
        goto done;
    }

    /* set the last block number */
    last_blkno = first_blkno + total_blocks - 1;

    /* set the output extent parameter */
    extent->first_blkno = first_blkno;
    extent->last_blkno = last_blkno;

done:
    return ret;
}

static request_t* _request_alloc(
    ephemeral_t* e,
    struct bio* bio,
    bio_end_io_t* end_io)
{
    request_t* req;
    extent_t extent;

    if (!e || !bio)
        return NULL;

    if (_extent_compute(e, bio, &extent) != 0)
        return NULL;

    if (!(req = kzalloc(sizeof(request_t), GFP_KERNEL)))
        return NULL;

    req->e = e;
    req->bio = bio;
    req->end_io = end_io;
    req->extent = extent;

    memcpy(&req->bi_iter, &bio->bi_iter, sizeof(struct bvec_iter));
    req->bi_private = bio->bi_private;
    req->bi_end_io = bio->bi_end_io;

    return req;
}

static void _request_submit(request_t* req)
{
    /* reset bi_private and bi_end_io */
    req->bio->bi_private = req;
    req->bio->bi_end_io = req->end_io;

    /* delegate the request to the underlying device */
    req->bio->bi_bdev = req->e->dev->bdev;
    submit_bio(req->bio);
}

static void _request_free(request_t* req)
{
    if (req)
        kfree(req);
}

#ifdef SYNCHRONIZE_OVERLAPPED_REQUESTS
static inline void _expand_global_extent_locked(
    extent_t* global_extent,
    const extent_t* p)
{
    global_extent->first_blkno =
        min(global_extent->first_blkno, p->first_blkno);
    global_extent->last_blkno =
        max(global_extent->last_blkno, p->last_blkno);
}
#endif

#ifdef SYNCHRONIZE_OVERLAPPED_REQUESTS
static inline void _shrink_global_extent_locked(
    extent_t* global_extent,
    bool* global_extent_dirty,
    const extent_t* p)
{
    if (global_extent->first_blkno == p->first_blkno ||
        global_extent->last_blkno == p->last_blkno)
    {
        /* shrink the global extent later on demand */
        *global_extent_dirty = true;
    }
}
#endif

#ifdef SYNCHRONIZE_OVERLAPPED_REQUESTS
static inline void _recompute_global_extent_locked(ephemeral_t* e)
{
    const request_t* p;
    struct list_head* list = &e->requests;
    extent_t* global_extent = &e->global_extent;

    if (e->global_extent_dirty)
    {
        *global_extent = (extent_t)EXTENT_INITIALIZER;

        list_for_each_entry(p, list, base)
        {
            _expand_global_extent_locked(&e->global_extent, &p->extent);
        }

        e->global_extent_dirty = false;
    }
}
#endif

#ifdef SYNCHRONIZE_OVERLAPPED_REQUESTS
static bool _is_overlapped_locked(ephemeral_t* e, request_t* req)
{
    if (list_empty(&e->requests))
        return false;

    if (e->global_extent_dirty)
        _recompute_global_extent_locked(e);

    /* if global extent overlaps, then check individual requests */
    if (_extent_overlap(&e->global_extent, &req->extent))
    {
        const request_t* p;

        list_for_each_entry(p, &e->requests, base)
        {
            if (_extent_overlap(&req->extent, &p->extent))
                return true;
        }
    }

    return false;
}
#endif

#ifdef SYNCHRONIZE_OVERLAPPED_REQUESTS
static void _sleep_on_wait_locked(ephemeral_t* e)
{
    DECLARE_WAITQUEUE(wait, current);

    /* add this thread to the wait queue */
    __add_wait_queue(&e->wait_queue, &wait);

    /* make this thread interruptible */
    __set_current_state(TASK_UNINTERRUPTIBLE);

    /* unlock, schedule, relock */
    spin_unlock_irq(&e->wait_queue.lock);
    io_schedule();
    spin_lock_irq(&e->wait_queue.lock);

    /* remove this thread to the wait queue */
    __remove_wait_queue(&e->wait_queue, &wait);
}
#endif

static void _request_start(request_t* req, u64* retries)
{
    ephemeral_t* e = req->e;
    struct list_head* list = &e->requests;

    *retries = 0;

    spin_lock_irq(&req->e->wait_queue.lock);

    for (;;)
    {
#ifdef SYNCHRONIZE_OVERLAPPED_REQUESTS
        /* check for overlap */
        if (_is_overlapped_locked(e, req))
        {
            (*retries)++;
            _sleep_on_wait_locked(req->e);
            /* still locked */
        }
        else
#endif
        {
            /* append to list of requests */
            list_add_tail(&req->base, list);
#ifdef SYNCHRONIZE_OVERLAPPED_REQUESTS
            _expand_global_extent_locked(
                &e->global_extent,
                &req->extent);
#endif
            break;
        }
    }

    spin_unlock_irq(&req->e->wait_queue.lock);

    _request_submit(req);
}

static void _request_finish(request_t* req)
{
    struct bio* bio = req->bio;
    ephemeral_t* e = req->e;

    /* remove request from list of requests and wakeup waiters */
    spin_lock_irq(&e->wait_queue.lock);
    list_del(&req->base);
#ifdef SYNCHRONIZE_OVERLAPPED_REQUESTS
    _shrink_global_extent_locked(
        &e->global_extent,
        &e->global_extent_dirty,
        &req->extent);
#endif
    wake_up_locked(&e->wait_queue);
    spin_unlock_irq(&e->wait_queue.lock);

    bio->bi_end_io = req->bi_end_io;
    bio->bi_private = req->bi_private;
    _request_free(req);

    bio_endio(bio);
}

static void _do_read_endio(struct bio* bio)
{
    const char* func = __FUNCTION__;
    request_t* req = bio->bi_private;
    struct shash_desc* desc = NULL;
    u8* local_page_ptr = NULL;

    /* if an error occurred in the underlying device */
    if (bio->bi_status != BLK_STS_OK)
    {
        printk(KERN_CRIT "%s: error from underying device", func);
        goto done;
    }

    /* allocate a hash descriptor */
    if (_hash_create_desc(&desc) < 0)
    {
        printk(KERN_CRIT "%s: _hash_create_desc() failed\n", func);
        bio->bi_status = BLK_STS_IOERR;
        goto done;
    }

    /* verify all read blocks against the hash tree */
    {
        struct bvec_iter save_bi_iter;
        struct bio_vec bvec;
        struct bvec_iter iter;
        const sector_t sector = req->bi_iter.bi_sector;
        ephemeral_t* e = req->e;
        u64 blkno = (sector / _ephemeral_blocking_factor(e));

        /* swap out the bio iterator field with the original one */
        save_bi_iter = bio->bi_iter;
        bio->bi_iter = req->bi_iter;

        /* iterate the segments of this bio vector */
        bio_for_each_segment(bvec, bio, iter)
        {
            u8* ptr; /* pointer to current block */
            u64 rem; /* number of remaining blocks */
            local_page_ptr = kmap_local_page(bvec.bv_page);

            /* the offset must be a multiple of the block size */
            if (bvec.bv_offset % e->block_size)
            {
                printk(KERN_CRIT "%s: misaligned offset: %u\n", func,
                    bvec.bv_offset);
                bio->bi_status = BLK_STS_IOERR;
                goto done;
            }

            /* the length must be a multiple of the block size */
            if (bvec.bv_len % e->block_size)
            {
                printk(KERN_CRIT "%s: misaligned length: %u\n", func,
                    bvec.bv_len);
                bio->bi_status = BLK_STS_IOERR;
                goto done;
            }

            /* assume page is not in high memory */
            ptr = (local_page_ptr + bvec.bv_offset);

            /* calculate the number of blocks in this page */
            rem = bvec.bv_len / e->block_size;

            /* while more blocks */
            while (rem > 0)
            {
                sha256_t tree_hash;

                T( printk(KERN_CRIT "%s: get hash: blkno=%llu", func, blkno); )

                if (_hashtree_get(&e->hashtree, blkno, &tree_hash) != 0)
                {
                    printk(KERN_CRIT "%s: get hash failed\n", func);
                    bio->bi_status = BLK_STS_IOERR;
                    goto done;
                }

                if (memcmp(&tree_hash, &e->zero_hash, sizeof(sha256_t)) == 0)
                {
                    /* ignore any data on disk and zero-out this block */
                    memset(ptr, 0, e->block_size);
                }
                else
                {
                    sha256_t read_hash;

                    if (_hash_compute(
                        &read_hash,
                        &e->hashtree.zero_hash,
                        (bool*)NULL,
                        desc,
                        &e->salt,
                        ptr,
                        e->block_size) != 0)
                    {
                        printk(KERN_CRIT "%s(): _hash_compute() failed\n",
                            func);
                        bio->bi_status = BLK_STS_IOERR;
                        goto done;
                    }

                    /* fail if the tree hash does not match the read hash */
                    if (memcmp(&tree_hash, &read_hash, sizeof(sha256_t)) != 0)
                    {
                        printk(KERN_CRIT
                            "%s(): emphemeral corruption: "
                            "blkno=%llu "
                            "block_size=%llu "
                            "len=%u "
                            "offset=%u\n",
                            func,
                            blkno,
                            e->block_size,
                            bvec.bv_len,
                            bvec.bv_offset);
                        bio->bi_status = BLK_STS_IOERR;
                        goto done;
                    }
                }

                blkno++;
                ptr += e->block_size;
                rem--;
            }

            kunmap_local(local_page_ptr);
            local_page_ptr = NULL;
        }

        /* restore the bio iterator field */
        bio->bi_iter = save_bi_iter;
    }

done:

    if (desc)
        _hash_release_desc(desc);

    if (local_page_ptr)
        kunmap_local(local_page_ptr);

    _request_finish(req);
}

static void _do_write_endio(struct bio* bio)
{
    const char* func = __FUNCTION__;
    request_t* req = bio->bi_private;
    ephemeral_t* e = req->e;
    struct shash_desc* desc = NULL;
    u8* local_page_ptr = NULL;

    /* if an error occurred in the underlying device */
    if (bio->bi_status != BLK_STS_OK)
    {
        printk(KERN_CRIT "%s: error from underying device", func);
        goto done;
    }

    /* allocate a hash descriptor */
    if (_hash_create_desc(&desc) < 0)
    {
        printk(KERN_CRIT "%s: _hash_create_desc() failed\n", func);
        bio->bi_status = BLK_STS_IOERR;
        goto done;
    }

    /* handle all segments in the bio structure */
    {
        struct bio_vec bvec;
        struct bvec_iter iter;
        const sector_t sector = req->bi_iter.bi_sector;
        u64 blkno = (sector / _ephemeral_blocking_factor(e));
        struct bvec_iter save_bi_iter;

        /* swap out the bio iterator field with the original one */
        save_bi_iter = bio->bi_iter;
        bio->bi_iter = req->bi_iter;

        /* iterate the segments of this bio vector */
        bio_for_each_segment(bvec, bio, iter)
        {
            u8* ptr; /* pointer to current block */
            u64 rem; /* number of remaining blocks */

            /* get a local pointer to the current page */
            local_page_ptr = kmap_local_page(bvec.bv_page);

            /* the offset must be a multiple of the block size */
            if (bvec.bv_offset % e->block_size)
            {
                printk(KERN_CRIT "%s: misaligned offset: %u\n", func,
                    bvec.bv_offset);
                bio->bi_status = BLK_STS_IOERR;
                goto done;
            }

            /* the length must be a multiple of the block size */
            if (bvec.bv_len % e->block_size)
            {
                printk(KERN_CRIT "%s: misaligned length: %u\n", func,
                    bvec.bv_len);
                bio->bi_status = BLK_STS_IOERR;
                goto done;
            }

            /* set a pointer to the offset page */
            ptr = local_page_ptr + bvec.bv_offset;

            /* calculate the number of blocks in this page */
            rem = bvec.bv_len / e->block_size;

            T( printk(KERN_CRIT "write.rem=%llu\n", rem); )

            /* while more blocks */
            while (rem > 0)
            {
                sha256_t hash;
                bool is_zero_hash;
                bool modified;

                /* calculate the hash of the current block */
                if (_hash_compute(
                    &hash,
                    &e->hashtree.zero_hash,
                    &is_zero_hash,
                    desc,
                    &e->salt,
                    ptr,
                    e->block_size) != 0)
                {
                    printk(KERN_CRIT "%s(): _hash_compute() failed\n", func);
                    bio->bi_status = BLK_STS_IOERR;
                    goto done;
                }

                T( printk(KERN_CRIT "%s: put hash: blkno=%llu", func, blkno); )

                /* cache the hash of this block */
                if (_hashtree_put(
                    &e->hashtree,
                    blkno,
                    &hash,
                    is_zero_hash,
                    &modified) != 0)
                {
                    printk(KERN_CRIT "%s: put hash failed\n", func);
                    bio->bi_status = BLK_STS_IOERR;
                    goto done;
                }

                blkno++;
                ptr += e->block_size;
                rem--;
            }

            kunmap_local(local_page_ptr);
            local_page_ptr = NULL;
        }

        /* restore the bio iterator field */
        bio->bi_iter = save_bi_iter;
    }

done:

    if (desc)
        _hash_release_desc(desc);

    if (local_page_ptr)
        kunmap_local(local_page_ptr);

    _request_finish(req);
}

static void _endio(struct bio* bio)
{
    request_t* req = bio->bi_private;
    ephemeral_t* e = req->e;
    unsigned long flags;

    /* queue to be handled outside atomic context */
    spin_lock_irqsave(&req->e->wait_queue.lock, flags);
    bio_list_add(&e->bios, bio);
    queue_delayed_work(e->workqueue, &e->delayed_work, 0);
    spin_unlock_irqrestore(&req->e->wait_queue.lock, flags);
}

static void _delayed_work(struct work_struct* work)
{
    const char* func = __FUNCTION__;
    ephemeral_t* e = container_of(work, ephemeral_t, delayed_work.work);
    struct bio* bio;

    spin_lock_irq(&e->wait_queue.lock);

    while ((bio = bio_list_pop(&e->bios)) != NULL)
    {
        spin_unlock_irq(&e->wait_queue.lock);

        if (bio_op(bio) == REQ_OP_WRITE)
            _do_write_endio(bio);
        else if (bio_op(bio) == REQ_OP_READ)
            _do_read_endio(bio);
        else
        {
            printk(KERN_CRIT TARGET_NAME ": %s(): unexpected\n", func);
        }

        spin_lock_irq(&e->wait_queue.lock);
    }

    spin_unlock_irq(&e->wait_queue.lock);
}

/* dm-mapper-target constructor */
static int _ephemeral_ctr(
    struct dm_target* dt,
    unsigned int argc,
    char** argv)
{
    int ret = 0;
    const char* func = __FUNCTION__;
    ephemeral_t* e = NULL;
    u8* zero_page = NULL;
    u64 block_size;
    struct shash_desc* desc = NULL;

    printk(KERN_CRIT "%s: starting (req)...\n", TARGET_NAME);

    /* check the module argument count */
    if (argc != 2)
    {
        printk(KERN_CRIT "%s(): expected 2 args: <block_size>\n", func);
        dt->error = TARGET_NAME ": bad args";
        ret = -EINVAL;
        goto done;
    }

    /* get the block size from argv[1] or use default */
    {
        if (sscanf(argv[1], "%llu", &block_size) != 1)
        {
            printk(KERN_CRIT "%s(): bad <block_size> arg: %s\n", func, argv[1]);
            dt->error = TARGET_NAME ": bad <block_size> arg";
            ret = -EINVAL;
            goto done;
        }

        if (!_valid_block_size(block_size))
        {
            printk(KERN_CRIT "%s(): invalid <block_size> arg: %s\n",
                func, argv[1]);
            dt->error = TARGET_NAME ": invalid <block_size> arg";
            ret = -EINVAL;
            goto done;
        }
    }

    /* allocate the private target context */
    if (!(e = kzalloc(sizeof(ephemeral_t), GFP_KERNEL)))
    {
        printk(KERN_CRIT "%s(%u): kmalloc() failed\n", func, __LINE__);
        dt->error = TARGET_NAME ": out of memory";
        ret = -ENOMEM;
        goto done;
    }

    /* initialize the wait queue */
    INIT_LIST_HEAD(&e->requests);
    e->global_extent_dirty = false;
    e->global_extent = (extent_t)EXTENT_INITIALIZER;
    init_waitqueue_head(&e->wait_queue);

    /* allocate a delayed work queue for _write_endio() */
    if (!(e->workqueue = alloc_workqueue(
        "dm-ephemeral-workqueue", WQ_MEM_RECLAIM, 0)))
    {
        ret = -ENOMEM;
        goto done;
    }

    /* set the block size */
    e->block_size = block_size;

    /* allocate a hash descriptor */
    if (_hash_create_desc(&desc) < 0)
    {
        printk(KERN_CRIT "%s: _hash_create_desc() failed\n", func);
        dt->error = TARGET_NAME ": _hash_create_desc() failed";
        ret = -ENOMEM;
        goto done;
    }

    /* generate a random hash */
    get_random_bytes(&e->salt, sizeof(e->salt));

    /* create a delayed work queue for thread-safe endio() handling */
    INIT_DELAYED_WORK(&e->delayed_work, _delayed_work);

    /* generate a hash of a zero-filled block for later use */
    {
        if (!(zero_page = kzalloc(e->block_size, GFP_KERNEL)))
        {
            printk(KERN_CRIT "%s(%u): kzalloc() failed\n", func, __LINE__);
            dt->error = TARGET_NAME ": out of memory";
            ret = -ENOMEM;
            goto done;
        }

        if (_hash_compute(
            &e->zero_hash,
            NULL,
            (bool*)NULL,
            desc,
            &e->salt,
            zero_page,
            e->block_size) != 0)
        {
            printk(KERN_CRIT "%s(): _hash_compute() failed\n", func);
            dt->error = TARGET_NAME ": _hash_compute() failed";
            ret = -EINVAL;
            goto done;
        }
    }

    /* initialize the hash tree */
    if (_hashtree_init(&e->hashtree, &e->zero_hash) != 0)
    {
        printk(KERN_CRIT "%s(): _hashtree_init() failed\n", func);
        dt->error = TARGET_NAME ": _hashtree_init() failed";
        ret = -EINVAL;
        goto done;
    }

    /* get the device for ephemeral.dev */
    {
        fmode_t mode = dm_table_get_mode(dt->table);

        if (dm_get_device(dt, argv[0], mode, &e->dev) < 0)
        {
            printk(KERN_CRIT "%s(): dm_get_device() failed\n", func);
            dt->error = TARGET_NAME ": dm_get_device() failed";
            ret = -EINVAL;
            goto done;
        }
    }

    /* save the private target context into the dm_target structure */
    dt->private = e;
    e = NULL;

done:

    if (e)
        kfree(e);

    if (desc)
        _hash_release_desc(desc);

    if (zero_page)
        kfree(zero_page);

    return ret;
}

/* dm-mapper-target destructor */
static void _ephemeral_dtr(struct dm_target* dt)
{
    ephemeral_t* e = (ephemeral_t*)dt->private;

    printk(KERN_CRIT TARGET_NAME ": stopping (%llu pages used)...\n",
        e->hashtree.num_pages_allocated);

    _hashtree_release(&e->hashtree);

    if (e->workqueue)
    {
        drain_workqueue(e->workqueue);
        destroy_workqueue(e->workqueue);
    }

    dm_put_device(dt, e->dev);
    kfree(e);

#ifdef ENABLE_LEAK_DETECTOR
    {
        const int n = atomic_read(&_num_allocations);

        if (n > 0)
            printk(KERN_CRIT TARGET_NAME ": warning: %d blocks leaked\n", n);
    }
#endif
}

static int _ephemeral_map_read(struct dm_target* dt, struct bio* bio)
{
    int ret = DM_MAPIO_KILL;
    const char* func = __FUNCTION__;
    ephemeral_t* e = (ephemeral_t*)dt->private;
    request_t* req = NULL;

    /* create a new request structure */
    if (!(req = _request_alloc(e, bio, _endio)))
    {
        printk(KERN_CRIT "%s: out of memory\n", func);
        dt->error = TARGET_NAME ": out of memory";
        goto done;
    }

    /* start the request (possibly waiting for overlap to resolve) */
    {
        u64 retries;
        _request_start(req, &retries);

#ifdef TRACE_RETRIES
        if (retries > 0)
            printk(KERN_CRIT TARGET_NAME ": retries=%llu\n", retries);
#endif
    }

    ret = DM_MAPIO_SUBMITTED;

done:

    return ret;
}

static int _ephemeral_map_write(struct dm_target* dt, struct bio* bio)
{
    int ret = DM_MAPIO_KILL;
    const char* func = __FUNCTION__;
    ephemeral_t* e = (ephemeral_t*)dt->private;
    request_t* req;

    /* create a new request structure */
    if (!(req = _request_alloc(e, bio, _endio)))
    {
        printk(KERN_CRIT "%s: out of memory\n", func);
        dt->error = TARGET_NAME ": out of memory";
        goto done;
    }

    /* start the request (possibly waiting for overlap to resolve) */
    {
        u64 retries;
        _request_start(req, &retries);

#ifdef TRACE_RETRIES
        if (retries > 0)
            printk(KERN_CRIT TARGET_NAME ": retries=%llu\n", retries);
#endif
    }

    ret = DM_MAPIO_SUBMITTED;

done:

    return ret;
}

/* dm-mapper-target mapper: for reading and writing */
static int _ephemeral_map(struct dm_target* dt, struct bio* bio)
{
    int ret = 0;
    const char* func = __FUNCTION__;
    const sector_t sector = bio->bi_iter.bi_sector;
    const unsigned int size = bio->bi_iter.bi_size;
    ephemeral_t* e = (ephemeral_t*)dt->private;

    T( printk(KERN_CRIT "%s(): enter\n", func); )

    /* the sector number should be multiple of the blocking factor */
    if (sector % _ephemeral_blocking_factor(e))
    {
        printk(KERN_CRIT
            "%s: unaligned sector: %llu:%u\n", func, sector, size);
        dt->error = TARGET_NAME ": unaligned sector number";
        ret = DM_MAPIO_KILL;
        goto done;
    }

    /* the size must be a multiple of the block size */
    if (size % e->block_size)
    {
        printk(KERN_CRIT "%s: unaligned request size: %u\n", func, size);
        dt->error = TARGET_NAME ": unaligned request size";
        ret = DM_MAPIO_KILL;
        goto done;
    }

    if (bio_op(bio) == REQ_OP_READ)
    {
        ret = _ephemeral_map_read(dt, bio);
        goto done;
    }
    else if (bio_op(bio) == REQ_OP_WRITE)
    {
        ret = _ephemeral_map_write(dt, bio);
        goto done;
    }
    else
    {
        printk(KERN_CRIT "%s(): unknown\n", func);
        ret = DM_MAPIO_KILL;
        goto done;
    }

done:

    return ret;
}

static void _ephemeral_status(
    struct dm_target* dt,
    status_type_t status_type,
    unsigned status_flags,
    char* result,
    unsigned maxlen)
{
    ephemeral_t* e = (ephemeral_t*)dt->private;

    if (result)
        *result = '\0';

    switch (status_type)
    {
	case STATUSTYPE_INFO:
        {
            const u64 block_size = e->block_size;
            const u64 pages = e->hashtree.num_pages_allocated;
            const u64 bytes = pages * PAGE_SIZE;

            snprintf(result, maxlen, "block_size=%llu pages=%llu bytes=%llu",
                block_size, pages, bytes);

            break;
        }
	case STATUSTYPE_TABLE:
        {
            break;
        }
        default:
        {
            break;
        }
    }
}

/* implement this function so io_hints() will be called below */
static int _ephemeral_iterate_devices(
    struct dm_target* ti,
    iterate_devices_callout_fn fn,
    void* data)
{
    ephemeral_t* e = (ephemeral_t*)ti->private;

    return fn(ti, e->dev, 0, ti->len, data);
}

static void _ephemeral_io_hints(
    struct dm_target* ti,
    struct queue_limits* limits)
{
    ephemeral_t* e = (ephemeral_t*)ti->private;

    limits->max_segment_size = e->block_size;
    limits->logical_block_size = e->block_size;
    limits->physical_block_size = e->block_size;

    /* all requests must be on block-size multiples */
    limits->io_min = e->block_size;
}

static struct target_type ephemeral =
{
    .name = TARGET_NAME,
    .version = {1,0,0},
    .module = THIS_MODULE,
    .ctr = _ephemeral_ctr,
    .dtr = _ephemeral_dtr,
    .map = _ephemeral_map,
    .status = _ephemeral_status,
    .iterate_devices = _ephemeral_iterate_devices,
    .io_hints = _ephemeral_io_hints,
};

static int _ephemeral_init(void)
{
    const char* func = __FUNCTION__;

    T( printk(KERN_CRIT "%s(): enter\n", func); )

    if (dm_register_target(&ephemeral) < 0)
        printk(KERN_CRIT "%s() failed\n", func);

    return 0;
}

static void _ephemeral_exit(void)
{
    dm_unregister_target(&ephemeral);
}

module_init(_ephemeral_init);
module_exit(_ephemeral_exit);
MODULE_LICENSE("GPL");
