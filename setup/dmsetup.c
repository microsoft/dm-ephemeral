// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdbool.h>
#include <linux/loop.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/sysmacros.h>
#include <sys/random.h>
#include <libdevmapper.h>

#include "eraise.h"
#include "color.h"
#include "dmsetup.h"

#define DM_UUID_LEN 129

static int _test_exists(const char* path)
{
    int ret = 0;
    struct stat st;

    if (stat(path, &st) != 0)
        ERAISE(-EINVAL);

done:
    return ret;
}

static int _test_block_device(const char* path)
{
    int ret = 0;
    struct stat st;

    if (stat(path, &st) != 0)
        ERAISE(-errno);

    if (!S_ISBLK(st.st_mode))
        return -EINVAL;

done:
    return ret;
}

/* assign the next free loop device */
static int _get_next_free_loopback_device(char loop_out[PATH_MAX])
{
    int ret = 0;
    int index;
    int fd = -1;
    char loop[PATH_MAX];

    if (loop_out)
        *loop_out = '\0';

    if (!loop_out)
        ERAISE(-EINVAL);

    /* open the loopback control device */
    if ((fd = open("/dev/loop-control", O_RDONLY | O_CLOEXEC)) < 0)
    {
        ret = -errno;
        goto done;
    }

    /* get the next available loopback index */
    if ((index = ioctl(fd, LOOP_CTL_GET_FREE)) < 0)
        ERAISE(-errno);

    /* format the loopback path */
    snprintf(loop, PATH_MAX, "/dev/loop%u", index);

    /* fail if not a block device */
    ECHECK(_test_block_device(loop));

    strcpy(loop_out, loop);

done:

    if (fd >= 0)
        close(fd);

    return ret;
}

static int _attach_loopback_device(
    const char* pathname,
    char loop_out[PATH_MAX])
{
    int ret = 0;
    int fd = -1;
    int loop_fd = -1;
    char loop[PATH_MAX];

    if (!pathname || !loop_out)
        ERAISE(-EINVAL);

    /* open for read-write-exclusive access */
    if ((fd = open(pathname, O_RDWR | O_EXCL)) < 0)
        ERAISE(-errno);

    /* associate pathname with a loopback device */
    for (;;)
    {
        ECHECK(_get_next_free_loopback_device(loop));

        if ((loop_fd = open(loop, O_RDWR)) < 0)
            ERAISE(-ENOENT);

        if (ioctl(loop_fd, LOOP_SET_FD, fd) >= 0)
            break;

        if (errno != EBUSY)
            ERAISE(-errno);

        close(loop_fd);
        loop_fd = -1;
    }

    /* set the name for this loop device */
    {
        struct loop_info64 info = {0};
        char* name = (char*)info.lo_file_name;

        if (snprintf(name, LO_NAME_SIZE, "%s", pathname) >= LO_NAME_SIZE)
            ERAISE(-ENAMETOOLONG);

        if (ioctl(loop_fd, LOOP_SET_STATUS64, &info) < 0)
        {
            int err = errno;
            ioctl(loop_fd, LOOP_CLR_FD, 0);
            ERAISE(-err);
        }
    }

    /* double check that LOOP_SET_STATUS64 was able to set the name */
    {
        struct loop_info64 info = {0};

        if (ioctl(loop_fd, LOOP_GET_STATUS64, &info) < 0)
            ERAISE(-errno);

        if (strcmp((const char*)info.lo_file_name, pathname) != 0)
            ERAISE(-EINVAL);
    }

    strcpy(loop_out, loop);

done:

    if (fd >= 0)
        close(fd);

    if (loop_fd >= 0)
        close(loop_fd);

    return ret;
}

static void _dm_log_with_errno_fn(
    int level,
    const char* file,
    int line,
    int dm_errno_or_class,
    const char* fmt,
    ...)
{
// #define ENABLE_LIBDEVMAPPER_LOGGING
#ifdef ENABLE_LIBDEVMAPPER_LOGGING
    fprintf(stderr, "%s", COLOR_RED);

    /* ignore all logging from libdevmapper */
    fprintf(stderr, "%s(%u): %d: ", file, line, dm_errno_or_class);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "%s\n", COLOR_RESET);
#endif
}

int dmsetup_create_emphemeral(
    const char* name,
    const char* pathname,
    uint64_t num_sectors,
    uint64_t block_size)
{
    int ret = 0;
    char device[PATH_MAX];
    char args[2 * PATH_MAX];
    struct dm_task* dmt = NULL;
    struct dm_info dmi;

    /* check for invalid parameters */
    if (!name || !pathname || !num_sectors)
        ERAISE(-EINVAL);

    if (!dmsetup_valid_block_size(block_size))
        ERAISE(-EINVAL);

    /* disable libdevmapper logging */
    dm_log_with_errno_init(_dm_log_with_errno_fn);

    /* if device does not exist */
    if (_test_exists(pathname) != 0)
        ERAISE(-ENOENT);

    /* if pathname not a block device, then map to a loopback device */
    if (_test_block_device(pathname) == 0)
    {
        strcpy(device, pathname);
    }
    else
    {
        ECHECK(_attach_loopback_device(pathname, device));
    }

    /* format the args */
    if (snprintf(
        args,
        sizeof(args),
        "%s %lu",
        device,
        block_size) >= sizeof(args))
    {
        ERAISE(-ENAMETOOLONG);
    }

    /* create device-mapper task */
    if (!(dmt = dm_task_create(DM_DEVICE_CREATE)))
    {
        ERAISE(-EINVAL);
    }

    /* set /dev/mapper/<name> */
    if (!dm_task_set_name(dmt, name))
        ERAISE(-EINVAL);

    /* set target parameters */
    if (!dm_task_add_target(dmt, 0, num_sectors, "dm_ephemeral", args))
        ERAISE(-EINVAL);

    /* run the task */
    if (!dm_task_run(dmt))
    {
        printf("errno=%s\n", strerror(errno));
        ERAISE(-EINVAL);
    }

    /* now check that target exists */
    if (!dm_task_get_info(dmt, &dmi) || !dmi.exists)
        ERAISE(-EINVAL);

done:

    if (dmt)
    {
        dm_task_destroy(dmt);
        dm_task_update_nodes();
    }

    dm_lib_release();

    return ret;
}

#define KEY_BYTES 64

int dmsetup_create_crypt(
    const char* name,
    const char* pathname,
    uint64_t num_sectors,
    const char* cipher,
    size_t __key_size)
{
    int ret = 0;
    char device[PATH_MAX];
    char args[2 * PATH_MAX];
    struct dm_task* dmt = NULL;
    struct dm_info dmi;
    uint8_t key[KEY_BYTES]; /* space for 512-bit key */
    char hexstr[(KEY_BYTES * 2) + 1];
    size_t key_bytes = __key_size / 8;

    /* check for invalid parameters */
    if (!name || !pathname)
        ERAISE(-EINVAL);

    /* disable libdevmapper logging */
    dm_log_with_errno_init(_dm_log_with_errno_fn);

    /* if device does not exist */
    if (_test_exists(pathname) != 0)
        ERAISE(-ENOENT);

    /* if pathname not a block device, then map to a loopback device */
    if (_test_block_device(pathname) == 0)
    {
        strcpy(device, pathname);
    }
    else
    {
        ECHECK(_attach_loopback_device(pathname, device));
    }

    /* generate the hexadecimal string key */
    {
        if (getrandom(key, sizeof(key), 0) != sizeof(key))
            ERAISE(-ENOSYS);

        for (size_t i = 0; i < key_bytes; i++)
            snprintf(&hexstr[i*2], 3, "%02x", key[i]);
    }

    /* format the args */
    {
        unsigned long iv_offset = 0;
        unsigned long offset = 0;

        if (snprintf(args, sizeof(args),
            "%s %s %lu %s %lu 1 sector_size:4096",
            cipher,
            hexstr,
            iv_offset,
            device,
            offset) >= sizeof(args))
        {
            ERAISE(-ENAMETOOLONG);
        }
    }

    /* create device-mapper task */
    if (!(dmt = dm_task_create(DM_DEVICE_CREATE)))
    {
        ERAISE(-EINVAL);
    }

    /* set /dev/mapper/<name> */
    if (!dm_task_set_name(dmt, name))
        ERAISE(-EINVAL);

    /* set target parameters */
    if (!dm_task_add_target(dmt, 0, num_sectors, "crypt", args))
        ERAISE(-EINVAL);

    /* run the task */
    if (!dm_task_run(dmt))
    {
        printf("errno=%s\n", strerror(errno));
        ERAISE(-EINVAL);
    }

    /* now check that target exists */
    if (!dm_task_get_info(dmt, &dmi) || !dmi.exists)
        ERAISE(-EINVAL);

done:

    if (dmt)
    {
        dm_task_destroy(dmt);
        dm_task_update_nodes();
    }

    dm_lib_release();

    return ret;
}

int dmsetup_remove(const char* name)
{
    int ret = 0;
    struct dm_task* dmt = NULL;
    const size_t num_retries = 10;
    int last_errno = 0;

    if (!name)
        ERAISE(-EINVAL);

    /* disable libdevmapper logging */
    dm_log_with_errno_init(_dm_log_with_errno_fn);

    if (!(dmt = dm_task_create(DM_DEVICE_REMOVE)))
        ERAISE(-errno);

    if (!dm_task_set_name(dmt, name))
        ERAISE(-errno);

    /* try up to to num_retries while device is still busy */
    for (size_t i = 0; i < num_retries; i++)
    {
        if (dm_task_run(dmt))
        {
            /* success */
            goto done;
        }

        last_errno = errno;

        if (errno == ENXIO)
            break;

        /* Sleep for 1/10th of a second */
        struct timespec req = { .tv_sec = 0, .tv_nsec = 100000000 };
        nanosleep(&req, NULL);
    }

    ret = -last_errno;

done:

    if (dmt)
    {
        dm_task_destroy(dmt);
        dm_task_update_nodes();
    }

    dm_lib_release();

    return ret;
}

int dmsetup_status(const char* name, char* buf, size_t bufsize)
{
    int ret = 0;
    struct dm_task* dmt = NULL;
    const size_t num_retries = 10;
    int last_errno = 0;
    struct dm_info dmi;

    if (buf)
        *buf = '\0';

    if (!name || !buf)
        ERAISE(-EINVAL);

    /* disable libdevmapper logging */
    dm_log_with_errno_init(_dm_log_with_errno_fn);

    if (!(dmt = dm_task_create(DM_DEVICE_STATUS)))
        ERAISE(-errno);

    if (!dm_task_set_name(dmt, name))
        ERAISE(-errno);

    /* try up to to num_retries while device is still busy */
    for (size_t i = 0; i < num_retries; i++)
    {
        if (dm_task_run(dmt))
        {
            last_errno = 0;
            break;
        }

        last_errno = errno;

        if (errno == ENXIO)
            break;

        /* Sleep for 1/10th of a second */
        struct timespec req = { .tv_sec = 0, .tv_nsec = 100000000 };
        nanosleep(&req, NULL);
    }

    if (last_errno != 0)
        ERAISE(-last_errno);

    if (!dm_task_get_info(dmt, &dmi))
        ERAISE(-EINVAL);

    if (!dmi.exists)
        ERAISE(-ENODEV);

    /* build the status line */
    {
        void* next = NULL;
	uint64_t start;
        uint64_t length;
	char *target_type = NULL;
        char *params = NULL;

	next = dm_get_next_target(
            dmt, next, &start, &length, &target_type, &params);

	if (next || start || length == 0 || !target_type)
            ERAISE(-EINVAL);

        snprintf(buf, bufsize, "%lu %lu %s %s",
            start, length, target_type, params);
    }

done:

    if (dmt)
    {
        dm_task_destroy(dmt);
        dm_task_update_nodes();
    }

    dm_lib_release();

    return ret;
}
