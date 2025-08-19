// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <limits.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include "dmsetup.h"
#include "color.h"

#define EXTENSION "dm-crypt-9cae35b4b3d7c2db"

#define SECTOR_SIZE 512

#define USAGE \
    "Usage: %s <action> [options] arguments...\n" \
    "\n" \
    "actions:\n" \
    "    create [options] <device> <dm-name>\n" \
    "    remove <dm-name>\n" \
    "    status <dm-name>\n"

#define CREATE_USAGE \
    "Usage: %s %s [options] <device> <dm-name>\n" \
    "\n" \
    "options:\n" \
    "    --block-size=<block-size> -- use this block size\n" \
    "    --crypt                   -- inject dm-crypt target\n" \
    "    --cipher=<cipher-spec>    -- cipher used by dm-crypt target\n" \
    "    --key-size=<num-bits>     -- key size used by dm-crypt target\n"

const char* arg0;
const char* arg1;

__attribute__((format(printf, 1, 2)))
void _err(const char* fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s", COLOR_YELLOW);

    if (arg1)
        fprintf(stderr, "%s %s: error: ", arg0, arg1);
    else
        fprintf(stderr, "%s: error: ", arg0);

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");

    fprintf(stderr, "%s", COLOR_RESET);

    exit(1);
}

static ssize_t _get_device_size(const char* pathname)
{
    ssize_t ret = 0;
    int fd;
    struct stat st;
    size_t size;

    if ((fd = open(pathname, O_RDWR | O_EXCL)) < 0)
    {
        ret = -errno;
        goto done;
    }

    if (fstat(fd, &st) != 0)
    {
        ret = -errno;
        goto done;
    }

    if (S_ISREG(st.st_mode))
    {
        size = st.st_size;
    }
    else if (ioctl(fd, BLKGETSIZE64, &size) != 0)
    {
        ret = -errno;
        goto done;
    }

    ret = size;

done:

    if (fd >= 0)
        close(fd);

    return ret;
}

static int _getopt(
    int* argc,
    const char* argv[],
    const char* opt,
    const char** optarg)
{
    int ret = 0;
    size_t optlen;

    if (optarg)
        *optarg = NULL;

    if (!argc || !argv || !opt)
        _err("unexpected: bad _getopt() parameters");

    optlen = strlen(opt);

    /* search for the option */
    for (int i = 0; i < *argc; )
    {
        if (strcmp(argv[i], opt) == 0)
        {
            if (optarg)
            {
                if (i + 1 == *argc)
                    _err("missing option argument for %s", opt);

                *optarg = argv[i + 1];
                memmove(&argv[i], &argv[i+2], (*argc-i-1) * sizeof(char*));
                (*argc) -= 2;
                goto done;
            }
            else
            {
                memmove(&argv[i], &argv[i+1], (*argc-i) * sizeof(char*));
                (*argc)--;
                goto done;
            }
        }
        else if (strncmp(argv[i], opt, optlen) == 0 && argv[i][optlen] == '=')
        {
            if (!optarg)
                _err("extraneous '=' character for %s", opt);

            *optarg = &argv[i][optlen+1];
            memmove(&argv[i], &argv[i+1], (*argc-i) * sizeof(char*));
            (*argc)--;
            goto done;
        }
        else
        {
            i++;
        }
    }

    /* option was not found */
    ret = 1;

done:

    return ret;
}

static int _getopt_u64(
    int* argc,
    const char* argv[],
    const char* opt,
    uint64_t* value_out)
{
    const char* value;

    if (_getopt(argc, argv, opt, &value) == 0)
    {
        char* end = NULL;
        unsigned long long x = strtoull(value, &end, 0);

        if (!end || *end != '\0')
            _err("bad option argument for %s: %s\n", opt, value);

        *value_out = x;
        return 0;
    }
    else
    {
        /* option was not found */
        return 1;
    }
}

#define DEFAULT_KEY_SIZE 512

typedef struct cipher
{
    const char* spec;
    size_t key_sizes[4];
}
cipher_t;

static const cipher_t _ciphers[] =
{
    /* aes-xts */
    { "aes-xts-benbi", { 256, 512 } },
    { "aes-xts-null", { 256, 512 } },
    { "aes-xts-plain", { 256, 512 } },
    { "aes-xts-plain64", { 256, 512 } },
    /* aes-cbc */
    { "aes-cbc-benbi", { 128, 256 } },
    { "aes-cbc-null", { 128, 256 } },
    { "aes-cbc-plain", { 128, 256 } },
    { "aes-cbc-plain64", { 128, 256 } },
    { "aes-cbc-essiv:sha256", { 128, 256 } },
    /* aes-ecb */
    { "aes-ecb-benbi", { 128, 256 } },
    { "aes-ecb-null", { 128, 256 } },
    { "aes-ecb-plain", { 128, 256 } },
    { "aes-ecb-plain64", { 128, 256 } },
};

/* default cipher (also default cipher for LUKS) */
#define DEFAULT_CIPHER "aes-xts-plain64"

static size_t _num_ciphers = sizeof(_ciphers) / sizeof(_ciphers[0]);

static void _check_cipher(const char* cipher, size_t* key_size)
{
    for (size_t i = 0; i < _num_ciphers; i++)
    {
        const cipher_t* c = &_ciphers[i];

        if (strcmp(c->spec, cipher) == 0)
        {
            if (*key_size == 0) /* pick the biggest key size */
            {
                size_t max_key_size = 0;

                for (size_t j = 0; c->key_sizes[j]; j++)
                {
                    if (c->key_sizes[j] > max_key_size)
                        max_key_size = c->key_sizes[j];
                }

                *key_size = max_key_size;
                return;
            }
            else /* validate the key size */
            {
                for (size_t j = 0; c->key_sizes[j]; j++)
                {
                    if (c->key_sizes[j] == *key_size)
                        return;
                }

                fprintf(stderr, "%s", COLOR_YELLOW);
                fprintf(stderr, "%s %s: error: bad key size for cipher: %s\n",
                    arg0, arg1, cipher);

                fprintf(stderr, "supported key sizes: ");

                for (size_t j = 0; c->key_sizes[j]; j++)
                {
                    fprintf(stderr, "%zu", c->key_sizes[j]);

                    if (c->key_sizes[j + 1])
                        fprintf(stderr, ", ");
                }

                fprintf(stderr, "\n");
                fprintf(stderr, "%s", COLOR_RESET);
                exit(1);
            }
        }
    }

    /* report unsuppored cipher */
    {
        fprintf(stderr, "%s", COLOR_YELLOW);
        fprintf(stderr, "%s %s: error: unsupported cipher: %s\n",
            arg0, arg1, cipher);

        fprintf(stderr, "supported ciphers\n");

        for (size_t i = 0; i < _num_ciphers; i++)
            fprintf(stderr, "    %s\n", _ciphers[i].spec);

        fprintf(stderr, "%s", COLOR_RESET);
        exit(1);
    }
}

static int _create_subcommand(int argc, const char* argv[])
{
    ssize_t size;
    size_t num_sectors;
    int r;
    bool crypt = false;
    uint64_t block_size = 4096; /* default block size */
    const char* cipher = NULL;
    uint64_t key_size = 0; /* key size in bits */

    if (_getopt(&argc, argv, "--crypt", NULL) == 0)
        crypt = true;

    _getopt_u64(&argc, argv, "--block-size", &block_size);

    _getopt_u64(&argc, argv, "--key-size", &key_size);

    if (_getopt(&argc, argv, "--cipher", &cipher) == 0)
    {
        if (!crypt)
            _err("--cipher option without --crypt option");
    }
    else
    {
        cipher = DEFAULT_CIPHER;
    }

    /* check the cipher and key-size */
    _check_cipher(cipher, &key_size);

    if (!dmsetup_valid_block_size(block_size))
        _err("--block-size must be 512, 1024, 2048, or 4096");

    if (argc != 4)
    {
        fprintf(stderr, CREATE_USAGE, arg0, arg1);
        exit(1);
    }

    const char* device = argv[2];
    const char* name = argv[3];

    /* get the size of this device */
    if ((size = _get_device_size(device)) < 0)
    {
        _err("cannot determine device size: %s (%s)", device, strerror(-size));
    }

    /* the device size must be a multiple of the sector size */
    if (size % SECTOR_SIZE)
    {
        _err("device size sector-size multiple: %s (%zu)", device, size);
    }

    num_sectors = size / SECTOR_SIZE;

    /* handle --crypt option */
    if (crypt)
    {
        char crypt_name[PATH_MAX];
        char crypt_device[PATH_MAX];
        const char ext[] = EXTENSION;
        int n = PATH_MAX;

        /* form the ephemeral target name by adding ".emphemeral" */
        if (snprintf(crypt_name, n, "%s.%s", name, ext) >= n)
            _err("target name is too long: %s", name);

        /* form the crypt device name from <dm-name> */
        if (snprintf(crypt_device, n, "/dev/mapper/%s.%s", name, ext) >= n)
            _err("target name is too long: %s", name);

        /* create the "ephemeral" device */
        if ((r = dmsetup_create_crypt(
            crypt_name, device, num_sectors, cipher, key_size)) < 0)
        {
            _err("failed to create crypt device: /dev/mapper/%s(%s): %s\n",
                crypt_name, device, strerror(-r));
        }

        printf("%screated %s%s\n", COLOR_GREEN, crypt_device, COLOR_RESET);

        /* create the "crypt" device */
        if ((r = dmsetup_create_emphemeral(
            name, crypt_device, num_sectors, block_size)) < 0)
        {
            /* remove the crypt device */
            dmsetup_remove(crypt_name);

            _err("failed to create crypt device: /dev/mapper/%s(%s): %s\n",
                name, crypt_device, strerror(-r));
        }

        printf("%screated /dev/mapper/%s%s\n", COLOR_GREEN, name, COLOR_RESET);
    }
    else
    {
        /* create the "ephemeral" device */
        if ((r = dmsetup_create_emphemeral(
            name, device, num_sectors, block_size)) < 0)
        {
            _err("failed to create ephemeral device: /dev/mapper/%s(%s): %s\n",
                name, device, strerror(-r));
        }

        printf("%screated /dev/mapper/%s%s\n", COLOR_GREEN, name, COLOR_RESET);
    }

    return 0;
}

static int _remove_subcommand(int argc, const char* argv[])
{
    int r;

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s %s <dm-name>\n", arg0, arg1);
        exit(1);
    }

    const char* name = argv[2];

    if ((r = dmsetup_remove(name)) < 0)
        _err("failed to remove /dev/mapper/%s: %s\n", name, strerror(-r));

    printf("%sremoved /dev/mapper/%s%s\n", COLOR_GREEN, name, COLOR_RESET);

    /* if <dm-name> was "crypt" device, then also remove "ephemeral" device */
    {
        char crypt_name[PATH_MAX];
        char crypt_device[PATH_MAX];
        const char ext[] = EXTENSION;
        int n = PATH_MAX;
        struct stat statbuf;

        /* form the ephemeral target name by adding ".emphemeral" */
        if (snprintf(crypt_name, n, "%s.%s", name, ext) >= n)
            _err("target name is too long: %s", name);

        /* form the crypt device name from <dm-name> */
        if (snprintf(crypt_device, n, "/dev/mapper/%s.%s", name, ext) >= n)
            _err("target name is too long: %s", name);

        /* if the intermediate ephemeral device exists */
        if (stat(crypt_device, &statbuf) == 0)
        {
            if (dmsetup_remove(crypt_name) < 0)
            {
                _err("failed to remove /dev/mapper/%s: %s\n",
                    crypt_name, strerror(-r));
            }

            printf("%sremoved /dev/mapper/%s%s\n",
                COLOR_GREEN, crypt_name, COLOR_RESET);
        }
    }

    return 0;
}

static int _status_subcommand(int argc, const char* argv[])
{
    int r;
    char buf[4096];

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s %s <dm-name>\n", arg0, arg1);
        exit(1);
    }

    const char* name = argv[2];

    if ((r = dmsetup_status(name, buf, sizeof(buf))) < 0)
        _err("status failed for /dev/mapper/%s: %s\n", name, strerror(-r));

    printf("%s%s%s\n", COLOR_GREEN, buf, COLOR_RESET);

    return 0;
}

int main(int argc, const char* argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, USAGE, argv[0]);
        exit(1);
    }

    arg0 = argv[0];
    arg1 = argv[1];

    if (strcmp(argv[1], "create") == 0)
    {
        return _create_subcommand(argc, argv);
    }
    else if (strcmp(argv[1], "remove") == 0)
    {
        return _remove_subcommand(argc, argv);
    }
    else if (strcmp(argv[1], "status") == 0)
    {
        return _status_subcommand(argc, argv);
    }
    else
    {
        _err("unknown subcommand: %s", argv[1]);
    }

    return 0;
}
