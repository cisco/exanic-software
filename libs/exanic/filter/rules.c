#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#include "../exanic.h"
#include "rules.h"

#define EXANIC_CONFIG_PATH "/dev/shm/exanic"
#define EXANIC_CONFIG_UMASK 0007

int exanic_set_filter_string(const char *ruleset, int slot, const char *filter)
{
    int fd;
    size_t filter_len, filter_off;
    ssize_t len;
    char path[256];
    mode_t old_umask;
    int err;

    filter_len = strlen(filter);
    filter_off = 0;

    /* Make sure the directory exists */
    err = mkdir(EXANIC_CONFIG_PATH, 0770);
    if ((err < 0) && (errno != EEXIST)) {
        exanic_err_printf("%s: mkdir failed: %s", path, strerror(errno));
        return -1;
    }
    snprintf(path, sizeof(path), EXANIC_CONFIG_PATH "/%s", ruleset);
    err = mkdir(path, 0770);
    if ((err < 0) && (errno != EEXIST)) {
        exanic_err_printf("%s: mkdir failed: %s", path, strerror(errno));
        return -1;
    }
    snprintf(path, sizeof(path), EXANIC_CONFIG_PATH "/%s/filters", ruleset);
    err = mkdir(path, 0770);
    if ((err < 0) && (errno != EEXIST)) {
        exanic_err_printf("%s: mkdir failed: %s", path, strerror(errno));
        return -1;
    }

    old_umask = umask(EXANIC_CONFIG_UMASK);
    /* Overwrite the file with the filter string */
    snprintf(path, sizeof(path), EXANIC_CONFIG_PATH "/%s/filters/%d",
            ruleset, slot);
    fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0660);
    if (fd == -1)
    {
        exanic_err_printf("%s: open failed: %s", path, strerror(errno));
        goto err_open;
    }

    if (ftruncate(fd, 0) == -1)
    {
        exanic_err_printf("%s: ftruncate failed: %s", path, strerror(errno));
        goto err_ftruncate;
    }

    while (filter_len > filter_off)
    {
        len = write(fd, filter + filter_off, filter_len - filter_off);
        if (len == -1)
        {
            exanic_err_printf("%s: write failed: %s", path, strerror(errno));
            goto err_write;
        }
        filter_off += len;
    }

    close(fd);
    umask(old_umask);
    return 0;

err_write:
err_ftruncate:
    close(fd);
err_open:
    umask(old_umask);
    return -1;
}

int exanic_get_filter_string(const char *ruleset, int slot, char *filter,
                             int filter_len)
{
    int fd;
    ssize_t len;
    char path[256];

    /* Read the entire file into the buffer */
    snprintf(path, sizeof(path), EXANIC_CONFIG_PATH "/%s/filters/%d",
            ruleset, slot);
    fd = open(path, O_RDONLY);
    if (fd == -1)
    {
        if (errno == ENOENT)
        {
            filter[0] = '\0';
            return 0;
        }
        exanic_err_printf("%s: open failed: %s", path, strerror(errno));
        return -1;
    }

    len = read(fd, filter, filter_len - 1);
    if (len == -1)
    {
        exanic_err_printf("%s: read failed: %s", path, strerror(errno));
        close(fd);
        return -1;
    }

    filter[len] = '\0';
    close(fd);
    return 0;
}

int exanic_clear_filter_string(const char *ruleset, int slot)
{
    char path[256];

    /* Delete the file containing the filter string */
    snprintf(path, sizeof(path), EXANIC_CONFIG_PATH "/%s/filters/%d",
            ruleset, slot);

    if (unlink(path) == -1 && errno != ENOENT)
    {
        exanic_err_printf("%s: unlink failed: %s", path, strerror(errno));
        return -1;
    }

    return 0;
}

int exanic_clear_all_filter_strings(const char *ruleset)
{
    char path[512];
    DIR *d;
    struct dirent *e;

    /* Delete all files in the directory */
    snprintf(path, sizeof(path), EXANIC_CONFIG_PATH "/%s/filters", ruleset);
    if ((d = opendir(path)) == NULL)
    {
        if (errno == ENOENT)
            return 0;
        exanic_err_printf("%s: opendir failed: %s", path, strerror(errno));
        return -1;
    }

    while ((e = readdir(d)) != NULL)
    {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        snprintf(path, sizeof(path), EXANIC_CONFIG_PATH "/%s/filters/%s",
                ruleset, e->d_name);
        if (unlink(path) == -1 && errno != ENOENT)
        {
            exanic_err_printf("%s: unlink failed: %s", path, strerror(errno));
            closedir(d);
            return -1;
        }
    }
    closedir(d);

    /* Remove the directory */
    snprintf(path, sizeof(path), EXANIC_CONFIG_PATH "/%s/filters", ruleset);
    if (rmdir(path) == -1 && errno != ENOENT)
    {
        exanic_err_printf("%s: rmdir failed: %s", path, strerror(errno));
        return -1;
    }

    return 0;
}
