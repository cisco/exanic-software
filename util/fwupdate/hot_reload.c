/*
 * hot_reload.c: Functions to "hot update" an ExaNIC card without a system reboot
 * Requires support in ExaNIC firmware, driver, and in Linux (/sys/bus/pci/rescan)
 *
 * Copyright (C) 2017 Exablaze Pty Ltd
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <exanic/exanic.h>
#include <exanic/ioctl.h>
#include <exanic/register.h>
#include <exanic/config.h>
#include <exanic/util.h>
#include "hot_reload.h"

/*
 * These definitions are defined by (or derived from) the PCIe 3.0
 * base spec, Nov. 10 2010, mostly from sections 7.8 and 7.10.
 */
#define PCIE_CFG_SPACE_MAX_LEN      4096
#define PCIE_EXT_CAP_FIRST          0x100
#define PCIE_EXT_CAP_ID_MASK        0x0000FFFF
#define PCIE_EXT_CAP_PTR_MASK       0xFFF00000
#define PCIE_EXT_CAP_PTR_SHIFT      20
#define PCIE_AER_CAP_ID             0x0001
#define PCIE_AER_SURPRISE_DOWN_MASK (1 << 5)
#define PCIE_AER_EXTCAP_MASK_OFFSET 8
typedef union {
    uint8_t b[PCIE_CFG_SPACE_MAX_LEN];
    uint16_t w[PCIE_CFG_SPACE_MAX_LEN/2];
    uint32_t l[PCIE_CFG_SPACE_MAX_LEN/4];
} pcie_cfg_space;
typedef uint16_t pcie_cfg_space_offset;

/*
 * Check that the currently loaded firmware has support for hot reloading
 */
bool check_firmware_can_hot_reload(exanic_t *exanic, bool silent)
{
    uint32_t caps = exanic_register_read(exanic, REG_EXANIC_INDEX(REG_EXANIC_CAPS));
    exanic_function_id_t function = exanic_get_function_id(exanic);

    /* this check is here to provide a more useful error message for demo devkits */
    if (function == EXANIC_FUNCTION_DEVKIT && exanic_is_devkit_demo(exanic))
    {
        if (!silent)
            fprintf(stderr, "ERROR: the hot reload feature is not available for evaluation FDKs\n");
        return false;
    }

    if (!(caps & EXANIC_CAP_HOT_RELOAD))
    {
        if (!silent)
            fprintf(stderr, "ERROR: the firmware version that is currently loaded does not support reconfiguring the FPGA without a host reboot\n");
        return false;
    }

    return true;
}

/*
 * Check that the currently loaded firmware has support for hot reloading,
 * the user has permission to rescan the PCI bus, and that nothing is using
 * the driver
 */
bool check_can_hot_reload(exanic_t *exanic, bool silent)
{
    FILE *fp = fopen("/sys/bus/pci/rescan", "w");
    if (!fp)
    {
        if (!silent)
            fprintf(stderr, "ERROR: could not open /sys/bus/pci/rescan for writing (you must be root to reconfigure the FPGA without a host reboot)\n");
        return false;
    }
    fclose(fp);

    struct exanicctl_usage_info usage;
    if (ioctl(exanic->fd, EXANICCTL_DEVICE_USAGE, &usage) == -1)
    {
        if (!silent)
            fprintf(stderr, "ERROR: could not obtain usage information from driver (driver 2.2.1 or later required)\n");
        return false;
    }

    /* we have a mapping to the TX feedback region, so allow one user */
    if (usage.users > 1)
    {
        if (!silent)
            fprintf(stderr, "ERROR: device still in use\n");
        return false;
    }

    return check_firmware_can_hot_reload(exanic, silent);
}

/*
 * Utility function for writing the character '1' to files in the /sys filesystem.
 */
static bool write_1_to_file(char *filename)
{
    FILE *fp = fopen(filename, "w");
    if (!fp)
    {
        fprintf(stderr, "ERROR: could not open %s for writing\n", filename);
        return false;
    }
    if (fputc('1', fp) == EOF)
    {
        fprintf(stderr, "ERROR: failed to write to %s\n", filename);
        return false;
    }
    fclose(fp);
    return true;
}

/*
 * Utility function to lseek and write
 */
static ssize_t write_at_offset(int fd, off_t offset, const void *buf, size_t count)
{
    if (lseek(fd, offset, SEEK_SET) == (off_t)-1)
        return -1;

    return write(fd, buf, count);
}

/*
 * Given a PCIe config space of size `sz`, locate a PCIe Advanced Error
 * Reporting (AER) structure and return a space-local pointer to its error
 * mask. Can fail if the device does not support AER, or the size of the
 * space indicates it doesn't have any extended capabilities.
 */
pcie_cfg_space_offset find_aer_mask(pcie_cfg_space *cfg_space, size_t sz)
{
    pcie_cfg_space_offset cap_ptr = PCIE_EXT_CAP_FIRST;
    uint32_t cap_id;

    if (sz < PCIE_EXT_CAP_FIRST)
        return 0;

    while (cap_ptr != 0
           && (cap_ptr + PCIE_AER_EXTCAP_MASK_OFFSET + sizeof(uint32_t)) < sz)
    {
        cap_id = cfg_space->l[cap_ptr/4] & PCIE_EXT_CAP_ID_MASK;

        if (cap_id == PCIE_AER_CAP_ID)
            return cap_ptr + PCIE_AER_EXTCAP_MASK_OFFSET;

        cap_ptr = (cfg_space->l[cap_ptr/4]
                   & PCIE_EXT_CAP_PTR_MASK) >> PCIE_EXT_CAP_PTR_SHIFT;
    }

    return 0;
}

/*
 * Reload firmware without requiring a host reboot
 */
exanic_t *reload_firmware(exanic_t *exanic, void (*report_progress)())
{
    char ifname[64];
    char remove_path[256];
    char device_path[256];
    char resolved_path[PATH_MAX];
    char parent_config_path[PATH_MAX];
    int parent_config_fd;
    pcie_cfg_space parent_config_space;
    ssize_t parent_config_space_size;
    DIR *dir;
    struct dirent *dirent;
    char new_device_name[64];
    int  new_device_port;
    unsigned int attempts;
    pcie_cfg_space_offset aer_mask_offset = 0;
    uint32_t aer_mask, old_aer_mask;

    /* Get the interface name of the first port on the device */
    if (exanic_get_interface_name(exanic, 0, ifname, sizeof(ifname)) == -1)
    {
        fprintf(stderr, "ERROR: could not get ExaNIC interface name\n");
        exanic_release_handle(exanic);
        return NULL;
    }

    /* Get the sysfs path (with symlinks) into the pci device section of our net interface */
    snprintf(device_path, sizeof(device_path), "/sys/class/net/%s/device/net", ifname);

    /* Remove the symlinks so that the path contains no references to the net interface (which may change) */
    if (realpath(device_path, resolved_path) == NULL)
    {
        fprintf(stderr, "ERROR: unable to determine real path of %s\n", device_path);
        exanic_release_handle(exanic);
        return NULL;
    }

    /* Attempt to mask surprise down event on parent bridge */
    snprintf(parent_config_path, sizeof(parent_config_path), "/sys/class/net/%s/device/../config", ifname);
    parent_config_fd = open(parent_config_path, O_RDWR);
    if (parent_config_fd != -1)
    {
        parent_config_space_size = read(parent_config_fd, parent_config_space.b, PCIE_CFG_SPACE_MAX_LEN);
        if (parent_config_space_size > 0)
        {
            aer_mask_offset = find_aer_mask(&parent_config_space, parent_config_space_size);
            if (aer_mask_offset != 0)
            {
                aer_mask = old_aer_mask = parent_config_space.l[aer_mask_offset/4];
                aer_mask |= htole32(PCIE_AER_SURPRISE_DOWN_MASK);
                if (write_at_offset(parent_config_fd, aer_mask_offset, &aer_mask, sizeof(uint32_t)) != sizeof(uint32_t))
                    fprintf(stderr, "WARNING: attempt to ignore \"surprise down\" event failed (%s)\n", strerror(errno));
            }
        }
    }

    snprintf(remove_path, sizeof(remove_path), "/sys/class/net/%s/device/remove", ifname);

    exanic_register_write(exanic, REG_HW_INDEX(REG_HW_RELOAD_RESET_FPGA), 0x1);
    exanic_release_handle(exanic);
    if (!write_1_to_file(remove_path))
        return NULL;

    /* Wait for the firmware reload to trigger */
    sleep(1);
    report_progress();

    for (attempts = 0; attempts < 3; attempts++)
    {
        if (!write_1_to_file("/sys/bus/pci/rescan"))
            return NULL;

        /* Wait for the rescan */
        sleep(1);
        report_progress();

        /* Open the sysfs path corresponding to the PCI device we are using that we saved before */
        dir = opendir(resolved_path);
        if (dir != NULL)
            break;
    }

    /* Restore the previous AER mask in the parent bridge */
    if (parent_config_fd != -1)
    {
        if (aer_mask_offset != 0)
            write_at_offset(parent_config_fd, aer_mask_offset, &old_aer_mask, sizeof(uint32_t));
        close(parent_config_fd);
    }

    if (dir == NULL)
    {
        fprintf(stderr, "ERROR: device did not reappear at %s after hot reload. If you cannot find the card in lspci, a host reboot or recovery mode boot may be required.\n", resolved_path);
        return NULL;
    }

    /* Find a file in this directory that looks like a network interface */
    while ((dirent = readdir(dir)) != NULL)
    {
        if (strcmp(dirent->d_name, ".") && strcmp(dirent->d_name, "..") && dirent->d_type == DT_DIR)
            break;
    }
    closedir(dir);

    if (dirent == NULL)
    {
        fprintf(stderr, "ERROR: unable to find network interface in directory: %s\n", resolved_path);
        return NULL;
    }

    if (exanic_find_port_by_interface_name(dirent->d_name, new_device_name, sizeof(new_device_name), &new_device_port) == -1)
    {
        fprintf(stderr, "ERROR: unable to get exanic device name for interface name: %s\n", dirent->d_name);
        return NULL;
    }

    /* Try to reacquire handle */
    if ((exanic = exanic_acquire_handle(new_device_name)) == NULL)
    {
        fprintf(stderr, "%s: %s\n", new_device_name, exanic_get_last_error());
        return NULL;
    }
    return exanic;
}

