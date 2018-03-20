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
#include <unistd.h>
#include <dirent.h>
#include <exanic/exanic.h>
#include <exanic/register.h>
#include <exanic/config.h>
#include <exanic/util.h>
#include "hot_reload.h"

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
 * and that the user has permission to rescan the PCI bus
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
 * Reload firmware without requiring a host reboot
 */
exanic_t *reload_firmware(exanic_t *exanic, void (*report_progress)())
{
    char ifname[64];
    char remove_path[256];
    char device_path[256];
    char resolved_path[PATH_MAX];
    DIR *d;
    struct dirent *dir;
    char new_device_name[64];
    int  new_device_port;
    unsigned int attempts;

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
        d = opendir(resolved_path);
        if (d != NULL)
            break;
    }

    if (d == NULL)
    {
        fprintf(stderr, "ERROR: device did not reappear at %s after hot reload. If you cannot find the card in lspci, a host reboot or recovery mode boot may be required.\n", resolved_path);
        return NULL;
    }

    /* Find a file in this directory that looks like a network interface */
    while ((dir = readdir(d)) != NULL)
    {
        if (strcmp(dir->d_name, ".") && strcmp(dir->d_name, "..") && dir->d_type == DT_DIR)
            break;
    }

    if (dir == NULL)
    {
        fprintf(stderr, "ERROR: unable to find network interface in directory: %s\n", resolved_path);
        return NULL;
    }

    if (exanic_find_port_by_interface_name(dir->d_name, new_device_name, sizeof(new_device_name), &new_device_port) == -1)
    {
        fprintf(stderr, "ERROR: unable to get exanic device name for interface name: %s\n", dir->d_name);
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

