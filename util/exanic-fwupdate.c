/*
 * exanic-fwupdate: Used to update firmware on ExaNIC cards.
 *
 * Copyright (C) 2017 Exablaze Pty Ltd
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <sys/time.h>
#include <exanic/exanic.h>
#include <exanic/util.h>
#include "fwupdate/flash_access.h"
#include "fwupdate/file_access.h"
#include "fwupdate/hot_reload.h"

/*
 * Functions for progress reporting of each stage
 */

struct timeval tv_start, tv_end;

static void report_phase(const char *description)
{
    printf("%s...", description);
    fflush(stdout);
    gettimeofday(&tv_start, NULL);
}

static void report_progress()
{
    putchar('.');
    fflush(stdout);
}

static void report_phase_done()
{
    float time_taken;
    gettimeofday(&tv_end, NULL);
    time_taken = (tv_end.tv_sec - tv_start.tv_sec) + (tv_end.tv_usec - tv_start.tv_usec) / 1000000.0;
    printf("done (%.1fs)\n", time_taken);
}


/*
 * Functions to check firmware image against target hardware
 */

static bool has_prefix(const char *firmware_id, const char *prefix)
{
    size_t prefixlen = strlen(prefix);
    return (memcmp(firmware_id, prefix, prefixlen) == 0)
          && ((firmware_id[prefixlen] == '_') || (firmware_id[prefixlen] == 0));
}

static bool check_target_hardware(const char *firmware_id, exanic_hardware_id_t hw_id)
{
    bool ret;

    if (!firmware_id)
        firmware_id = "unknown";

    switch (hw_id)
    {
        case EXANIC_HW_X4:
            ret = has_prefix(firmware_id, "exanic_x4");
            break;
        case EXANIC_HW_X2:
            ret = has_prefix(firmware_id, "exanic_x2");
            break;
        case EXANIC_HW_X10:
            ret = has_prefix(firmware_id, "exanic_x10")
                    && !has_prefix(firmware_id, "exanic_x10_gm")
                    && !has_prefix(firmware_id, "exanic_x10_hpt");
            break;
        case EXANIC_HW_X10_GM:
            ret = has_prefix(firmware_id, "exanic_x10_gm");
            break;
        case EXANIC_HW_X10_HPT:
            ret = has_prefix(firmware_id, "exanic_x10_hpt");
            break;
        case EXANIC_HW_X40:
            ret = has_prefix(firmware_id, "exanic_x40");
            break;
        case EXANIC_HW_V5P:
            ret = has_prefix(firmware_id, "exanic_v5p");
            break;
        default:
            fprintf(stderr, "ERROR: card hardware unsupported by this software version\n");
            return false;
    }

    if (!ret)
        fprintf(stderr, "ERROR: firmware ID %s does not appear to match target hardware %s\n",
                        firmware_id, exanic_hardware_id_str(hw_id));
    return ret;
}


/*
 * exanic-fwupdate main function
 */

int main(int argc, char *argv[])
{
    const char *device = NULL;
    const char *filename = NULL;
    bool hot_reload = false;
    bool recovery_partition = false;
    bool verify_only = false;
    bool force = false;
    exanic_t *exanic = NULL;
    struct flash_device *flash = NULL;
    const char *firmware_id = NULL;
    flash_word_t *data;
    flash_size_t partition_size, data_size;
    int c, ret = 1;

    while ((c = getopt(argc, argv, "d:rRVfh?")) != -1)
    {
        switch (c)
        {
            case 'd':
                device = optarg;
                break;
            case 'r':
                hot_reload = true;
                break;
            case 'R':
                recovery_partition = true;
                break;
            case 'V':
                verify_only = true;
                break;
            case 'f':
                force = true;
                break;
            default:
                goto usage;
        }
    }

    if (argc > optind+1)
       goto usage;

    if (argc > optind)
       filename = argv[optind];

    if (!hot_reload && !filename)
        goto usage;

    if (recovery_partition && !verify_only && !force)
    {
        fprintf(stderr, "ERROR: -f (force) is required to program the recovery image portion of flash\n");
        return 1;
    }

    if (!device)
    {
        exanic = exanic_acquire_handle("exanic1");
        if (exanic)
        {
            exanic_release_handle(exanic);
            fprintf(stderr, "ERROR: multiple ExaNICs found, please specify which card to update (e.g. -d exanic0)\n");
            return 1;
        }
        device = "exanic0";
    }

    exanic = exanic_acquire_handle(device);
    if (!exanic)
    {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        return 1;
    }

    if (hot_reload && !check_can_hot_reload(exanic, false))
        goto error;

    if (filename)
    {
        report_phase("Querying target device");
        flash = flash_open(exanic, recovery_partition, &partition_size);
        if (!flash)
            goto error;
        report_phase_done();

        report_phase("Loading and checking update");
        data = read_firmware(filename, flash->partition_size,
                             &data_size, &firmware_id);
        if (!data)
            goto error;
        report_phase_done();

        if (!check_target_hardware(firmware_id, exanic_get_hw_type(exanic)))
            goto error;

        if (verify_only)
        {
            printf("WARNING: invoked with -V (verify only), not writing new firmware\n");
        }
        else
        {
            report_phase("Erasing");
            if (!flash_erase(flash, data_size, report_progress))
                goto error;
            report_phase_done();

            report_phase("Programming");
            if (!flash_program(flash, data, data_size, report_progress))
                goto error;
            report_phase_done();
        }

        report_phase("Verifying flash contents");
        if (!flash_verify(flash, data, data_size, report_progress))
            goto error;
        report_phase_done();

        flash_close(flash);
        flash = NULL;
    }

    if (hot_reload)
    {
        report_phase("Reloading card");
        exanic = reload_firmware(exanic, report_progress);
        if (!exanic)
            goto error;
        report_phase_done();
        printf("The new firmware will take effect immediately.\n");
    }
    else if (!verify_only)
    {
        printf("The new firmware will take effect after a system reboot");
        if (check_firmware_can_hot_reload(exanic, true))
            printf(", or you can load it now using exanic-fwupdate -r");
        printf(".\n");
    }

    ret = 0;
error:
    if (firmware_id)
        free((void *)firmware_id);
    if (flash)
        flash_close(flash);
    if (exanic)
        exanic_release_handle(exanic);
    return ret;

usage:
    printf("usage:\n"
              "  %s [-d device] [-r] exanic_XXX_YYYYYY.fw\n"
              "     - program, verify and optionally reload now (with -r)\n"
              "  %s [-d device] -V exanic_XXX_YYYYYY.fw\n"
              "     - verify only\n"
              "  %s [-d device] -r\n"
              "     - reload only\n", argv[0], argv[0], argv[0]);
    return 1;
}

