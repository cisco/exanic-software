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
#include <exanic/hw_info.h>
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

static bool check_target_hardware(const char *firmware_id, exanic_t *exanic)
{
    bool found_match = false;
    unsigned longest_prefix = 0;
    int intended_hw_id = -1;
    int i;
    exanic_hardware_id_t device_hw_id = exanic_get_hw_type(exanic);

    /* iterate the device table and find the device whose expected
     * bitstream prefix and the firmware ID read from file produce
     * the best match
     * in this way, a bitstream starting with "exanic_x10_special"
     * will pass the check for X10, but "exanic_x10_gm" will not */
    for (i = 0; i < EXANIC_HW_TABLE_SIZE; i++)
    {
        const struct exanic_hw_info *hwinfo = &exanic_hw_products[i];
        if (hwinfo->bitstream_prf == NULL)
            continue;

        unsigned prflen = strlen(hwinfo->bitstream_prf);
        if (strncmp(firmware_id, hwinfo->bitstream_prf, prflen))
            continue;

        if (firmware_id[prflen] && firmware_id[prflen] != '_')
            continue;

        found_match = true;
        if (prflen > longest_prefix)
        {
            longest_prefix = prflen;
            intended_hw_id = hwinfo->hwid;
        }
    }

    if (!found_match)
    {
        fprintf(stderr, "ERROR: card hardware unsupported by this software version\n");
        return false;
    }

    if (intended_hw_id != (int)device_hw_id)
    {
        fprintf(stderr, "ERROR: firmware ID %s does not appear to match target hardware %s\n",
                        firmware_id, exanic_hardware_id_str(device_hw_id));
        return false;
    }

    return true;
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

        if (!check_target_hardware(firmware_id, exanic))
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

