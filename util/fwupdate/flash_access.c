/*
 * flash_access_cfi.c: Functions to access CFI flash memory devices on ExaNIC cards
 *
 * Copyright (C) 2020 Exablaze Pty Ltd
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h> /* for MIN/MAX */
#include <exanic/exanic.h>
#include <exanic/register.h>
#include <exanic/hw_info.h>
#include "flash_access.h"
#include "flash_access_cfi.h"
#include "flash_access_qspi.h"

struct flash_device *flash_open(exanic_t *exanic, bool recovery_partition,
        flash_size_t *partition_size)
{
    const struct exanic_fw_flash_info *info = exanic->hw_info.flash_info;
    struct flash_device *flash = info->type == EXANIC_FW_FLASH_QSPI ?
        flash_open_qspi(exanic, recovery_partition, partition_size) :
        flash_open_cfi(exanic, recovery_partition, partition_size);
    if (flash->ops->init && !flash->ops->init(flash))
    {
        flash_close(flash);
        return NULL;
    }
    return flash;
}

bool flash_erase(struct flash_device *flash, flash_size_t size, void (*report_progress)())
{
    flash_address_t address = flash->partition_start;
    flash_address_t erase_end = address + size;

    while (address < erase_end)
    {
        if (!flash->ops->erase_block(flash, address))
            return false;
        report_progress();

        flash_size_t erase_size = (address >= flash->boot_area_start) ?
            flash->boot_area_block_size : flash->block_size;
        address += erase_size;
    }
    return true;
}

bool flash_program(struct flash_device *flash, flash_word_t *data, flash_size_t size,
        void (*report_progress)())
{
    flash_address_t offset, address;
    flash_size_t burst_size;

    for (offset = 0; offset < size; offset += flash->burst_buffer_size)
    {
        address = flash->partition_start + offset;
        burst_size = MIN(flash->burst_buffer_size, size-offset);
        if (!flash->ops->burst_program(flash, address, &data[offset], burst_size))
            return false;
        if ((offset & (flash->block_size-1)) == 0)
            report_progress();
    }
    return true;
}

bool flash_verify(struct flash_device *flash, flash_word_t *data, flash_size_t size,
        void (*report_progress)())
{
    flash_address_t curr_addr = flash->partition_start;
    flash_size_t words_left = size;
    const flash_word_t *ptr = data;
    /* make sure that both the buffer address and the device address given to
     * the read function is aligned to the device minimum read size */
    flash_word_t buffer[256] __attribute__ ((aligned));
    size_t buffer_size = sizeof(buffer) / sizeof(buffer[0]);
    size_t buffer_capacity = (buffer_size & (~(flash->min_read_size - 1)));

    flash_size_t words_unreported = 0;
    while (words_left)
    {
        flash_size_t to_read = MIN(words_left, buffer_capacity);
        flash_size_t i = 0;

        if (!flash->ops->read(flash, curr_addr, buffer, to_read))
        {
            fprintf(stderr, "ERROR: read failed at address 0x%x\n",
                            curr_addr);
            return false;
        }

        for (; i < to_read; i++)
        {
            if (buffer[i] != ptr[i])
            {
                fprintf(stderr,
                        "ERROR: verify failed at address 0x%x (expected 0x%x, read 0x%x)\n",
                        curr_addr + i, ptr[i], buffer[i]);
                return false;
            }
        }

        words_unreported += to_read;
        if (words_unreported >= flash->block_size)
        {
            report_progress();
            words_unreported = 0;
        }

        curr_addr += to_read;
        ptr += to_read;
        words_left -= to_read;
    }
    return true;
}

void flash_close(struct flash_device *flash)
{
    if (flash->ops->release)
        flash->ops->release(flash);
    free(flash);
}
