/*
 * flash_access.c: Functions to access flash memory devices on ExaNIC cards
 *
 * Copyright (C) 2017 Exablaze Pty Ltd
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h> /* for MIN/MAX */
#include <exanic/exanic.h>
#include <exanic/register.h>
#include "flash_access.h"
#include "flash_opcodes.h"

/**
 * Low-level ExaNIC flash access functions
 */

#define EXANIC_FLASH_ADDR_REG  (0x4F)
#define EXANIC_FLASH_DIN_REG   (0x52)
#define EXANIC_FLASH_DOUT_REG  (0x50)
#define EXANIC_FLASH_CTRL_REG  (0x51)

static void flash_init_interface(struct flash_device *flash)
{
    /* nWE high, nCE high, nOE high, nL high */
    exanic_register_write(flash->exanic, EXANIC_FLASH_CTRL_REG, 0xf);
    /* dummy read for timing */
    exanic_register_read(flash->exanic, EXANIC_FLASH_CTRL_REG);
    /* nWE high, nCE low, nOE high, nL low */
    exanic_register_write(flash->exanic, EXANIC_FLASH_CTRL_REG, 0x5);
}

static void flash_set_address(struct flash_device *flash, flash_address_t address)
{
    exanic_register_write(flash->exanic, EXANIC_FLASH_ADDR_REG, address);
}

static flash_word_t flash_read_current(struct flash_device *flash)
{
    flash_word_t data;
    /* nWE high, nCE low, nOE high, nL low, flash to FPGA */
    exanic_register_write(flash->exanic, EXANIC_FLASH_CTRL_REG, 0x5);
    /* drive OE low */
    exanic_register_write(flash->exanic, EXANIC_FLASH_CTRL_REG, 0x1);
    /* dummy read for timing */
    exanic_register_read(flash->exanic, EXANIC_FLASH_DIN_REG);
    data = exanic_register_read(flash->exanic, EXANIC_FLASH_DIN_REG);
    /* return OE high */
    exanic_register_write(flash->exanic, EXANIC_FLASH_CTRL_REG, 0x5);
    return data;
}

static void flash_write_current(struct flash_device *flash, flash_word_t data)
{
    /* nWE high, nCE low, nOE high, nL low, FPGA to flash */
    exanic_register_write(flash->exanic, EXANIC_FLASH_CTRL_REG, 0x15);
    exanic_register_write(flash->exanic, EXANIC_FLASH_DOUT_REG, data);
    /* drive WE low */
    exanic_register_write(flash->exanic, EXANIC_FLASH_CTRL_REG, 0x14);
    /* dummy read for timing */
    exanic_register_read(flash->exanic, EXANIC_FLASH_DIN_REG);
    /* return WE high */
    exanic_register_write(flash->exanic, EXANIC_FLASH_CTRL_REG, 0x15);
}

static flash_word_t flash_read(struct flash_device *flash, flash_address_t address)
{
    flash_set_address(flash, address);
    return flash_read_current(flash);
}

static void flash_write(struct flash_device *flash, flash_address_t address, flash_word_t data)
{
    flash_set_address(flash, address);
    flash_write_current(flash, data);
}

static void flash_release_interface(struct flash_device *flash)
{
    /* nWE high, nCE high, nOE high, nL high */
    exanic_register_write(flash->exanic, EXANIC_FLASH_CTRL_REG, 0xf);
}


/**
 * P30 flash family specific functions
 */

static void p30_set_asynchronous_mode(struct flash_device *flash)
{
    flash_write(flash, P30_CR_CONFIG, P30_SET_CR_SETUP);
    flash_write(flash, P30_CR_CONFIG, P30_SET_CR_CONFIRM);
}

static void p30_init(struct flash_device *flash)
{
    flash_write(flash, 0, P30_CLEAR_STATUS_REG);
}

static void p30_release(struct flash_device *flash)
{
}

static bool p30_check_status(struct flash_device *flash)
{
    do {
        flash->status = flash_read_current(flash);
    } while (!(flash->status & P30_STATUS_READY_MASK));
    return !(flash->status & P30_STATUS_ERROR_MASK);
}

static bool p30_block_operation(struct flash_device *flash,
                                flash_word_t command_code, flash_word_t confirm_code)
{
    flash_write_current(flash, command_code);
    flash_write_current(flash, confirm_code);
    return p30_check_status(flash);
}

static bool p30_erase_block(struct flash_device *flash, flash_address_t address)
{
    flash_set_address(flash, address);
    if (!p30_block_operation(flash, P30_UNLOCK_BLOCK_SETUP, P30_UNLOCK_BLOCK_CONFIRM))
    {
        fprintf(stderr, "ERROR: failed to unlock block at 0x%x (sr=0x%x)\n", address, flash->status);
        return false;
    }
    if (!p30_block_operation(flash, P30_BLOCK_ERASE_SETUP, P30_BLOCK_ERASE_CONFIRM))
    {
        fprintf(stderr, "ERROR: failed to erase block at 0x%x (sr=0x%x)\n", address, flash->status);
        return false;
    }
    return true;
}

static bool p30_burst_program(struct flash_device *flash, flash_address_t address, flash_word_t *data, flash_size_t size)
{
    flash_size_t offset;

    flash_set_address(flash, address);
    flash_write_current(flash, P30_BUFFER_PROGRAM_SETUP);
    flash_write_current(flash, size-1);
    flash_write_current(flash, data[0]);
    for (offset = 1; offset < size; offset++)
        flash_write(flash, address+offset, data[offset]);
    flash_write(flash, address, P30_BUFFER_PROGRAM_CONFIRM);
    if (!p30_check_status(flash))
    {
        fprintf(stderr, "ERROR: failed to program block at 0x%x (sr=0x%x)\n", address, flash->status);
        return false;
    }
    return true;
}

static struct flash_ops p30_ops = {
    init:          p30_init,
    erase_block:   p30_erase_block,
    burst_program: p30_burst_program,
    release:       p30_release
};


/**
 * MT28 flash family specific functions
 */

static void mt28_init(struct flash_device *flash)
{
    /* clear status register */
    flash_write(flash, MT28_UNLOCK_ADDRESS_1, MT28_UNLOCK_DATA_1);
    flash_write(flash, MT28_UNLOCK_ADDRESS_2, MT28_UNLOCK_DATA_2);
    flash_write(flash, 0, MT28_READ_ARRAY);

    /* enter unlock bypass mode */
    flash_write(flash, MT28_UNLOCK_ADDRESS_1, MT28_UNLOCK_DATA_1);
    flash_write(flash, MT28_UNLOCK_ADDRESS_2, MT28_UNLOCK_DATA_2);
    flash_write(flash, MT28_UNLOCK_BYPASS_ADDRESS, MT28_UNLOCK_BYPASS_DATA);
}

static void mt28_release(struct flash_device *flash)
{
    /* exit unlock bypass mode */
    flash_write(flash, 0, MT28_UNLOCK_BYPASS_RESET);
    flash_write(flash, 0, MT28_READ_ARRAY);
}

static bool mt28_check_status(struct flash_device *flash, flash_word_t error_mask)
{
    flash_word_t status = flash_read_current(flash);
    flash_word_t tmp_status1, tmp_status2;
    while (1)
    {
        tmp_status1 = flash_read_current(flash);
        /* there is a toggle bit in the status register which toggles on each read */
        /* no change in value indicates we have returned to array read (=success) */
        if (tmp_status1 == status)
            return true;

        /* check again if the operation has finished; this avoids a race condition on */
        /* S29GLxxxP flash chips where 'status' could have been a corrupt array read */
        /* if the operation had just finished */
        tmp_status2 = flash_read_current(flash);
        if (tmp_status2 == tmp_status1)
            return true;

        if (status & error_mask)
        {
            flash->status = status;
            return false;
        }

        status = tmp_status2;
    }
}

static bool mt28_erase_block(struct flash_device *flash, flash_address_t address)
{
    flash_set_address(flash, address);
    flash_write_current(flash, MT28_BLOCK_ERASE_SETUP);
    flash_write_current(flash, MT28_BLOCK_ERASE_CONFIRM);
    if (!mt28_check_status(flash, MT28_STATUS_ERASE_ERROR_MASK))
    {
        fprintf(stderr, "ERROR: failed to erase block at 0x%x (sr=0x%x)\n", address, flash->status);
        return false;
    }
    return true;
}

static bool mt28_burst_program(struct flash_device *flash, flash_address_t address, flash_word_t *data, flash_size_t size)
{
    flash_size_t offset;

    flash_set_address(flash, address);
    flash_write_current(flash, MT28_BUFFER_PROGRAM_SETUP);
    flash_write_current(flash, size-1);
    flash_write_current(flash, data[0]);
    for (offset = 1; offset < size; offset++)
        flash_write(flash, address+offset, data[offset]);
    flash_write(flash, address, MT28_BUFFER_PROGRAM_CONFIRM);
    if (!mt28_check_status(flash, MT28_STATUS_PROGRAM_ERROR_MASK))
    {
        fprintf(stderr, "ERROR: failed to program block at 0x%x (sr=0x%x)\n", address, flash->status);
        return false;
    }
    return true;
}

static struct flash_ops mt28_ops = {
    init:          mt28_init,
    erase_block:   mt28_erase_block,
    burst_program: mt28_burst_program,
    release:       mt28_release
};


/**
 * Generic flash access functions
 */

struct flash_device *flash_open(exanic_t *exanic, bool recovery_partition, flash_size_t *partition_size)
{
    struct flash_device *flash;
    uint16_t command_set, burst_buffer_size, block_size_b, block_size_t;
    uint8_t device_size;

    flash = calloc(1, sizeof(struct flash_device));
    if (!flash)
    {
        fprintf(stderr, "ERROR: memory allocation failed\n");
        return NULL;
    }

    flash->exanic = exanic;
    flash_init_interface(flash);
    flash_write(flash, CFI_QUERY_ADDRESS, CFI_QUERY_DATA);
    if (flash_read(flash, 0x10) != 'Q')
    {
        /* Flash may be in synchronous read mode */
        p30_set_asynchronous_mode(flash);
        flash_init_interface(flash);
        flash_write(flash, CFI_QUERY_ADDRESS, CFI_QUERY_DATA);
    }
    if (flash_read(flash, 0x10) != 'Q' || flash_read(flash, 0x11) != 'R' || flash_read(flash, 0x12) != 'Y')
    {
        fprintf(stderr, "ERROR: failed to query flash\n");
        goto error;
    }

    command_set = (flash_read(flash, 0x14) << 8) | (flash_read(flash, 0x13));
    switch (command_set)
    {
        case 1: /* Intel */
            flash->ops = &p30_ops;
            break;
        case 2: /* AMD */
            flash->ops = &mt28_ops;
            break;
        default:
            fprintf(stderr, "ERROR: unknown flash command set 0x%x\n", command_set);
            goto error;
    }

    device_size = flash_read(flash, 0x27);
    if (device_size < 24)
    {
        fprintf(stderr, "ERROR: unexpected flash device size (bits=%u)\n", device_size);
        goto error;
    }

    flash->partition_size = *partition_size = 1 << (device_size-2);
    flash->partition_start = recovery_partition ? 0 : flash->partition_size;

    burst_buffer_size = (flash_read(flash, 0x2b) << 8) | (flash_read(flash, 0x2a));
    if ((burst_buffer_size < 2) || (burst_buffer_size > device_size))
    {
        fprintf(stderr, "ERROR: unexpected burst buffer size (bits=%u)\n", burst_buffer_size);
        goto error;
    }
    flash->burst_buffer_size = 1 << (burst_buffer_size-1);

    block_size_b = (flash_read(flash, 0x30) << 8) | (flash_read(flash, 0x2f));
    block_size_t = (flash_read(flash, 0x34) << 8) | (flash_read(flash, 0x33));
    if ((block_size_b < block_size_t) || (block_size_b < 1))
    {
        fprintf(stderr, "ERROR: flash organization not currently supported\n");
        goto error;
    }
    flash->block_size = block_size_b * 256 / 2;

    flash->ops->init(flash);
    return flash;

error:
    flash_release_interface(flash);
    free(flash);
    return NULL;
}

bool flash_erase(struct flash_device *flash, flash_size_t size, void (*report_progress)())
{
    flash_address_t offset, address;

    /* round size up to a multiple of block size */
    if (size % flash->block_size != 0)
        size += flash->block_size - size % flash->block_size;

    for (offset = 0; offset < size; offset += flash->block_size)
    {
        address = flash->partition_start + offset;
        if (!flash->ops->erase_block(flash, address))
            return false; 
        report_progress();
    }
    return true;
}

bool flash_program(struct flash_device *flash, flash_word_t *data, flash_size_t size, void (*report_progress)())
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

bool flash_verify(struct flash_device *flash, flash_word_t *data, flash_size_t size, void (*report_progress)())
{
    flash_address_t offset, address;
    flash_word_t readback_data;

    flash_write(flash, 0, CFI_READ_ARRAY);
    for (offset = 0; offset < size; offset++)
    {
        address = flash->partition_start + offset;
        readback_data = flash_read(flash, address);
        if (readback_data != data[offset])
        {
            fprintf(stderr, "ERROR: verify failed at address 0x%x (expected 0x%x, read 0x%x)\n",
                                                          address, data[offset], readback_data);
            return false;
        }
        if ((offset & (flash->block_size-1)) == 0)
            report_progress();
    }
    return true; 
}

void flash_close(struct flash_device *flash)
{
    flash->ops->release(flash);
    flash_release_interface(flash);
    free(flash);
}

