/*
 * flash_access_cfi.c: Functions to access CFI flash memory devices on ExaNIC cards
 *
 * Copyright (c) 2020-2022 by Cisco Systems, Inc.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <exanic/exanic.h>
#include <exanic/register.h>
#include "flash_access.h"

/* generic Common Flash Interface opcodes */
#define CFI_READ_ARRAY               0xFF
#define CFI_QUERY_ADDRESS            0x55
#define CFI_QUERY_DATA               0x98

/* Intel/P30 specific opcodes */
#define P30_SET_CR_SETUP             0x60
#define P30_SET_CR_CONFIRM           0x03
#define P30_CLEAR_STATUS_REG         0x50
#define P30_UNLOCK_BLOCK_SETUP       0x60
#define P30_UNLOCK_BLOCK_CONFIRM     0xD0
#define P30_BLOCK_ERASE_SETUP        0x20
#define P30_BLOCK_ERASE_CONFIRM      0xD0
#define P30_BUFFER_PROGRAM_SETUP     0xE8
#define P30_BUFFER_PROGRAM_CONFIRM   0xD0
/* Intel/P30 status register masks */
#define P30_STATUS_READY_MASK        0x80
#define P30_STATUS_ERROR_MASK        0x30
/* Value to program to P30 config register */
#define P30_CR_CONFIG                0x9803

/* AMD/MT28 specific opcodes */
#define MT28_UNLOCK_ADDRESS_1        0x555
#define MT28_UNLOCK_DATA_1           0xAA
#define MT28_UNLOCK_ADDRESS_2        0x2AA
#define MT28_UNLOCK_DATA_2           0x55
#define MT28_UNLOCK_BYPASS_ADDRESS   0x555
#define MT28_UNLOCK_BYPASS_DATA      0x20
#define MT28_UNLOCK_BYPASS_RESET     0x90
#define MT28_BLOCK_ERASE_SETUP       0x80
#define MT28_BLOCK_ERASE_CONFIRM     0x30
#define MT28_BUFFER_PROGRAM_SETUP    0x25
#define MT28_BUFFER_PROGRAM_CONFIRM  0x29
#define MT28_READ_ARRAY              0xF0
/* AMD/MT28 status register masks */
#define MT28_STATUS_TOGGLE_MASK      0x40
#define MT28_STATUS_ERASE_ERROR_MASK 0x20
#define MT28_STATUS_PROGRAM_ERROR_MASK 0x22

/**
 * Low-level ExaNIC flash access functions
 */

static void cfi_flash_init_interface(struct flash_device *flash)
{
    /* nWE high, nCE high, nOE high, nL high */
    exanic_register_write(flash->exanic, REG_HW_INDEX(REG_HW_FLASH_CTRL),
        EXANIC_FLASH_CTRL_nWE | EXANIC_FLASH_CTRL_nCE | EXANIC_FLASH_CTRL_nOE |
        EXANIC_FLASH_CTRL_nADV);
    /* dummy read for timing */
    exanic_register_read(flash->exanic, REG_HW_INDEX(REG_HW_FLASH_CTRL));
    /* nWE high, nCE low, nOE high, nL low */
    exanic_register_write(flash->exanic, REG_HW_INDEX(REG_HW_FLASH_CTRL),
        EXANIC_FLASH_CTRL_nWE | EXANIC_FLASH_CTRL_nOE);
}

static void cfi_flash_set_address(struct flash_device *flash, flash_address_t address)
{
    exanic_register_write(flash->exanic, REG_HW_INDEX(REG_HW_FLASH_ADDR), address);
}

static flash_word_t cfi_flash_read_current(struct flash_device *flash)
{
    flash_word_t data;
    /* nWE high, nCE low, nOE high, nL low, flash to FPGA */
    exanic_register_write(flash->exanic, REG_HW_INDEX(REG_HW_FLASH_CTRL),
        EXANIC_FLASH_CTRL_nWE | EXANIC_FLASH_CTRL_nOE);
    /* drive OE low */
    exanic_register_write(flash->exanic, REG_HW_INDEX(REG_HW_FLASH_CTRL),
        EXANIC_FLASH_CTRL_nWE);
    /* dummy read for timing */
    exanic_register_read(flash->exanic, REG_HW_INDEX(REG_HW_FLASH_DIN_CFI));
    data = exanic_register_read(flash->exanic, REG_HW_INDEX(REG_HW_FLASH_DIN_CFI));
    /* return OE high */
    exanic_register_write(flash->exanic, REG_HW_INDEX(REG_HW_FLASH_CTRL),
        EXANIC_FLASH_CTRL_nWE | EXANIC_FLASH_CTRL_nOE);
    return data;
}

static void cfi_flash_write_current(struct flash_device *flash, flash_word_t data)
{
    /* nWE high, nCE low, nOE high, nL low, FPGA to flash */
    exanic_register_write(flash->exanic, REG_HW_INDEX(REG_HW_FLASH_CTRL),
        EXANIC_FLASH_CTRL_nWE | EXANIC_FLASH_CTRL_nOE | EXANIC_FLASH_CTRL_BUS_DIR);
    exanic_register_write(flash->exanic, REG_HW_INDEX(REG_HW_FLASH_DOUT_CFI), data);
    /* drive WE low */
    exanic_register_write(flash->exanic, REG_HW_INDEX(REG_HW_FLASH_CTRL),
        EXANIC_FLASH_CTRL_nOE | EXANIC_FLASH_CTRL_BUS_DIR);
    /* dummy read for timing */
    exanic_register_read(flash->exanic, REG_HW_INDEX(REG_HW_FLASH_DIN_CFI));
    /* return WE high */
    exanic_register_write(flash->exanic, REG_HW_INDEX(REG_HW_FLASH_CTRL),
        EXANIC_FLASH_CTRL_nWE | EXANIC_FLASH_CTRL_nOE | EXANIC_FLASH_CTRL_BUS_DIR);
}

static flash_word_t cfi_flash_read(struct flash_device *flash, flash_address_t address)
{
    cfi_flash_set_address(flash, address);
    return cfi_flash_read_current(flash);
}

static void cfi_flash_write(struct flash_device *flash, flash_address_t address,
        flash_word_t data)
{
    cfi_flash_set_address(flash, address);
    cfi_flash_write_current(flash, data);
}

static bool cfi_flash_read_multiple(struct flash_device *flash, flash_address_t address,
            flash_word_t *data, flash_size_t size)
{
    flash_address_t curr_addr = address;
    flash_size_t i = 0;
    flash_word_t *ptr = data;

    cfi_flash_write(flash, 0, CFI_READ_ARRAY);
    for (; i < size; i++)
        *ptr++ = cfi_flash_read(flash, curr_addr++);

    return true;
}

static void cfi_flash_release_interface(struct flash_device *flash)
{
    /* nWE high, nCE high, nOE high, nL high */
    exanic_register_write(flash->exanic, REG_HW_INDEX(REG_HW_FLASH_CTRL),
        EXANIC_FLASH_CTRL_nWE | EXANIC_FLASH_CTRL_nCE | EXANIC_FLASH_CTRL_nOE |
        EXANIC_FLASH_CTRL_nADV);
}

/**
 * P30 flash family specific functions
 */

static void p30_set_asynchronous_mode(struct flash_device *flash)
{
    cfi_flash_write(flash, P30_CR_CONFIG, P30_SET_CR_SETUP);
    cfi_flash_write(flash, P30_CR_CONFIG, P30_SET_CR_CONFIRM);
}

static bool p30_init(struct flash_device *flash)
{
    cfi_flash_write(flash, 0, P30_CLEAR_STATUS_REG);
    return true;
}

static void p30_release(struct flash_device *flash)
{
    cfi_flash_release_interface(flash);
}

static bool p30_check_status(struct flash_device *flash)
{
    do {
        flash->status = cfi_flash_read_current(flash);
    } while (!(flash->status & P30_STATUS_READY_MASK));
    return !(flash->status & P30_STATUS_ERROR_MASK);
}

static bool p30_block_operation(struct flash_device *flash,
                                flash_word_t command_code, flash_word_t confirm_code)
{
    cfi_flash_write_current(flash, command_code);
    cfi_flash_write_current(flash, confirm_code);
    return p30_check_status(flash);
}

static bool p30_erase_block(struct flash_device *flash, flash_address_t address)
{
    cfi_flash_set_address(flash, address);
    if (!p30_block_operation(flash, P30_UNLOCK_BLOCK_SETUP, P30_UNLOCK_BLOCK_CONFIRM))
    {
        fprintf(stderr, "ERROR: failed to unlock block at 0x%x (sr=0x%x)\n",
                address, flash->status);
        return false;
    }
    if (!p30_block_operation(flash, P30_BLOCK_ERASE_SETUP, P30_BLOCK_ERASE_CONFIRM))
    {
        fprintf(stderr, "ERROR: failed to erase block at 0x%x (sr=0x%x)\n",
                address, flash->status);
        return false;
    }
    return true;
}

static bool p30_burst_program(struct flash_device *flash, flash_address_t address,
        flash_word_t *data, flash_size_t size)
{
    flash_size_t offset;

    cfi_flash_set_address(flash, address);
    cfi_flash_write_current(flash, P30_BUFFER_PROGRAM_SETUP);
    cfi_flash_write_current(flash, size-1);
    cfi_flash_write_current(flash, data[0]);
    for (offset = 1; offset < size; offset++)
        cfi_flash_write(flash, address+offset, data[offset]);
    cfi_flash_write(flash, address, P30_BUFFER_PROGRAM_CONFIRM);
    if (!p30_check_status(flash))
    {
        fprintf(stderr, "ERROR: failed to program block at 0x%x (sr=0x%x)\n",
                address, flash->status);
        return false;
    }
    return true;
}

static struct flash_ops p30_ops = {
    init:          p30_init,
    erase_block:   p30_erase_block,
    burst_program: p30_burst_program,
    read:          cfi_flash_read_multiple,
    release:       p30_release
};

/**
 * MT28 flash family specific functions
 */

static bool mt28_init(struct flash_device *flash)
{
    /* clear status register */
    cfi_flash_write(flash, MT28_UNLOCK_ADDRESS_1, MT28_UNLOCK_DATA_1);
    cfi_flash_write(flash, MT28_UNLOCK_ADDRESS_2, MT28_UNLOCK_DATA_2);
    cfi_flash_write(flash, 0, MT28_READ_ARRAY);

    if (flash->supports_unlock_bypass)
    {
        /* enter unlock bypass mode */
        cfi_flash_write(flash, MT28_UNLOCK_ADDRESS_1, MT28_UNLOCK_DATA_1);
        cfi_flash_write(flash, MT28_UNLOCK_ADDRESS_2, MT28_UNLOCK_DATA_2);
        cfi_flash_write(flash, MT28_UNLOCK_BYPASS_ADDRESS, MT28_UNLOCK_BYPASS_DATA);
    }
    return true;
}

static void mt28_release(struct flash_device *flash)
{
    /* exit unlock bypass mode */
    cfi_flash_write(flash, 0, MT28_UNLOCK_BYPASS_RESET);
    cfi_flash_write(flash, 0, MT28_READ_ARRAY);
    cfi_flash_release_interface(flash);
}

static bool mt28_check_status(struct flash_device *flash, flash_word_t error_mask)
{
    flash_word_t status = cfi_flash_read_current(flash);
    flash_word_t tmp_status1, tmp_status2;
    while (1)
    {
        tmp_status1 = cfi_flash_read_current(flash);
        /* there is a toggle bit in the status register which toggles on each read */
        /* no change in value indicates we have returned to array read (=success) */
        if (tmp_status1 == status)
            return true;

        /* check again if the operation has finished; this avoids a race condition on */
        /* S29GLxxxP flash chips where 'status' could have been a corrupt array read */
        /* if the operation had just finished */
        tmp_status2 = cfi_flash_read_current(flash);
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
    if (flash->supports_unlock_bypass)
    {
        cfi_flash_set_address(flash, address);
        cfi_flash_write_current(flash, MT28_BLOCK_ERASE_SETUP);
    }
    else
    {
        cfi_flash_write(flash, MT28_UNLOCK_ADDRESS_1, MT28_UNLOCK_DATA_1);
        cfi_flash_write(flash, MT28_UNLOCK_ADDRESS_2, MT28_UNLOCK_DATA_2);
        cfi_flash_write(flash, MT28_UNLOCK_ADDRESS_1, MT28_BLOCK_ERASE_SETUP);
        cfi_flash_write(flash, MT28_UNLOCK_ADDRESS_1, MT28_UNLOCK_DATA_1);
        cfi_flash_write(flash, MT28_UNLOCK_ADDRESS_2, MT28_UNLOCK_DATA_2);
        cfi_flash_set_address(flash, address);
    }

    cfi_flash_write_current(flash, MT28_BLOCK_ERASE_CONFIRM);
    if (!mt28_check_status(flash, MT28_STATUS_ERASE_ERROR_MASK))
    {
        fprintf(stderr, "ERROR: failed to erase block at 0x%x (sr=0x%x)\n",
                address, flash->status);
        return false;
    }
    return true;
}

static bool mt28_burst_program(struct flash_device *flash, flash_address_t address,
        flash_word_t *data, flash_size_t size)
{
    flash_size_t offset;

    if (!flash->supports_unlock_bypass)
    {
        cfi_flash_write(flash, MT28_UNLOCK_ADDRESS_1, MT28_UNLOCK_DATA_1);
        cfi_flash_write(flash, MT28_UNLOCK_ADDRESS_2, MT28_UNLOCK_DATA_2);
    }

    cfi_flash_set_address(flash, address);
    cfi_flash_write_current(flash, MT28_BUFFER_PROGRAM_SETUP);
    cfi_flash_write_current(flash, size-1);
    cfi_flash_write_current(flash, data[0]);
    for (offset = 1; offset < size; offset++)
        cfi_flash_write(flash, address+offset, data[offset]);
    cfi_flash_write(flash, address, MT28_BUFFER_PROGRAM_CONFIRM);
    if (!mt28_check_status(flash, MT28_STATUS_PROGRAM_ERROR_MASK))
    {
        fprintf(stderr, "ERROR: failed to program block at 0x%x (sr=0x%x)\n",
                address, flash->status);
        return false;
    }
    return true;
}

static struct flash_ops mt28_ops = {
    init:          mt28_init,
    erase_block:   mt28_erase_block,
    burst_program: mt28_burst_program,
    read:          cfi_flash_read_multiple,
    release:       mt28_release
};


/**
 * Generic flash access functions
 */

struct flash_device *flash_open_cfi(exanic_t *exanic, bool recovery_partition,
        flash_size_t *partition_size)
{
    struct flash_device *flash;
    uint16_t command_set, burst_buffer_size_bits;
    uint8_t device_size_bits;
    flash_size_t block_size_1, block_size_2, block_size_3, device_size,
                 num_blocks_1, num_blocks_2, num_blocks_3, device_end;

    flash = calloc(1, sizeof(struct flash_device));
    if (!flash)
    {
        fprintf(stderr, "ERROR: memory allocation failed\n");
        return NULL;
    }

    flash->exanic = exanic;
    cfi_flash_init_interface(flash);
    cfi_flash_write(flash, CFI_QUERY_ADDRESS, CFI_QUERY_DATA);
    if (cfi_flash_read(flash, 0x10) != 'Q')
    {
        /* Flash may be in synchronous read mode */
        p30_set_asynchronous_mode(flash);
        cfi_flash_init_interface(flash);
        cfi_flash_write(flash, CFI_QUERY_ADDRESS, CFI_QUERY_DATA);
    }
    if (cfi_flash_read(flash, 0x10) != 'Q' ||
        cfi_flash_read(flash, 0x11) != 'R' ||
        cfi_flash_read(flash, 0x12) != 'Y')
    {
        fprintf(stderr, "ERROR: failed to query flash\n");
        goto error;
    }

    command_set = (cfi_flash_read(flash, 0x14) << 8) | (cfi_flash_read(flash, 0x13));
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

    device_size_bits = cfi_flash_read(flash, 0x27);
    if (device_size_bits < 24)
    {
        fprintf(stderr, "ERROR: unexpected flash device size (bits=%u)\n", device_size_bits);
        goto error;
    }

    flash->device_size = device_size = 1 << (device_size_bits-1);
    flash->partition_size = *partition_size = device_size / 2;
    flash->partition_start = recovery_partition ? 0 : flash->partition_size;
    flash->is_recovery = recovery_partition;

    burst_buffer_size_bits = (cfi_flash_read(flash, 0x2b) << 8) | (cfi_flash_read(flash, 0x2a));
    if ((burst_buffer_size_bits < 2) || (burst_buffer_size_bits > device_size_bits))
    {
        fprintf(stderr, "ERROR: unexpected burst buffer size (bits=%u)\n", burst_buffer_size_bits);
        goto error;
    }
    flash->burst_buffer_size = 1 << (burst_buffer_size_bits-1);

    block_size_1 = ((cfi_flash_read(flash, 0x30) << 8) | (cfi_flash_read(flash, 0x2f))) * 256 / 2;
    num_blocks_1 = ((cfi_flash_read(flash, 0x2e) << 8) | (cfi_flash_read(flash, 0x2d))) + 1;
    block_size_2 = ((cfi_flash_read(flash, 0x34) << 8) | (cfi_flash_read(flash, 0x33))) * 256 / 2;
    num_blocks_2 = ((cfi_flash_read(flash, 0x32) << 8) | (cfi_flash_read(flash, 0x31))) + 1;
    block_size_3 = ((cfi_flash_read(flash, 0x38) << 8) | (cfi_flash_read(flash, 0x37))) * 256 / 2;
    num_blocks_3 = ((cfi_flash_read(flash, 0x36) << 8) | (cfi_flash_read(flash, 0x35))) + 1;

    flash->region_1_block_size = block_size_1;
    flash->region_2_start = num_blocks_1 * block_size_1;
    flash->region_2_block_size = block_size_2;
    flash->region_3_start = flash->region_2_start + num_blocks_2 * block_size_2;
    flash->region_3_block_size = block_size_3;
    device_end = flash->region_3_start + num_blocks_3 * block_size_3;
    if (device_end != device_size)
    {
        fprintf(stderr, "ERROR: unexpected flash layout (%ux%u + %ux%u + %ux%u != %u)\n",
                        num_blocks_1, block_size_1, num_blocks_2, block_size_2,
                        num_blocks_3, block_size_3, device_size);
        goto error;
    }

    flash->main_block_size = (block_size_2 > block_size_1) ? block_size_2 : block_size_1;
    flash->min_read_size = 1;
    /* FPGA bitstreams should be bit-reversed when writing to parallel flash */
    flash->bit_reverse_bitstream = true;
    flash->supports_unlock_bypass = (cfi_flash_read(flash, 0x51) != 0);

    return flash;

error:
    cfi_flash_release_interface(flash);
    free(flash);
    return NULL;
}
