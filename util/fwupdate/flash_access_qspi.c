/*
 * flash_access_qspi.c: Functions to access QSPI flash memory devices on ExaNIC cards
 *
 * Copyright (C) 2020 Exablaze Pty Ltd
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <exanic/exanic.h>
#include <exanic/register.h>
#include "flash_access.h"

#define TIMEOUT_US 100000

/* the QSPI bus itself is not 32-bit wide but the QSPI acceleration logic in
 * the FPGA accepts 4 bytes at a time */
typedef uint32_t qspi_flash_word_t;

/* convert to byte offsets and lengths */
static inline size_t to_byte_address(flash_address_t address)
{
    return address * BYTES_IN_FLASH_WORDS;
}

static inline size_t to_byte_size(flash_size_t word_size)
{
    return word_size * BYTES_IN_FLASH_WORDS;
}

/* whether the address in bytes is aligned to 32-bit boundary */
static inline bool byte_address_dword_aligned(size_t address)
{
    return (address % sizeof(qspi_flash_word_t)) == 0;
}

/* Logic for interpreting the status register content returned to the host from
 * the FPGA. */

static bool qspi_busy(uint32_t status_register)
{
    return (status_register & 0x80800000) != 0x80800000;
}

enum qspi_error_bits
{
    QSPI_ERR_PROT  = 1,
    QSPI_ERR_WRITE = 4,
    QSPI_ERR_ERASE = 5
};

static uint8_t qspi_error_status(uint32_t status_register)
{
    uint8_t flash0 = status_register >> 24,
            flash1 = status_register >> 16;
    uint8_t ret = 0;
#define CHECK_BIT(ret, reg0, reg1, bit)             \
    if ((reg0 & (1 << bit)) || (reg1 & (1 << bit))) \
        ret |= (1 << bit);
    CHECK_BIT(ret, flash0, flash1, QSPI_ERR_PROT);
    CHECK_BIT(ret, flash0, flash1, QSPI_ERR_WRITE);
    CHECK_BIT(ret, flash0, flash1, QSPI_ERR_ERASE);
    return ret;
}

static void qspi_print_error(const char *op, uint32_t status_register, uint8_t err)
{
    fprintf(stderr, "ERROR: error during %s operation!", op);
    fprintf(stderr, "  Status register content 0x%08x\n", status_register);
    if (err & (1 << QSPI_ERR_WRITE))
        fprintf(stderr, "    Write failure status is active\n");
    if (err & (1 << QSPI_ERR_ERASE))
        fprintf(stderr, "    Erase failure status is active\n");
    if (err & (1 << QSPI_ERR_PROT))
        fprintf(stderr, "    Attempting to modify protected sectors\n");
};

/* wait for busy flag to clear */
static bool qspi_wait_ready(struct flash_device *flash)
{
    struct timeval then, now, elapsed;
    gettimeofday(&then, NULL);

    while (true)
    {
        exanic_register_write(flash->exanic,
                REG_HW_INDEX(REG_HW_FLASH_QSPI_OPCODE),
                EXANIC_FLASH_QSPI_OPCODE_RDSR);
        flash->status = exanic_register_read(flash->exanic,
                REG_HW_INDEX(REG_HW_FLASH_QSPI_SR));
        if (!qspi_busy(flash->status))
            break;

        gettimeofday(&now, NULL);
        timersub(&now, &then, &elapsed);
        unsigned long usecs = 1000000 * elapsed.tv_sec + elapsed.tv_usec;
        if (usecs > TIMEOUT_US)
            return false;
    }

    return true;
}

/* flash_ops interface implementation */

static bool qspi_init(struct flash_device *flash)
{
    /* enter QSPI mode */
    exanic_register_write(flash->exanic,
            REG_HW_INDEX(REG_HW_FLASH_QSPI_OPCODE),
            EXANIC_FLASH_QSPI_QUAD_ENABLE);

    /* wait for any previous operation to finish running */
    if (!qspi_wait_ready(flash))
    {
        fprintf(stderr, "ERROR: timeout during initialization!\n");
        return false;
    }
    return true;
}

static void qspi_release(struct flash_device *flash)
{
    /* exit QSPI mode */
    exanic_register_write(flash->exanic,
            REG_HW_INDEX(REG_HW_FLASH_QSPI_OPCODE),
            EXANIC_FLASH_QSPI_QUAD_DISABLE);
}

static bool qspi_erase_block(struct flash_device *flash, flash_address_t address)
{
    size_t byte_addr = to_byte_address(address);
    size_t block_size_byte = to_byte_size(flash->block_size);
    byte_addr &= (~(block_size_byte - 1));

    exanic_register_write(flash->exanic,
            REG_HW_INDEX(REG_HW_FLASH_ADDR), byte_addr);
    exanic_register_write(flash->exanic,
            REG_HW_INDEX(REG_HW_FLASH_QSPI_OPCODE),
            EXANIC_FLASH_QSPI_OPCODE_ERASE);

    if (!qspi_wait_ready(flash))
    {
        fprintf(stderr, "ERROR: timeout during erase at offset 0x%x!\n", address);
        return false;
    }

    uint8_t err;
    if ((err = qspi_error_status(flash->status)))
    {
        qspi_print_error("erase", flash->status, err);
        return false;
    }

    return true;
}

static bool qspi_burst_program(struct flash_device *flash, flash_address_t address,
        flash_word_t *data, flash_size_t size)
{
    size_t byte_addr = to_byte_address(address),
           byte_size = to_byte_size(size);

    if (!byte_address_dword_aligned(byte_addr))
    {
        /* shouldn't happen */
        fprintf(stderr, "BUG: unaligned word offset 0x%x!\n", address);
        return false;
    }

    /* Issuing the write opcode always causes the firmware to write an entire
     * burst length worth of data to the flash.  The caller of this function
     * should ensure that 'size' is always equal to the burst length, except
     * possibly at the end of the bitstream. */

    exanic_register_write(flash->exanic,
            REG_HW_INDEX(REG_HW_FLASH_ADDR), byte_addr);

    size_t dword_size = byte_size / sizeof(qspi_flash_word_t);
    qspi_flash_word_t *dwords = (qspi_flash_word_t *)data;
    for (size_t i = 0; i < dword_size; i++)
        exanic_register_write(flash->exanic,
                REG_HW_INDEX(REG_HW_FLASH_DOUT_SPI), dwords[i]);

    flash_word_t *tail = (flash_word_t *)&dwords[dword_size];
    if (tail < data + size)
    {
        /* least significant bytes are clocked out first in firmware */
        qspi_flash_word_t dwtail = (qspi_flash_word_t )*tail;
        exanic_register_write(flash->exanic,
                REG_HW_INDEX(REG_HW_FLASH_DOUT_SPI), dwtail);
    }

    exanic_register_write(flash->exanic,
            REG_HW_INDEX(REG_HW_FLASH_QSPI_OPCODE),
            EXANIC_FLASH_QSPI_OPCODE_WRITE);

    /* wait for write cycle to finish */
    if (!qspi_wait_ready(flash))
    {
        fprintf(stderr, "ERROR: timeout during write at offset 0x%x!\n", address);
        return false;
    }

    uint8_t err;
    if ((err = qspi_error_status(flash->status)))
    {
        qspi_print_error("write", flash->status, err);
        return false;
    }

    return true;
}

static bool qspi_read(struct flash_device *flash, flash_address_t address,
        flash_word_t *data, flash_size_t size)
{
    size_t byte_addr = to_byte_address(address),
           byte_size = to_byte_size(size);
    if (!byte_address_dword_aligned(byte_addr))
    {
        /* shouldn't happen */
        fprintf(stderr, "BUG: unaligned word offset 0x%x!\n", address);
        return false;
    }

    qspi_flash_word_t *dwords = (qspi_flash_word_t *)data;
    size_t dwsize = byte_size / sizeof(qspi_flash_word_t);
    for (unsigned i = 0; i < dwsize; ++i)
    {
        exanic_register_write(flash->exanic,
                REG_HW_INDEX(REG_HW_FLASH_ADDR),
                byte_addr + i * sizeof(qspi_flash_word_t));
        exanic_register_write(flash->exanic,
                REG_HW_INDEX(REG_HW_FLASH_QSPI_OPCODE),
                EXANIC_FLASH_QSPI_OPCODE_READ);
        dwords[i] = exanic_register_read(flash->exanic,
                REG_HW_INDEX(REG_HW_FLASH_DIN_SPI));
    }

    flash_word_t *tail = (flash_word_t *)&dwords[dwsize];
    if (tail < data + size)
    {
        exanic_register_write(flash->exanic,
                REG_HW_INDEX(REG_HW_FLASH_ADDR),
                byte_addr + dwsize * sizeof(qspi_flash_word_t));
        exanic_register_write(flash->exanic,
                REG_HW_INDEX(REG_HW_FLASH_QSPI_OPCODE),
                EXANIC_FLASH_QSPI_OPCODE_READ);
        *tail = (flash_word_t)exanic_register_read(flash->exanic,
                REG_HW_INDEX(REG_HW_FLASH_DIN_SPI));
    }

    return true;
}

static struct flash_ops qspi_ops = {
    .init = qspi_init,
    .erase_block = qspi_erase_block,
    .burst_program = qspi_burst_program,
    .read = qspi_read,
    .release = qspi_release,
};

struct flash_device *flash_open_qspi(exanic_t *exanic, bool recovery_partition,
        flash_size_t *partition_size)
{
    struct flash_device *flash = calloc(1, sizeof *flash);
    if (!flash)
    {
        fprintf(stderr, "ERROR: memory allocation failed\n");
        return NULL;
    }

    const struct exanic_fw_flash_info *info = exanic->hw_info.flash_info;
    flash_size_t chip_size_words = info->device_size / BYTES_IN_FLASH_WORDS;
    flash_size_t recovery_size_words, production_size_words;
    flash_address_t recovery_offset, production_offset;

    /* split down the middle and store the recovery firmware in
     * the lower address range */
    size_t split_offset_byte = info->device_size >> 1;
    recovery_offset = 0;
    production_offset = split_offset_byte / BYTES_IN_FLASH_WORDS;
    recovery_size_words = production_offset;
    production_size_words = chip_size_words - production_offset;

    flash->exanic = exanic;
    flash->ops = &qspi_ops;
    flash->is_recovery = recovery_partition;
    flash->partition_size = *partition_size = recovery_partition ?
        recovery_size_words : production_size_words;
    flash->partition_start = recovery_partition ? recovery_offset : production_offset;
    flash->block_size = info->erase_size / BYTES_IN_FLASH_WORDS;
    flash->burst_buffer_size = info->write_size / BYTES_IN_FLASH_WORDS;
    flash->min_read_size = sizeof(qspi_flash_word_t) / BYTES_IN_FLASH_WORDS;
    /* no boot area */
    flash->boot_area_start = flash->partition_size;
    flash->boot_area_block_size = flash->block_size;

    return flash;
}
