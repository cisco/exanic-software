/*
 * bitstream_config.c: Functions to modify bitstream configuration if required
 *
 * Copyright (C) 2020 Exablaze Pty Ltd
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <exanic/exanic.h>
#include <exanic/util.h>
#include "bitstream_config.h"

static const unsigned char bit_reverse_table[] =
{
    0x00, 0x80, 0x40, 0xC0, 0x20, 0xA0, 0x60, 0xE0, 0x10, 0x90, 0x50, 0xD0, 0x30, 0xB0, 0x70, 0xF0,
    0x08, 0x88, 0x48, 0xC8, 0x28, 0xA8, 0x68, 0xE8, 0x18, 0x98, 0x58, 0xD8, 0x38, 0xB8, 0x78, 0xF8,
    0x04, 0x84, 0x44, 0xC4, 0x24, 0xA4, 0x64, 0xE4, 0x14, 0x94, 0x54, 0xD4, 0x34, 0xB4, 0x74, 0xF4,
    0x0C, 0x8C, 0x4C, 0xCC, 0x2C, 0xAC, 0x6C, 0xEC, 0x1C, 0x9C, 0x5C, 0xDC, 0x3C, 0xBC, 0x7C, 0xFC,
    0x02, 0x82, 0x42, 0xC2, 0x22, 0xA2, 0x62, 0xE2, 0x12, 0x92, 0x52, 0xD2, 0x32, 0xB2, 0x72, 0xF2,
    0x0A, 0x8A, 0x4A, 0xCA, 0x2A, 0xAA, 0x6A, 0xEA, 0x1A, 0x9A, 0x5A, 0xDA, 0x3A, 0xBA, 0x7A, 0xFA,
    0x06, 0x86, 0x46, 0xC6, 0x26, 0xA6, 0x66, 0xE6, 0x16, 0x96, 0x56, 0xD6, 0x36, 0xB6, 0x76, 0xF6,
    0x0E, 0x8E, 0x4E, 0xCE, 0x2E, 0xAE, 0x6E, 0xEE, 0x1E, 0x9E, 0x5E, 0xDE, 0x3E, 0xBE, 0x7E, 0xFE,
    0x01, 0x81, 0x41, 0xC1, 0x21, 0xA1, 0x61, 0xE1, 0x11, 0x91, 0x51, 0xD1, 0x31, 0xB1, 0x71, 0xF1,
    0x09, 0x89, 0x49, 0xC9, 0x29, 0xA9, 0x69, 0xE9, 0x19, 0x99, 0x59, 0xD9, 0x39, 0xB9, 0x79, 0xF9,
    0x05, 0x85, 0x45, 0xC5, 0x25, 0xA5, 0x65, 0xE5, 0x15, 0x95, 0x55, 0xD5, 0x35, 0xB5, 0x75, 0xF5,
    0x0D, 0x8D, 0x4D, 0xCD, 0x2D, 0xAD, 0x6D, 0xED, 0x1D, 0x9D, 0x5D, 0xDD, 0x3D, 0xBD, 0x7D, 0xFD,
    0x03, 0x83, 0x43, 0xC3, 0x23, 0xA3, 0x63, 0xE3, 0x13, 0x93, 0x53, 0xD3, 0x33, 0xB3, 0x73, 0xF3,
    0x0B, 0x8B, 0x4B, 0xCB, 0x2B, 0xAB, 0x6B, 0xEB, 0x1B, 0x9B, 0x5B, 0xDB, 0x3B, 0xBB, 0x7B, 0xFB,
    0x07, 0x87, 0x47, 0xC7, 0x27, 0xA7, 0x67, 0xE7, 0x17, 0x97, 0x57, 0xD7, 0x37, 0xB7, 0x77, 0xF7,
    0x0F, 0x8F, 0x4F, 0xCF, 0x2F, 0xAF, 0x6F, 0xEF, 0x1F, 0x9F, 0x5F, 0xDF, 0x3F, 0xBF, 0x7F, 0xFF
};

static uint32_t get_uint32_bit_reverse(flash_word_t *data)
{
    uint32_t a = bit_reverse_table[data[0] >> 8];
    uint32_t b = bit_reverse_table[data[0] & 0xff];
    uint32_t c = bit_reverse_table[data[1] >> 8];
    uint32_t d = bit_reverse_table[data[1] & 0xff];
    return (a << 24) | (b << 16) | (c << 8) | d;
}

static void put_uint32_bit_reverse(flash_word_t *data, uint32_t val)
{
    uint32_t a = bit_reverse_table[val >> 24];
    uint32_t b = bit_reverse_table[(val >> 16) & 0xff];
    uint32_t c = bit_reverse_table[(val >> 8) & 0xff];
    uint32_t d = bit_reverse_table[val & 0xff];
    data[0] = (a << 8) | b;
    data[1] = (c << 8) | d;
}

#define CRC32C_POLYNOMIAL 0x82F63B78

static uint32_t accumulate_crc_le(uint32_t crc, uint32_t value, unsigned int bits)
{
    unsigned int bit, bottom_bit;
    for (bit = 0; bit < bits; bit++)
    {
        bottom_bit = crc&1;
        crc >>= 1;
        if (bottom_bit ^ (value&1))
            crc ^= CRC32C_POLYNOMIAL;
        value >>= 1;
    }
    return crc;
}

#define XIL_PACKET_TYPE1  1
#define XIL_PACKET_TYPE2  2
#define XIL_OPCODE_NOP    0
#define XIL_OPCODE_WRITE  2
#define XIL_REG_CRC       0
#define XIL_REG_CMD       4
#define XIL_REG_COR0      9
#define XIL_REG_CBC       11
#define XIL_REG_COR1      14
#define XIL_REG_BSPI      31
#define XIL_CMD_RCRC      7
#define XIL_CMD_DESYNC    13

static bool update_bitstream_config(flash_word_t *data, flash_size_t size,
                                    uint32_t bspi, uint32_t cor0, uint32_t cor1)
{
    flash_word_t *data_start = data;
    bool done_cor0 = false, done_cor1 = false;
    uint32_t packet, type, opcode, reg = 0, val;
    uint32_t write_length, i;
    uint32_t crc_reg = 0;

resync:
    /* Find SYNC pattern where FPGA starts processing bitstream */
    for (; size >= 2; data++, size--)
    {
        if ((data[0] == 0x5599) && (data[1] == 0xaa66))
        {
            data += 2;
            size -= 2;
            break;
        }
    }

    while (size >= 2)
    {
        packet = get_uint32_bit_reverse(data);
        data += 2;
        size -= 2;

        type = (packet >> 29) & 7;
        switch (type)
        {
            case XIL_PACKET_TYPE1:
                opcode = (packet >> 27) & 3;
                switch (opcode)
                {
                    case XIL_OPCODE_NOP:
                        continue;
                    case XIL_OPCODE_WRITE:
                        reg = (packet >> 13) & 0x3fff;
                        write_length = packet & 0x7ff;
                        break;
                    default:
                        fprintf(stderr, "ERROR: unexpected opcode %x in bitstream at offset 0x%lx\n", opcode,
                                                             sizeof(flash_word_t)*(data-data_start));

                        return false;
                }
                break;
            case XIL_PACKET_TYPE2:
                /* reg address taken from previous Type 1 packet */
                write_length = packet & 0x7ffffff;
                break;
            default:
                fprintf(stderr, "ERROR: unexpected packet type %x in bitstream at offset 0x%lx\n", type,
                                                             sizeof(flash_word_t)*(data-data_start));
                return false;
        }

        if (2*write_length > size)
            goto too_short;

        if (reg == XIL_REG_CBC)
        {
            /* begin encrypted section, get payload length and skip */
            if (write_length < 4)
            {
                fprintf(stderr, "ERROR: CBC arguments too short at offset 0x%lx\n",
                                         sizeof(flash_word_t)*(data-data_start));
                return false;
            }
            write_length += 60 + get_uint32_bit_reverse(&data[6]);
            if (2*write_length > size)
                goto too_short;

            data += 2*write_length;
            size -= 2*write_length;
            goto resync;
        }

        for (i = 0; i < write_length; i++)
        {
            switch (reg)
            {
                case XIL_REG_BSPI:
                    val = bspi;
                    put_uint32_bit_reverse(data, val);
                    break;
                case XIL_REG_COR0:
                    val = cor0;
                    put_uint32_bit_reverse(data, val);
                    done_cor0 = true;
                    break;
                case XIL_REG_COR1:
                    val = cor1;
                    put_uint32_bit_reverse(data, val);
                    done_cor1 = true;
                    break;
                case XIL_REG_CRC:
                    val = crc_reg;
                    put_uint32_bit_reverse(data, val);
                    break;
                default:
                    val = get_uint32_bit_reverse(data);
            }

            crc_reg = accumulate_crc_le(crc_reg, val, 32);
            crc_reg = accumulate_crc_le(crc_reg, reg, 5);

            switch (reg)
            {
                case XIL_REG_CMD:
                    val = get_uint32_bit_reverse(data);
                    switch (val)
                    {
                        case XIL_CMD_DESYNC:
                            goto resync;
                        case XIL_CMD_RCRC:
                            crc_reg = 0;
                    }
            }

            data += 2;
            size -= 2;
        }
    }

    return done_cor0 && done_cor1;

too_short:
    fprintf(stderr, "ERROR: ran out of data while processing bitstream at offset 0x%lx\n",
                                 sizeof(flash_word_t)*(data-data_start));
    return false;
}

bool check_bitstream_config(struct flash_device *flash, flash_word_t *data, flash_size_t data_size)
{
    exanic_hardware_id_t device_hw_id = exanic_get_hw_type(flash->exanic);

    if ((device_hw_id == EXANIC_HW_X10) || (device_hw_id == EXANIC_HW_X40)
         || (device_hw_id == EXANIC_HW_X10_GM) || (device_hw_id == EXANIC_HW_X10_HPT))
    {
        if ((flash->region_3_start != flash->device_size) || !flash->supports_unlock_bypass)
        {
            /* S29WS or S29GL part used on new X10/X40/GM/HPT to replace EOL P30 */
            /* set BPI_SYNC_MODE=0, CCLK=40Mhz, BPI_PAGE_SIZE=8, BPI_1ST_READ_CYCLE=4 */
            if (!update_bitstream_config(data, data_size, 0, 0x38103fe5, 0x0040000e))
            {
                fprintf(stderr, "ERROR: Failed to update bitstream settings. If this is an Exablaze firmware image, please use a newer version.\n"
                                "       Otherwise, please contact support for assistance.\n");
                return false;
            }
        }
    }
    return true;
}
