/*
 * file_access.c: Functions to read various firmware file formats (currently .bit, .fw and .fw.gz)
 *
 * Copyright (C) 2017 Exablaze Pty Ltd
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "file_access.h"

/**
 * Xilinx .bit file reading functions
 */

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

static bool get_uint16_be(FILE *fp, uint16_t *val)
{
    int a, b;
    a = fgetc(fp);
    b = fgetc(fp);
    *val = (a << 8) | b;
    return (b != EOF);
}

static bool get_uint32_be(FILE *fp, uint32_t *val)
{
    int a, b, c, d;
    a = fgetc(fp);
    b = fgetc(fp);
    c = fgetc(fp);
    d = fgetc(fp);
    *val = ((uint32_t)a << 24) | (b << 16) | (c << 8) | d;
    return (d != EOF);
}

static uint8_t *get_field(FILE *fp, size_t length)
{
    uint8_t *data = (uint8_t *) malloc(length);
    if (!data)
    {
        fprintf(stderr, "ERROR: malloc failed\n");
        return NULL;
    }

    if (fread(data, 1, length, fp) != length)
    {
        if (ferror(fp))
            perror("ERROR: fread");
        else
            fprintf(stderr, "ERROR: bitfile truncated\n");
        free(data);
        return NULL;
    }

    return data;
}

static flash_word_t *bytes_to_flash_words(uint8_t *buf, size_t size_bytes, bool bit_reverse, flash_size_t *size)
{
    size_t offset;
    if (bit_reverse)
    {
        for (offset = 0; offset < size_bytes; offset += 2)
        {
            uint8_t b0 = bit_reverse_table[buf[offset]];
            uint8_t b1 = bit_reverse_table[buf[offset+1]];
            *(uint16_t *)(&buf[offset]) = (b0 << 8) | b1;
        }
    }
    *size = size_bytes >> 1;
    return (flash_word_t *)buf;
}

static flash_word_t *read_bit_file(FILE *fp, flash_size_t partition_size, bool bit_reverse,
                                   flash_size_t *data_size, const char **firmware_id)
{
    size_t partition_size_bytes = partition_size<<1;
    int tag, header_done = 0;
    uint16_t field_length, version;
    uint32_t data_length = 0;
    uint8_t *bytes;
    char *build_info, *delimiter;

    if (!get_uint16_be(fp, &field_length) || (field_length != 9))
    {
        fprintf(stderr, "ERROR: this does not appear to be a valid bitfile\n");
        return NULL;
    }
    fseek(fp, field_length, SEEK_CUR); /* skip magic pattern (should be 0ff00ff00ff00ff000) */
    if (!get_uint16_be(fp, &version) || (version != 1))
    {
        fprintf(stderr, "ERROR: this does not appear to be a valid bitfile\n");
        return NULL;
    }

    /* process tag-length-value data */
    while (!header_done)
    {
        tag = fgetc(fp);
        switch (tag)
        {
            case 'a': /* build information */
                if (!get_uint16_be(fp, &field_length))
                    break;
                build_info = (char *)get_field(fp, field_length);
                if (!build_info)
                    return NULL;
                /* use first field of build information as firmware ID */
                delimiter = (char *) memchr(build_info, ';', field_length);
                if (!delimiter)
                {
                    fprintf(stderr, "ERROR: unexpected build info read from bitstream: %.*s\n",
                                    field_length, build_info);
                    free(build_info);
                    return NULL;
                }
                *delimiter = 0;
                *firmware_id = build_info;
                break;
            case 'b': /* FPGA part */
            case 'c': /* build date */
            case 'd': /* build time */
                if (!get_uint16_be(fp, &field_length))
                    break;
                fseek(fp, field_length, SEEK_CUR); /* skip */
                break;
            case 'e': /* bitstream data */
                if (!get_uint32_be(fp, &data_length))
                    break;
                header_done = 1;
                break;
            case EOF:
                break;
            default:
                fprintf(stderr, "ERROR: unexpected tag %d while parsing bitfile\n", tag);
                return NULL;
        }

        if (feof(fp))
            fprintf(stderr, "ERROR: bitfile truncated\n");
    }

    if (data_length == 0)
    {
        fprintf(stderr, "ERROR: no data read from firmware file\n");
        return NULL;
    }
    if (data_length > partition_size_bytes)
    {
        fprintf(stderr, "ERROR: image size %u larger than flash partition size %lu\n", data_length, partition_size_bytes);
        return NULL;
    }

    bytes = get_field(fp, data_length);
    if ( bytes == NULL )
    {
        fprintf(stderr, "ERROR: Failed to allocate buffer for %u bytes\n", data_length);
        return NULL;
    }

    return bytes_to_flash_words(bytes, data_length, bit_reverse, data_size);
}


/**
 * Intel HEX file reading functions
 */

static int8_t parse_hex_nibble(char c)
{
    switch (c)
    {
        case '0' ... '9':
            return c - '0';
        case 'A' ... 'F':
            return c - 'A' + 0xa;
        case 'a' ... 'f':
            return c - 'a' + 0xa;
        default:
            return -1;
    }
}

static bool parse_hex_byte(const char *p, uint8_t *value)
{
    int8_t hi, lo;

    hi = parse_hex_nibble(p[0]);
    lo = parse_hex_nibble(p[1]);
    *value = (hi << 4) | lo;
    return (hi != -1) && (lo != -1);
}

static flash_word_t *read_fw_file(FILE *fp, flash_size_t partition_size,
                                  flash_size_t *data_size, const char **firmware_id)
{
    char line[256];
    size_t line_len;
    char *delimiter;
    uint8_t bytes, line_address_hi, line_address_lo, type, checksum;
    uint8_t data[32] = {0};
    int line_number = 1;
    flash_word_t *flash_data;
    flash_address_t flash_address, flash_top, data_end = 0;
    uint32_t seg_address = 0;
    uint16_t line_address;
    unsigned int i;

    if (fgets(line, sizeof(line), fp) == NULL)
    {
        fprintf(stderr, "ERROR: empty firmware file\n");
        return NULL;
    }
    if (line[0] != ';')
    {
        fprintf(stderr, "ERROR: bad firmware file format\n");
        return NULL;
    }
    /* first field of header line is firmware ID */
    delimiter = strchr(&line[1], ',');
    if (delimiter)
        *delimiter = 0;
    *firmware_id = strdup(&line[1]);

    flash_data = (flash_word_t *) malloc(partition_size*sizeof(flash_word_t));
    if (!flash_data)
    {
        fprintf(stderr, "ERROR: malloc failed\n");
        return NULL;
    }

    while (fgets(line, sizeof(line), fp) != NULL)
    {
        line_number++;
        if (line[0] == ';')
            continue;

        line_len = strlen(line);
        if ((line_len < 11) || (line[0] != ':')
             || !parse_hex_byte(&line[1], &bytes)
             || !parse_hex_byte(&line[3], &line_address_hi)
             || !parse_hex_byte(&line[5], &line_address_lo)
             || !parse_hex_byte(&line[7], &type)
             || (bytes > sizeof(data))
             || (line_len < 11u+2u*bytes)
             || !parse_hex_byte(&line[9+2*bytes], &checksum))
        {
            fprintf(stderr, "ERROR: parse error on line %u\n", line_number);
            goto error;
        }

        checksum += bytes + line_address_hi + line_address_lo + type;
        for (i = 0; i < bytes; i++)
        {
            if (!parse_hex_byte(&line[9+2*i], &data[i]))
            {
                fprintf(stderr, "ERROR: parse error on line %u\n", line_number);
                goto error;
            }
            checksum += data[i];
        }

        if ((checksum & 0xff) != 0)
        {
            fprintf(stderr, "ERROR: bad checksum on line %u\n", line_number);
            goto error;
        }

        switch (type)
        {
            case 0: /* data */
                line_address = (line_address_hi << 8) | line_address_lo;
                flash_address = (seg_address + line_address) >> 1;
                flash_top = flash_address + (bytes>>1);
                if (flash_top > data_end)
                {
                    if (flash_top > partition_size)
                    {
                        fprintf(stderr, "ERROR: image size larger than flash partition size %u\n", partition_size);
                        goto error;
                    }
                    data_end = flash_top;
                }
                for (i = 0; i < bytes; i+=2)
                    flash_data[flash_address++] = (data[i+1] << 8) | data[i];
                break;
            case 1: /* eof */
                break;
            case 4: /* extended linear address */
                seg_address = (data[0] << 24) | (data[1] << 16);
                break;
            default:
                fprintf(stderr, "ERROR: unknown record type %u on line %u\n", type, line_number);
                goto error;
        }
    }

    if (data_end == 0)
    {
        fprintf(stderr, "ERROR: no data read from firmware file\n");
        goto error;
    }
    *data_size = data_end;
    return flash_data;

error:
    free(flash_data);
    return NULL;
}

static flash_word_t *read_gz_file(const char *filename, flash_size_t partition_size,
                                  flash_size_t *data_size, const char **firmware_id)
{
    const char *cmdprefix = "gunzip -c ";
    unsigned int cmdlen = strlen(cmdprefix)+strlen(filename)+1;
    char *pipecmd;
    FILE *pipefp;
    uint16_t *ret;

    pipecmd = (char *) malloc(cmdlen);
    if (pipecmd == NULL)
    {
        fprintf(stderr, "ERROR: malloc failed\n");
        return NULL;
    }

    snprintf(pipecmd, cmdlen, "gunzip -c %s", filename);
    pipefp = popen(pipecmd, "r");
    free(pipecmd);
    if (pipefp == NULL)
    {
        perror("gunzip");
        return NULL;
    }
    ret = read_fw_file(pipefp, partition_size, data_size, firmware_id);
    pclose(pipefp);
    return ret;
}


flash_word_t *read_firmware(const char *filename, flash_size_t partition_size,
                            bool bit_reverse_bitstream, flash_size_t *data_size,
                            const char **firmware_id)
{
    FILE *fp;
    uint16_t *ret;
    int c;

    fp = fopen(filename, "r");
    if (fp == NULL)
    {
        perror(filename);
        return NULL;
    }

    /* peek at first character to determine file type */
    c = fgetc(fp);
    ungetc(c, fp);
    switch (c)
    {
        case EOF:
            fprintf(stderr, "ERROR: empty firmware file\n");
            ret = NULL;
            break;
        case ';':
            ret = read_fw_file(fp, partition_size, data_size, firmware_id);
            break;
        case 0x1f:
            ret = read_gz_file(filename, partition_size, data_size, firmware_id);
            break;
        default:
            ret = read_bit_file(fp, partition_size, bit_reverse_bitstream,
                                data_size, firmware_id);
    }
    fclose(fp);
    if (ret == NULL)
        return NULL;
    return ret;
}

