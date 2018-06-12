/**
 * ExaNIC Firmware Development Kit 'spam' example.
 *
 * To be used with "exanic_*_native_spam_example.fw" generated from the
 * devkit examples.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <exanic/exanic.h>
#include <exanic/util.h>
#include <exanic/port.h>

#define REG_FIRMWARE_ID         0x0000
#define REG_FIRMWARE_VERSION    0x0001
#define REG_START               0x0002
#define REG_NUM_FRAMES          0x0003
#define REG_FRAME_LEN_MIN       0x0004
#define REG_FRAME_LEN_MAX       0x0005
#define REG_WAIT_CYCLES         0x0006
#define REG_SRC_MAC_LOWER       0x0007
#define REG_SRC_MAC_UPPER       0x0008
#define REG_DST_MAC_LOWER       0x0009
#define REG_DST_MAC_UPPER       0x000A
#define REG_ETHERTYPE           0x000B

#define FIRMWARE_ID             0xEB000003
#define FIRMWARE_VERSION        0x00000001

int main(int argc, char *argv[])
{
    const char *device;
    long num_frames;
    int frame_len_min, frame_len_max, wait_cycles;
    uint8_t src_mac[6];
    uint32_t src_mac_lower, src_mac_upper;
    exanic_t *exanic;
    volatile uint32_t *application_registers;
    int opt;

    device = "";
    num_frames = 0xFFFFFFFF;
    frame_len_min = -1;
    frame_len_max = -1;
    wait_cycles = 0;

    while ((opt = getopt(argc, argv, "c:s:S:g:")) != -1)
    {
        switch (opt) {
        case 'c':
            num_frames = atol(optarg);
            if (num_frames < 0)
                goto usage_error;
            break;
        case 's':
            frame_len_min = atoi(optarg);
            if (frame_len_min <= 0)
                goto usage_error;
            break;
        case 'S':
            frame_len_max = atoi(optarg);
            if (frame_len_max <= 0)
                goto usage_error;
            break;
        case 'g':
            wait_cycles = atoi(optarg);
            if (wait_cycles < 0)
                goto usage_error;
            break;
        default:
            goto usage_error;
        }
    }

    if (argc != optind + 1)
        goto usage_error;

    device = argv[optind];
    if (frame_len_min == -1 && frame_len_max == -1)
        frame_len_min = frame_len_max = 60;
    else if (frame_len_max == -1)
        frame_len_max = frame_len_min;
    else if (frame_len_min == -1)
        frame_len_min = frame_len_max;

    if ((exanic = exanic_acquire_handle(device)) == NULL)
    {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        return -1;
    }

    if (exanic_get_function_id(exanic) != EXANIC_FUNCTION_DEVKIT)
    {
        fprintf(stderr, "%s: Device is not a development kit device\n", device);
        return -1;
    }

    if ((application_registers = exanic_get_devkit_registers(exanic)) == NULL)
    {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        return -1;
    }

    if (application_registers[REG_FIRMWARE_ID] != FIRMWARE_ID)
    {
        fprintf(stderr, "Application ID register does not match expected (got %x, expected %x)\n",
                    application_registers[REG_FIRMWARE_ID], FIRMWARE_ID);
        fprintf(stderr, "This program requires the native_spam_example firmware\n");
        return -1;
    }

    if (application_registers[REG_FIRMWARE_VERSION] != FIRMWARE_VERSION)
    {
        fprintf(stderr, "Application version register does not match expected (got %x, expected %x)\n",
                    application_registers[REG_FIRMWARE_VERSION], FIRMWARE_VERSION);
        return -1;
    }

    /* Use MAC address of ExaNIC as source address */
    exanic_get_mac_addr(exanic, 0, src_mac);
    src_mac_lower = src_mac[0] | (src_mac[1] << 8) | (src_mac[2] << 16) | (src_mac[3] << 24);
    src_mac_upper = src_mac[4] | (src_mac[5] << 8);

    /* Write packet generator settings to hardware */
    application_registers[REG_NUM_FRAMES] = num_frames;
    application_registers[REG_FRAME_LEN_MIN] = frame_len_min;
    application_registers[REG_FRAME_LEN_MAX] = frame_len_max;
    application_registers[REG_WAIT_CYCLES] = wait_cycles;
    application_registers[REG_SRC_MAC_LOWER] = src_mac_lower;
    application_registers[REG_SRC_MAC_UPPER] = src_mac_upper;
    application_registers[REG_DST_MAC_LOWER] = 0xFFFFFFFF;
    application_registers[REG_DST_MAC_UPPER] = 0xFFFF;
    application_registers[REG_ETHERTYPE] = 0xB688;

    /* Read back registers to confirm settings */
    num_frames = application_registers[REG_NUM_FRAMES];
    frame_len_min = application_registers[REG_FRAME_LEN_MIN];
    frame_len_max = application_registers[REG_FRAME_LEN_MAX];
    wait_cycles = application_registers[REG_WAIT_CYCLES];

    if (num_frames == 0xFFFFFFFF)
        printf("Number of frames : unlimited\n");
    else
        printf("Number of frames : %lu\n", num_frames);
    printf("Frame size       : %u to %u\n", frame_len_min, frame_len_max);
    printf("Extra frame gap  : %u\n", wait_cycles);

    /* Start the packet generator by writing any value to the start register */
    application_registers[REG_START] = 0;

    return 0;

usage_error:
    fprintf(stderr, "Usage: %s <device> [-c count] [-s min-size] [-S max-size] [-g gap]\n", argv[0]);
    return -1;
}
