/**
 * Development kit example application, for use with the sample FPGA application.
 * Shows how to prime the FPGA with a reply frame, and how to set up the mask and
 * pattern in the FPGA memory.
 *
 * To be used with "exanic_x4_trigger.fw" from the devkit examples.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <limits.h>
#include <getopt.h>
#include <exanic/exanic.h>
#include <exanic/util.h>
#include <arpa/inet.h>
#include <unistd.h>

#define REG_FIRMWARE_ID         0x00
#define REG_FIRMWARE_VERSION    0x01
#define REG_ARM                 0x02
#define REG_TESTFIRE            0x03
#define REG_MATCH_LENGTH        0x04
#define REG_TRANSMIT_LENGTH     0x05
#define REG_TRIGGER_COUNT       0x06
#define REG_AUTORELOAD          0x07

#define PATTERN_RAM_OFFSET      0x2000
#define MASK_RAM_OFFSET         0x4000
#define TRANSMIT_RAM_OFFSET     0x6000

#define FIRMWARE_ID             0xEB000001

int keep_running = 1;

void sig_handler(int sig)
{
    keep_running = 0;
}

int main(int argc, char *argv[])
{
    const char *device;
    exanic_t *exanic;
    volatile uint32_t *application_registers;
    char * application_memory;
    int c, index, trigger_count = 0;
    int32_t max_triggers = INT32_MAX;

    struct __attribute__ ((__packed__)) my_ip_frame
    {
        uint8_t dst_mac[6];
        uint8_t src_mac[6];
        uint16_t ethertype;
        uint8_t  version;
        uint8_t  dscp;
        uint16_t  ip_len;
        uint16_t ident;
        uint16_t fragment;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t ip_checksum;
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        uint16_t prot_len;
        uint16_t prot_checksum;
        uint8_t  payload[23];
    } pattern_data, mask_data, reply;

    static struct option long_options[] = {
        {"max-triggers", required_argument, NULL, 0},
        {NULL, 0, NULL, 0}
    };

    while ((c = getopt_long(argc, argv, "", long_options, &index)) != -1) {
        switch(c) {
        case 0:
            max_triggers = atoi(optarg);
        case '?':
            break;
        default:
            goto usage_error;
        }
    }

    if (optind != argc - 1) // one remaining arg - the exanic to use
        goto usage_error;
    device = argv[optind];
    exanic = exanic_acquire_handle(device);

    if (exanic == NULL)
    {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        return -1;
    }

    if (exanic_get_function_id(exanic) != EXANIC_FUNCTION_DEVKIT)
    {
        fprintf(stderr, "%s: %s\n", device, "Device is not a development kit.");
        return -1;
    }

    if ((application_registers = exanic_get_devkit_registers(exanic)) == NULL)
    {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        return -1;
    }

    if ((application_memory = exanic_get_devkit_memory(exanic)) == NULL)
    {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        return -1;
    }

    if (application_registers[REG_FIRMWARE_ID] != FIRMWARE_ID)
    {
        fprintf(stderr, "Application ID register does not match expected (got %x, expected %x)\n",
                    application_registers[REG_FIRMWARE_ID], FIRMWARE_ID);
        return -1;
    }

    signal(SIGINT, sig_handler);

    memset(&pattern_data, 0, sizeof(pattern_data));
    memset(&mask_data, 0, sizeof(mask_data));
    memset(&reply, 0, sizeof(reply));

    /* Match on IP ethertype. */
    pattern_data.ethertype = htons(0x0800);
    mask_data.ethertype = 0xFFFF;

    /* Configure a dummy IP reply. */
    memset(reply.dst_mac, 0xFF, 6);
    reply.ethertype = htons(0x0800);
    reply.payload[0] = 0xDE;
    reply.payload[1] = 0xAD;
    reply.payload[2] = 0xBE;
    reply.payload[3] = 0xEF;

    /* Copy our mask, pattern and reply to the FPGA memory. */
    memcpy(application_memory + PATTERN_RAM_OFFSET, &pattern_data, sizeof(pattern_data));
    memcpy(application_memory + MASK_RAM_OFFSET, &mask_data, sizeof(mask_data));
    memcpy(application_memory + TRANSMIT_RAM_OFFSET, &reply, sizeof(reply));

    /* Configure registers. Setup the match length, arm the trigger, etc. */
    application_registers[REG_MATCH_LENGTH] = 25;
    application_registers[REG_TRANSMIT_LENGTH] = sizeof(reply);
    application_registers[REG_ARM] = 1;
    application_registers[REG_TESTFIRE] = 0;
    application_registers[REG_AUTORELOAD] = 1;

    printf("Application Version: %d\n", application_registers[REG_FIRMWARE_VERSION]);
    printf("Armed:               %d\n", application_registers[REG_ARM]);
    printf("Match Length:        %d\n", application_registers[REG_MATCH_LENGTH]);
    printf("Transmit Length:     %d\n", application_registers[REG_TRANSMIT_LENGTH]);
    printf("Trigger count:       %d\n", application_registers[REG_TRIGGER_COUNT]);

    do
    {
        if (trigger_count != application_registers[REG_TRIGGER_COUNT])
        {
            trigger_count = application_registers[REG_TRIGGER_COUNT];
            printf("-> Triggered. Total %d\n", trigger_count);
            max_triggers--;
        }
        usleep(1000);
    } while (keep_running && max_triggers > 0);

    application_registers[REG_ARM] = 0;

    if (!keep_running)
        printf("Signal caught: Disarming trigger.\n");
    else if (max_triggers == 0)
        printf("Max trigger count reached: Disarming trigger.\n");

    return 0;
    usage_error:
    fprintf(stderr,
            "Usage: %s [--max-triggers=MAX_TRIGGERS] <device>\n"
            "Configure the example exanic development kit application on <device>.\n"
            "The example FPGA application sends a pre-loaded reply to incoming frames\n"
            "that match a mask and pattern. In this example, all IP frames are matched\n"
            "and a dummy reply is sent. The optional argument `max-triggers` controls\n"
            "the maximum number of triggers seen before exiting.\n",
            argv[0]);
    return -1;

}
