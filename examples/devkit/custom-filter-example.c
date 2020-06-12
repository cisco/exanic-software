/**
 * Devkit example showing how to steer traffic based on packet contents to a
 * userspace buffer.
 *
 * To be used with steer_example, one of the ExaNIC devkit examples.
 */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <exanic/fifo_rx.h>
#include <exanic/fifo_tx.h>
#include <exanic/filter.h>
#include <exanic/util.h>
#include <exanic/exanic.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#define REG_FIRMWARE_ID         0x00
#define REG_FIRMWARE_VERSION    0x01
#define REG_FILTER_BUFFER       0x02
#define REG_FILTER_DST_IP       0x03

#define FIRMWARE_ID             0xEB000003

#define IDLE_SECS_BEFORE_EXIT 20

void print_frame(char *buf, int len)
{
    int i, j;
    for (i = 0; i < len; i += 16)
    {
        printf("  ");
        for (j = 0; j < 16 && i+j < len; j++)
        {
            printf("%02X", (uint8_t) buf[i+j]);
        }
        printf("\n");
    }
}

int keep_running = 1;

void sig_handler(int sig)
{
    keep_running = 0;
}

int parse_device_port(const char *str, char *device, int *port_number)
{
    char *p, *q;

    if (strlen(str) > 16)
        return -1;

    p = strchr(str, ':');
    if (p == NULL)
        return -1;

    strncpy(device, str, p - str);
    device[p - str] = '\0';
    *port_number = strtol(p + 1, &q, 10);
    if (*(p + 1) == '\0' || *q != '\0')
        return -1;
    return 0;
}

int main(int argc, char *argv[])
{
    const char *exanic_name = NULL;
    char device[16];
    exanic_t *exanic;
    exanic_rx_t *rx;
    struct in_addr dst_addr;
    char buf[1550];
    int size, port_number;
    volatile uint32_t *application_registers;
    int total_matched;
    int expected_matches = 0;
    int last_time, curr_time, idle_secs;

    if (argc < 3 || argc > 4)
        goto usage_error;

    exanic_name = argv[1];

    if (parse_device_port(exanic_name, device, &port_number) == -1)
      goto usage_error;

    if (argc >= 4)
      expected_matches = atoi(argv[3]);

    if ((exanic = exanic_acquire_handle(device)) == NULL)
    {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        return -1;
    }

    if (exanic_get_function_id(exanic) != EXANIC_FUNCTION_DEVKIT)
    {
        fprintf(stderr, "%s: %s\n", argv[1], "Device is not a development kit.");
        return -1;
    }

    if ((application_registers = exanic_get_devkit_registers(exanic)) == NULL)
    {
        fprintf(stderr, "%s: %s\n", argv[1], exanic_get_last_error());
        return -1;
    }

    /* Check that the ExaNIC is actually loaded with our desired firmware. */
    if (application_registers[REG_FIRMWARE_ID] != FIRMWARE_ID)
    {
        fprintf(stderr, "Application ID register does not match expected (got %x, expected %x)",
                application_registers[REG_FIRMWARE_ID], FIRMWARE_ID);
        return -1;
    }

    /* Acquire an unused filter buffer to steer our traffic to. */
    rx = exanic_acquire_unused_filter_buffer(exanic, port_number);
    if (rx == NULL)
    {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        fprintf(stderr, "%s: %s\n", device, "Couldn't allocate filter.");
        return -1;
    }

    if (inet_aton(argv[2], &dst_addr) == 0)
    {
        printf("Invalid destination IP.\n");
        return -1;
    }

    signal(SIGINT, sig_handler);

    /* Set up our filter. */
    application_registers[REG_FILTER_BUFFER] = rx->buffer_number;
    application_registers[REG_FILTER_DST_IP] = dst_addr.s_addr;
    printf("Acquired filter buffer %d\n", rx->buffer_number);

    total_matched = 0;
    idle_secs = 0;
    last_time = time(NULL);

    while (keep_running)
    {
        size = exanic_receive_frame(rx, buf, sizeof(buf), NULL);
        if (size > 0)
        {
            printf("Frame matched filter:\n");
            print_frame(buf, size);
            total_matched++;
        }
        else if (size < 0)
        {
            printf("Receive error: %d.\n", size);
        }

        if (expected_matches > 0)
        {
            if (total_matched >= expected_matches)
                break;

            curr_time = time(NULL);
            if (curr_time != last_time)
            {
                last_time = curr_time;
                if(idle_secs++ >= IDLE_SECS_BEFORE_EXIT)
                {
                    goto return_timeout;
                }
            }
        }
    }
    printf("Frames matched: %d\n", total_matched);

    exanic_release_rx_buffer(rx);
    exanic_release_handle(exanic);
    return 0;

return_timeout:
    exanic_release_rx_buffer(rx);
    exanic_release_handle(exanic);
    printf("Timeout at: %d, Frames matched: %d\n", idle_secs, total_matched);
    return 2;

usage_error:
    printf("Usage: %s <device>:<port_number> <dst_ip> [expected_matches]\n", argv[0]);
    printf("    Filter IP packets to a custom RX buffer based upon the destination IP.\n");
    printf("    Requires the card to be loaded with the devkit filter example firmware.\n");
    return 1;
}
