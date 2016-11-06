/**
 * ExaNIC Firmware Development Kit 'ping' example.
 *
 * Demonstrates:
 *  - Sending an ARP request from within hardware.
 *  - Listening for the ARP reply and populating a hardware ARP table.
 *  - Sending a ping request from within hardware.
 *  - Listening for the reply and hardware timestamping it.
 *  - Sending a custom frame to the host that contains the hardware timestamps.
 *
 *  To be used with "exanic_x4_ping.fw" generated from devkit examples.
 *
 */
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <exanic/exanic.h>
#include <exanic/fifo_rx.h>
#include <exanic/util.h>
#include <exanic/port.h>
#include <arpa/inet.h>
#include <unistd.h>

#define REG_FIRMWARE_ID         0x0000
#define REG_FIRMWARE_VERSION    0x0001
#define REG_REMOTE_IP           0x0002
#define REG_LOCAL_IP            0x0003
#define REG_LOCAL_MAC_LOWER     0x0004
#define REG_LOCAL_MAC_UPPER     0x0005

#define FIRMWARE_ID             0xEB000002

int keep_running = 1;

void sig_handler(int sig)
{
    keep_running = 0;
}

int main(int argc, char *argv[])
{
    exanic_t *exanic;
    exanic_rx_t *rx;
    volatile uint32_t *application_registers;
    char * application_memory;
    struct in_addr dst_ip;
    struct in_addr src_ip;
    uint8_t src_mac[6];
    uint32_t mac_lower;
    uint32_t mac_upper;
    uint32_t start_time;
    uint32_t end_time;
    double multiplier;
    char rx_buf[2048]; 
    int size;

    if (argc != 4)
        goto usage_error;

    if ((exanic = exanic_acquire_handle(argv[1])) == NULL)
    {
        fprintf(stderr, "%s: %s\n", argv[1], exanic_get_last_error());
        return -1;
    }

    if ((rx = exanic_acquire_rx_buffer(exanic, 0, 0)) == NULL)
    {
        fprintf(stderr, "%s: %s\n", argv[1], exanic_get_last_error());
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

    if ((application_memory = exanic_get_devkit_memory(exanic)) == NULL)
    {
        fprintf(stderr, "%s: %s\n", argv[1], exanic_get_last_error());
        return -1;
    }

    if (application_registers[REG_FIRMWARE_ID] != FIRMWARE_ID)
    {
        fprintf(stderr, "Application ID register does not match expected (got %x, expected %x)\n",
                    application_registers[REG_FIRMWARE_ID], FIRMWARE_ID);
        return -1;
    }

    signal(SIGINT, sig_handler);

    exanic_get_mac_addr(exanic, 0, src_mac);
    mac_lower = src_mac[0] | (src_mac[1] << 8) | (src_mac[2] << 16) | (src_mac[3] << 24);
    mac_upper = src_mac[4] | (src_mac[5] << 8);

    inet_aton(argv[2], &dst_ip);
    inet_aton(argv[3], &src_ip);

    application_registers[REG_LOCAL_IP] = src_ip.s_addr;
    application_registers[REG_LOCAL_MAC_LOWER] = mac_lower;
    application_registers[REG_LOCAL_MAC_UPPER] = mac_upper;
    application_registers[REG_REMOTE_IP] = dst_ip.s_addr;

    multiplier = 1000000000.0 / (double) exanic->tick_hz;

    while (keep_running)
    {
        size = exanic_receive_frame(rx, rx_buf, sizeof(rx_buf), NULL);
        if (size > 0)
        {
            /* Look for our custom frame type. */
            if (size == 48 && (uint8_t) rx_buf[12] == 0xEB && (uint8_t) rx_buf[13] == 0xEB)
            {
                switch(rx_buf[16])
                {
                    case 0: 
                        start_time = *(uint32_t *)(&rx_buf[24]);
                        end_time = *(uint32_t *)(&rx_buf[32]);
                        printf("Received ping reply with delta: %f ns (raw start: %u, raw end: %u, clock period: %f)\n", (end_time - start_time) * multiplier, start_time, end_time, multiplier);
                        return 0;
                    case 1:
                        printf("Timed out waiting for ARP reply.\n");
                        return 1;
                    case 2:
                        printf("Sent too many ARP requests, but replies came from different host.\n");
                        return 1;
                    case 3:
                        printf("ICMP request timed out.\n");
                        return 1;
                    default: 
                        printf("Unknown custom frame received, status = %u\n", rx_buf[16]);
                        return 1;
                }
            }
        }
    }

    return 0;
    usage_error:
    fprintf(stderr, "Usage: %s <device> <dst-ip> <src-ip>\n", argv[0]);
    fprintf(stderr, "   Sends a ping to <dst-ip> originating from <src-ip>.\n");
    return -1;

}
