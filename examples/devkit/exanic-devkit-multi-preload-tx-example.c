/**
 * Devkit example showing how to stage packets in advance and then trigger them.
 *
 * To be used with "exanic_v5p_multi_preload_tx_example.fw" from the devkit examples.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <exanic/exanic.h>
#include <exanic/util.h>
#include <exanic/register.h>

void trigger_packet(volatile uint32_t *application_registers, uint32_t mask, uint8_t index)
{
    application_registers[0] = mask << 8 | index;
}

void write_length(volatile uint32_t *application_registers, uint8_t port, uint8_t buffer, uint16_t len)
{
    application_registers[1 << 10 | port << 5 | buffer] = len;
}

int get_buffer_offset(uint8_t port, uint8_t buffer)
{
  return port << 18 | buffer << 11;
}

int main(int argc, char *argv[])
{
    exanic_t *exanic;
    char *device;
    volatile uint32_t *application_registers;
    char *app_mem;

    if (argc != 2)
        goto usage_error;

    device = argv[1];

    /*
     * Open the Exanic device and get handles to the register and memory spaces
     */
    exanic = exanic_acquire_handle(device);
    if (exanic == NULL)
    {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        return EXIT_FAILURE;
    }

    if ((application_registers = exanic_get_devkit_registers(exanic)) == NULL)
    {
        fprintf(stderr, "%s: %s\n", argv[1], exanic_get_last_error());
        return EXIT_FAILURE;
    }

    if ((app_mem = exanic_get_devkit_memory(exanic)) == NULL)
    {
        fprintf(stderr, "exanic_get_devkit_memory: %s\n", exanic_get_last_error());
        return EXIT_FAILURE;
    }

    /*
     * Setup 4 packets: the first 2 buffers on the first 2 ports
     */
    write_length(application_registers, 0, 0, 600);
    strcpy(app_mem + get_buffer_offset(0, 0), "a packet");

    write_length(application_registers, 0, 1, 601);
    strcpy(app_mem + get_buffer_offset(0, 1), "a packet buffer 2");

    write_length(application_registers, 1, 0, 1000);
    strcpy(app_mem + get_buffer_offset(1, 0), "a packet port 2");

    write_length(application_registers, 1, 1, 1001);
    strcpy(app_mem + get_buffer_offset(1, 1), "a packet port 2 buffer 2");

    /*
     * Trigger both buffers on both ports
     */
    trigger_packet(application_registers, 3, 0);
    trigger_packet(application_registers, 3, 1);

    exanic_release_handle(exanic);
    return 0;

usage_error:
    fprintf(stderr, "Usage: %s <exanic>\n", argv[0]);
    return 1;
}

