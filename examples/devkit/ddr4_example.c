/**
 * ExaNIC Firmware Development Kit x25 'ddr4_example'.
 *
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

const char *ALL_REGS[6] = {
    "UID",
    "ddr4_npres",
    "init_complete_host",
    "app_rdy_host",
    "ddr_open_host",
    "agree_host"
};

int main(int argc, char *argv[])
{
    exanic_t *exanic;
    volatile uint32_t *application_registers;
    uint32_t temp;
    int i;
    const char *device;

    if (argc != 3)
        goto usage_error;

    device = argv[1];

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

    if (strcmp(argv[2], (const char *) "wr") == 0)
    {
        printf("write\n");
        application_registers[0] = 1;
    }
    else if(strcmp(argv[2], (const char *) "rd") == 0)
    {
        printf("read\n");
        application_registers[1] = 1;
    }
    else if(strcmp(argv[2], (const char *) "rst") == 0)
    {
        printf("reset\n");
        application_registers[2] = 1;
    }

    for (i = 0; i < 6; i++)
    {
        temp = application_registers[i];
        printf("\n%d %-20s: %08X", i, ALL_REGS[i], temp);
    }
    printf("\n");

    return 0;

usage_error:
    fprintf(stderr, "Usage: %s <device> <wr|rd|rst>", argv[0]);
    return -1;
}
