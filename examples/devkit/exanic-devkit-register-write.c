/**
 * Simple utility for writing to registers in the devkit user register space
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <exanic/exanic.h>
#include <exanic/util.h>
#include <exanic/register.h>

int main(int argc, char *argv[])
{
    exanic_t *exanic;
    char *device;
    int reg;
    char *p;
    uint32_t value;
    volatile uint32_t *application_registers;

    if (argc != 4)
        goto usage_error;

    device = argv[1];
    reg = strtol(argv[2], &p, 0);
    if (*p != '\0')
        goto usage_error;
    value = strtol(argv[3], &p, 0);
    if (*p != '\0')
        goto usage_error;

    exanic = exanic_acquire_handle(device);
    if (exanic == NULL)
    {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        return 1;
    }

    if ((application_registers = exanic_get_devkit_registers(exanic)) == NULL)
    {
        fprintf(stderr, "%s: %s\n", argv[1], exanic_get_last_error());
        return -1;
    }

    application_registers[reg] = value;

    printf("0x%03x: wrote 0x%08x (%d)\n", reg, value, value);

    exanic_release_handle(exanic);
    return 0;

usage_error:
    fprintf(stderr, "Usage: %s <exanic> <reg> <value>\n", argv[0]);
    return 1;
}
