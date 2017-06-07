/**
 * Simple utility for reading from registers in the devkit user register space
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
    int reg1, reg2, i;
    char *p;
    int32_t value;
    volatile uint32_t *application_registers;

    if (argc == 3)
    {
        device = argv[1];
        reg1 = reg2 = strtol(argv[2], &p, 0);
        if (*p != '\0')
            goto usage_error;
    }
    else if (argc == 4)
    {
        device = argv[1];
        reg1 = strtol(argv[2], &p, 0);
        if (*p != '\0')
            goto usage_error;
        reg2 = strtol(argv[3], &p, 0);
        if (*p != '\0')
            goto usage_error;
        if (reg1 > reg2) { i = reg2; reg2 = reg1; reg1 = i; }
    }
    else
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

    for (i = reg1; i <= reg2; i++)
    {
        value = application_registers[i];
        printf("0x%03x: 0x%08x (%d)\n", i, value, value);
    }

    exanic_release_handle(exanic);
    return 0;

usage_error:
    fprintf(stderr, "Usage: %s <exanic> <reg> [<reg>]\n", argv[0]);
    return 1;
}
