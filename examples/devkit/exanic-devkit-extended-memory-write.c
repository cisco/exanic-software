/**
 * Simple utility for writing to the devkit's extra BAR 4 space.
 *
 * Works with the extra_bars_example.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <exanic/exanic.h>
#include <exanic/util.h>

#define BUFFER_SIZE 128
#define CONTENT 0xdeadbeef
void write_to_extended_memory(exanic_t *exanic, size_t offset)
{
    char *extended_mem = exanic_get_extended_devkit_memory(exanic);
    static uint32_t buffer[BUFFER_SIZE];
    int i;
    for (i = 0; i < BUFFER_SIZE; i++)
        buffer[i] = CONTENT;

    printf("Writing <0x%08x> %d times to extended devkit memory region\n",
           CONTENT, BUFFER_SIZE);
    memcpy(extended_mem + offset, buffer, sizeof buffer);
}

int main(int argc, char **argv)
{
    exanic_t *exanic;
    char *device;
    char *leftover;
    size_t offset;

    if (argc != 3)
        goto usage_error;

    device = argv[1];
    offset = strtoull(argv[2], &leftover, 0);
    if (*leftover != '\0')
        goto usage_error;

    exanic = exanic_acquire_handle(device);
    if (!exanic)
    {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        return 1;
    }

    write_to_extended_memory(exanic, offset);
    exanic_release_handle(exanic);

    return 0;

usage_error:
    fprintf(stderr, "Usage: %s <exanic> <byte offset>\n", argv[0]);
    return 1;
}
