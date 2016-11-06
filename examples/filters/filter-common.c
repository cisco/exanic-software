#include "filter-common.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
void print_escape(FILE *stream, const char *str, size_t len)
{
    int i;

    for (i = 0; i < len; i++)
    {
        if (i % 16 == 0 && i != 0)
            fprintf(stream, "\n");
        fprintf(stream, "%02X ", (unsigned char) str[i]);
    }
    fprintf(stream, "\n\n");
}

/* Parses a string of the format "<device>:<port>" */
int parse_device_port(const char *str, char *device, int *port_number)
{
    char *p, *q;

    p = strchr(str, ':');
    if (p == NULL)
        return -1;

    if ((p-str) >= 16)
        return -1;
    strncpy(device, str, p - str);
    device[p - str] = '\0';
    *port_number = strtol(p + 1, &q, 10);
    if (*(p + 1) == '\0' || *q != '\0')
        /* strtol failed */
        return -1;
    return 0;
}
