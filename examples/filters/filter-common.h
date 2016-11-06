#ifndef FILTER_COMMON_H_
#define FILTER_COMMON_H_
#include <stdio.h>
int parse_device_port(const char *str, char *device, int *port_number);
void print_escape(FILE *stream, const char *str, size_t len);

#endif
