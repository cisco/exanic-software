#ifndef EXANIC_CHECKSUM_H
#define EXANIC_CHECKSUM_H

#if defined(__amd64__)
#include "checksum_amd64.h"
#elif defined(__powerpc64__)
#include "checksum_ppc64.h"
#else

#warning "NOTICE: This system does not appear to be an amd64 (x86_64) or powerpc64 (POWER) system; performance may be affected."
#warning "NOTICE: Please contact support@exablaze.com for assistance."

static inline uint64_t
csum_part(const void *buf, size_t len, uint64_t sum)
{
    uintptr_t p = (uintptr_t)buf;

    while (len > 1)
    {
        sum += *(uint16_t *)p;
        len -= 2;
        p += 2;
    }

    if (len)
        sum += *(uint8_t *)p;

    return sum;
}

#endif

static inline uint16_t
csum_pack(uint64_t sum)
{
    sum = (sum >> 32) + (uint32_t)sum;
    sum = (sum >> 32) + (uint32_t)sum;
    sum = (sum >> 16) + (uint16_t)sum;
    sum = (sum >> 16) + (uint16_t)sum;
    return sum;
}

static inline uint16_t
csum_pack32(uint32_t sum)
{
    sum = (sum >> 16) + (uint16_t)sum;
    sum = (sum >> 16) + (uint16_t)sum;
    return sum;
}

static inline uint16_t
csum(const void *buf, size_t len, uint64_t sum)
{
    return csum_pack(csum_part(buf, len, sum));
}

#endif /* EXANIC_CHECKSUM_H */
