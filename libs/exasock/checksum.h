#ifndef EXASOCK_CHECKSUM_H
#define EXASOCK_CHECKSUM_H

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

static inline uint16_t
csum_iov(const struct iovec * restrict iov, size_t iovcnt, size_t skip_len,
         size_t data_len, uint64_t sum)
{
    size_t i;
    size_t offs;
    size_t iov_len = skip_len + data_len;

    offs = 0;
    for (i = 0; i < iovcnt && offs < iov_len; i++)
    {
        size_t len = iov[i].iov_len < iov_len - offs
                   ? iov[i].iov_len : iov_len - offs;
        size_t skip = offs < skip_len ? skip_len - offs : 0;

        if (skip < len)
        {
            if (((offs + skip) ^ skip_len) & 1)
            {
                sum = csum_part((void *)((uintptr_t)iov[i].iov_base + skip + 1),
                                len - skip - 1, sum);
                sum = sum + ((*(uint8_t *)iov[i].iov_base + skip) << 8);
            }
            else
                sum = csum_part(iov[i].iov_base + skip, len - skip, sum);
        }

        offs += len;
    }

    assert(offs == iov_len);

    return csum_pack(sum);
}

#endif /* EXASOCK_CHECKSUM_H */
