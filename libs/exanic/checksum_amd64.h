#ifndef EXANIC_CHECKSUM_AMD64_H
#define EXANIC_CHECKSUM_AMD64_H

static inline uint64_t
csum_part(const void *buf, size_t len, uint64_t sum)
{
    uintptr_t p = (uintptr_t)buf;

    if (len >= 128)
    {
        uint64_t sum1 = 0, sum2 = 0, sum3 = 0;

        /* 128 byte blocks */
        while (len >= 128)
        {
            asm volatile
            (
                "add    (%4), %0;"
                "adc    8(%4), %0;"
                "adc    16(%4), %0;"
                "adc    24(%4), %0;"
                "adc    $0, %0;"
                "add    32(%4), %1;"
                "adc    40(%4), %1;"
                "adc    48(%4), %1;"
                "adc    56(%4), %1;"
                "adc    $0, %1;"
                "add    64(%4), %2;"
                "adc    72(%4), %2;"
                "adc    80(%4), %2;"
                "adc    88(%4), %2;"
                "adc    $0, %2;"
                "add    96(%4), %3;"
                "adc    104(%4), %3;"
                "adc    112(%4), %3;"
                "adc    120(%4), %3;"
                "adc    $0, %3;"
                : "=r"(sum), "=r"(sum1), "=r"(sum2), "=r"(sum3)
                : "r"(p), "0"(sum), "1"(sum1), "2"(sum2), "3"(sum3)
            );
            len -= 128;
            p += 128;
        }

        /* Combine the four 64 bit sums into a single 33 bit sum */
        asm volatile
        (
            "add    %3, %1;"
            "adc    $0, %1;"
            "add    %2, %0;"
            "adc    $0, %0;"
            "add    %1, %0;"
            "adc    $0, %0;"
            "mov    %k0, %k1;"
            "shr    $32, %0;"
            "add    %1, %0;"
            : "=r"(sum), "=r"(sum1)
            : "r"(sum2), "r"(sum3), "0"(sum), "1"(sum1)
        );
    }

    if (len & 64)
    {
        uint32_t *ptr = (uint32_t *)p;
        sum += (uint64_t)ptr[0]  + (uint64_t)ptr[1]  + (uint64_t)ptr[2]  + (uint64_t)ptr[3] +
               (uint64_t)ptr[4]  + (uint64_t)ptr[5]  + (uint64_t)ptr[6]  + (uint64_t)ptr[7] +
               (uint64_t)ptr[8]  + (uint64_t)ptr[9]  + (uint64_t)ptr[10] + (uint64_t)ptr[11] +
               (uint64_t)ptr[12] + (uint64_t)ptr[13] + (uint64_t)ptr[14] + (uint64_t)ptr[15];
        p += 64;
    }

    if (len & 32)
    {
        uint32_t *ptr = (uint32_t *)p;
        sum += (uint64_t)ptr[0] + (uint64_t)ptr[1] + (uint64_t)ptr[2] + (uint64_t)ptr[3] +
               (uint64_t)ptr[4] + (uint64_t)ptr[5] + (uint64_t)ptr[6] + (uint64_t)ptr[7];
        p += 32;
    }

    if (len & 16)
    {
        uint32_t *ptr = (uint32_t *)p;
        sum += (uint64_t)ptr[0] + (uint64_t)ptr[1] + (uint64_t)ptr[2] + (uint64_t)ptr[3];
        p += 16;
    }

    if (len & 8)
    {
        uint32_t *ptr = (uint32_t *)p;
        sum += (uint64_t)ptr[0] + (uint64_t)ptr[1];
        p += 8;
    }

    if (len & 4)
    {
        sum += *(uint32_t *)p;
        p += 4;
    }

    if (len & 2)
    {
        sum += *(uint16_t *)p;
        p += 2;
    }

    if (len & 1)
    {
        sum += *(uint8_t *)p;
        p += 1;
    }

    return sum;
}

#endif /* EXANIC_CHECKSUM_AMD64_H */
