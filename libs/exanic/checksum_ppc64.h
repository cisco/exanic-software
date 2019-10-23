#ifndef EXANIC_CHECKSUM_PPC64_H
#define EXANIC_CHECKSUM_PPC64_H

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
                "ld    %%r15, 0(%4);"
                "ld    %%r16, 8(%4);"
                "ld    %%r17, 16(%4);"
                "ld    %%r18, 24(%4);"
                "addc  %0, %0, %%r15;"
                "adde  %0, %0, %%r16;"
                "adde  %0, %0, %%r17;"
                "adde  %0, %0, %%r18;"
                "addze %0, %0;"

                "ld    %%r15, 32(%4);"
                "ld    %%r16, 40(%4);"
                "ld    %%r17, 48(%4);"
                "ld    %%r18, 56(%4);"
                "addc  %1, %1, %%r15;"
                "adde  %1, %1, %%r16;"
                "adde  %1, %1, %%r17;"
                "adde  %1, %1, %%r18;"
                "addze %1, %1;"

                "ld    %%r15, 64(%4);"
                "ld    %%r16, 72(%4);"
                "ld    %%r17, 80(%4);"
                "ld    %%r18, 88(%4);"
                "addc  %2, %2, %%r15;"
                "adde  %2, %2, %%r16;"
                "adde  %2, %2, %%r17;"
                "adde  %2, %2, %%r18;"
                "addze %2, %2;"

                "ld    %%r15, 96(%4);"
                "ld    %%r16, 104(%4);"
                "ld    %%r17, 112(%4);"
                "ld    %%r18, 120(%4);"
                "addc  %3, %3, %%r15;"
                "adde  %3, %3, %%r16;"
                "adde  %3, %3, %%r17;"
                "adde  %3, %3, %%r18;"
                "addze %3, %3;"

                : "=r"(sum), "=r"(sum1), "=r"(sum2), "=r"(sum3)
                : "r"(p), "0"(sum), "1"(sum1), "2"(sum2), "3"(sum3)
                : "r15", "r16", "r17", "r18"
            );
            len -= 128;
            p += 128;
        }

        /* Combine the four 64 bit sums into a single 33 bit sum */
        asm volatile
        (
            "addc   %1, %1, %3;"
            "addze  %1, %1;"
            "addc   %0, %0, %2;"
            "addze  %0, %0;"
            "addc   %0, %0, %1;"
            "addze  %0, %0;"
            "inslwi %1, %0, 32, 0;"
            "srdi   %0, %0, 32;"
            "add    %0, %0, %1;"
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

#endif /* EXANIC_CHECKSUM_PPC64_H */
