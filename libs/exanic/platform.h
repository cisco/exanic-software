#ifndef _PLATFORM_H_722B3A01DE3F709432A8C51CCB4265C8
#define _PLATFORM_H_722B3A01DE3F709432A8C51CCB4265C8

static inline void iowb()
{
#if defined(__amd64__)
    asm volatile ("sfence" ::: "memory");
#elif defined(__powerpc__)
    asm volatile ("eieio" ::: "memory");
#elif defined(__i386__)
#warning "NOTICE: 32-bit x86 system detected, performance may be degraded. Please contact support@exablaze.com for assistance."
    asm volatile ("sfence" ::: "memory");
#else
#error "This version of libexanic supports amd64 (x86_64) and powerpc platforms only; please contact support@exablaze.com for assistance."
#endif
}

#endif /* _PLATFORM_H_722B3A01DE3F709432A8C51CCB4265C8 */
