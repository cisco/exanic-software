#ifndef EXASOCK_COMMON_H
#define EXASOCK_COMMON_H

#define _GNU_SOURCE
#include <features.h>
#define __FAVOR_BSD

#ifndef CLOCK_MONOTONIC_COARSE
#define CLOCK_MONOTONIC_COARSE CLOCK_MONOTONIC
#endif

#ifdef __GNUC__
    #define EXPECT_TRUE(x)  __builtin_expect(!!(x),1)
    #define EXPECT_FALSE(x) __builtin_expect((x),0)
#else
    #define EXPECT_TRUE(x)  (x)
    #define EXPECT_FALSE(x) (x)
#endif

#endif /* EXASOCK_COMMON_H */
