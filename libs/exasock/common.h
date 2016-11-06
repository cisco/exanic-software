#define _GNU_SOURCE
#include <features.h>
#define __FAVOR_BSD

#ifndef CLOCK_MONOTONIC_COARSE
#define CLOCK_MONOTONIC_COARSE CLOCK_MONOTONIC
#endif
