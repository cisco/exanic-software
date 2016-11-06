#ifndef LOCK_H_808890E5B04A4EEE95EBF703CB6E6A6A
#define LOCK_H_808890E5B04A4EEE95EBF703CB6E6A6A

/* Return 1 if lock successful, 0 if unsuccessful */
static inline int
exa_trylock(volatile uint32_t *flag)
{
    return __sync_lock_test_and_set(flag, 1) == 0;
}

static inline void
exa_lock(volatile uint32_t *flag)
{
    while (__sync_lock_test_and_set(flag, 1))
    {
        while (*flag)
        {
#ifdef __amd64__
            __asm__("pause" ::: "memory");
#endif
#ifdef __powerpc64__
            __asm__("or 1, 1, 1" ::: "memory");
            __asm__("or 2, 2, 2" ::: "memory");
#endif
        }
    }
}

static inline void
exa_unlock(volatile uint32_t *flag)
{
    assert(*flag);
    __sync_lock_release(flag);
}

#endif /* LOCK_H_808890E5B04A4EEE95EBF703CB6E6A6A */
