#ifndef EXASOCK_RWLOCK_H
#define EXASOCK_RWLOCK_H

struct exa_rwlock
{
    uint32_t __lock;
};

typedef struct exa_rwlock exa_rwlock_t;

static inline void
exa_relax_thread()
{
#ifdef __amd64__
            __asm__("pause" ::: "memory");
#endif
#ifdef __powerpc64__
            __asm__("or 1, 1, 1" ::: "memory");
            __asm__("or 2, 2, 2" ::: "memory");
#endif
}

static inline void
exa_rwlock_init(struct exa_rwlock *lock)
{
    *(volatile uint32_t *)lock = 0;
}

/* Return 1 if lock successful, 0 if unsuccessful */
static inline int
exa_write_trylock(struct exa_rwlock *lock)
{
    uint32_t tmp = *(volatile uint32_t *)lock;
    uint8_t tkt = tmp >> 16;
    uint8_t nxt = tkt + 1;
    uint32_t val = ((uint32_t)tkt << 16) | ((uint32_t)tkt << 8) | tkt;
    uint32_t newval = ((uint32_t)nxt << 16) | ((uint32_t)tkt << 8) | tkt;

    return (__sync_val_compare_and_swap((uint32_t *)lock, val, newval) == val);
}

static inline void
exa_write_lock(struct exa_rwlock *lock)
{
    uint8_t tkt = __sync_fetch_and_add((uint8_t *)lock + 2, 1);
    uint16_t val = ((uint16_t)tkt << 8) | tkt;

    while (*(volatile uint16_t *)lock != val)
        exa_relax_thread();
}

/* Return 1 if the lock is held for writing */
static inline int
exa_write_locked(struct exa_rwlock *lock)
{
    uint32_t tmp = *(volatile uint32_t *)lock;
    uint8_t wr = tmp;
    uint8_t rd = tmp >> 8;
    uint8_t tkt = tmp >> 16;

    return (tkt != wr && wr == rd);
}

static inline void
exa_write_unlock(struct exa_rwlock *lock)
{
    uint32_t tmp = *(volatile uint32_t *)lock;
    uint8_t wr = tmp;
    uint8_t rd = tmp >> 8;

    assert(exa_write_locked(lock));

    __asm__("" ::: "memory");

    *(uint16_t *)lock = (uint8_t)(rd + 1) << 8 | (uint8_t)(wr + 1);
}

/* Atomically release the write lock and acquire the read lock */
static inline void
exa_rwlock_downgrade(struct exa_rwlock *lock)
{
    assert(exa_write_locked(lock));
    __sync_add_and_fetch((uint8_t *)lock + 1, 1);
}

/* Return 1 if lock successful, 0 if unsuccessful */
static inline int
exa_read_trylock(struct exa_rwlock *lock)
{
    uint32_t tmp = *(volatile uint32_t *)lock;
    uint8_t wr = tmp;
    uint8_t tkt = tmp >> 16;
    uint8_t nxt = tkt + 1;
    uint32_t val = ((uint32_t)tkt << 16) | ((uint32_t)tkt << 8) | wr;
    uint32_t newval = ((uint32_t)nxt << 16) | ((uint32_t)nxt << 8) | wr;

    return (__sync_val_compare_and_swap((uint32_t *)lock, val, newval) == val);
}

static inline void
exa_read_lock(struct exa_rwlock *lock)
{
    uint8_t tkt = __sync_fetch_and_add((uint8_t *)lock + 2, 1);
    uint8_t nxt = tkt + 1;

    for (uint32_t t = 1; *((volatile uint8_t *)lock + 1) != tkt; t++)
    {
        exa_relax_thread();
        if ((t & 0xFFFF) == 0)
            sched_yield();
    }

    *((uint8_t *)lock + 1) = nxt;
}

/* Return 1 if the lock is held for reading */
static inline int
exa_read_locked(struct exa_rwlock *lock)
{
    uint32_t tmp = *(volatile uint32_t *)lock;
    uint8_t wr = tmp;
    uint8_t rd = tmp >> 8;
    uint8_t tkt = tmp >> 16;

    return ((uint8_t)(tkt + 1) != rd && rd != wr);
}

static inline void
exa_read_unlock(struct exa_rwlock *lock)
{
    assert(exa_read_locked(lock));
    __sync_add_and_fetch((uint8_t *)lock, 1);
}

#endif /* EXASOCK_RWLOCK_H */
