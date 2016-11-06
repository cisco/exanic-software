#ifndef CLOCK_SYNC_SYS_PHC_H
#define CLOCK_SYNC_SYS_PHC_H

struct sys_phc_sync_state;

struct sys_phc_sync_state *init_sys_phc_sync(const char *name, int fd,
        exanic_t *exanic_src, int tai_offset, int auto_tai_offset,
        int64_t offset);
enum sync_status poll_sys_phc_sync(struct sys_phc_sync_state *state);
void shutdown_sys_phc_sync(struct sys_phc_sync_state *state);

#endif /* CLOCK_SYNC_SYS_PHC_H */
