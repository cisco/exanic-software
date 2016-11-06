#ifndef CLOCK_SYNC_PHC_SYS_H
#define CLOCK_SYNC_PHC_SYS_H

struct phc_sys_sync_state;

struct phc_sys_sync_state *init_phc_sys_sync(const char *name, int fd,
        int tai_offset, int auto_tai_offset, int64_t offset);
enum sync_status poll_phc_sys_sync(struct phc_sys_sync_state *state);
void shutdown_phc_sys_sync(struct phc_sys_sync_state *state);

#endif /* CLOCK_SYNC_PHC_SYS_H */
