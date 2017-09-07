#ifndef EXANIC_CLOCK_SYNC_EXANIC_PPS_H
#define EXANIC_CLOCK_SYNC_EXANIC_PPS_H

enum pps_type { PPS_DIFFERENTIAL, PPS_SINGLE_ENDED };
enum pps_edge { PPS_RISING_EDGE, PPS_FALLING_EDGE };

struct exanic_pps_sync_state;

struct exanic_pps_sync_state *init_exanic_pps_sync(const char *name, int clkfd,
        exanic_t *exanic, enum pps_type pps_type, int pps_termination_disable,
        enum pps_edge pps_edge, int tai_offset, int auto_tai_offset,
        int64_t offset, unsigned interval);
enum sync_status poll_exanic_pps_sync(struct exanic_pps_sync_state *state);
void shutdown_exanic_pps_sync(struct exanic_pps_sync_state *state);

#endif /* EXANIC_CLOCK_SYNC_EXANIC_PPS_H */
