#ifndef EXANIC_CLOCK_SYNC_PHC_PHC_H
#define EXANIC_CLOCK_SYNC_PHC_PHC_H

struct phc_phc_sync_state;

struct phc_phc_sync_state *init_phc_phc_sync(const char *name,
        int clkfd, const char *name_src, int clkfd_src);
enum sync_status poll_phc_phc_sync(struct phc_phc_sync_state *state);
void shutdown_phc_phc_sync(struct phc_phc_sync_state *state);

#endif /* EXANIC_CLOCK_SYNC_PHC_PHC_H */
