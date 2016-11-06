#ifndef OVERRIDE_H_03B7ED26304E40B7A8A24A6DD82D33E2
#define OVERRIDE_H_03B7ED26304E40B7A8A24A6DD82D33E2

/* When using the LD_PRELOAD sockets interface, temporarily turn off
 * override of certain socket functions.
 * This is needed because libexanic calls some of those functions. */
void exasock_override_off(void);
void exasock_override_on(void);
bool exasock_override_is_off(void);

#endif /* OVERRIDE_H_03B7ED26304E40B7A8A24A6DD82D33E2 */
