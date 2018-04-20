/**
 * \file
 * \brief Exasock private socket options and message flags
 */
#ifndef EXASOCK_API_SOCKET_H
#define EXASOCK_API_SOCKET_H

#include <sys/socket.h>

/**
 * \brief Exasock private socket option level
 *
 * To manipulate socket options at Exasock level (i.e. manipulate an Exasock
 * private socket option specified in this file) the level argument of
 * setsockopt()/getsockopt() needs to be specified as SOL_EXASOCK.
 */
#define SOL_EXASOCK 0x200

/**
 * \brief Exasock socket option for disabling acceleration on the socket
 *
 * Disabling of acceleration on a socket is not allowed if the socket has
 * already been accelerated (either by binding it to an ExaNIC interface
 * or joining a multicast group with an ExaNIC interface). Once acceleration
 * has been disabled on the socket, it can no longer be re-enabled. If any of
 * above rules is not followed setsocketopt() fails with EPERM error.
 *
 * This is Exasock private socket level option (the level argument of
 * setsockopt()/getsockopt() needs to be specified as SOL_EXASOCK).
 * This option takes an int value. This is a Boolean option.
 */
#define SO_EXA_NO_ACCEL     1

/**
 * \brief Exasock socket option for passively listening to multicast data
 * arriving on an ExaNIC interface
 *
 * Setting SO_EXA_MCAST_LISTEN has a similar effect to setting the
 * IP_ADD_MEMBERSHIP socket option with an ExaNIC interface specified in
 * imr_address or imr_ifindex.  However the SO_EXA_MCAST_LISTEN option does not
 * result in multicast joins being sent.  Also, with SO_EXA_MCAST_LISTEN, it is
 * possible to allow receiving the multicast group's data from any local ExaNIC
 * interface (if imr_address is set to INADDR_ANY and imr_ifindex is set to 0).
 * If such a wildcard is specified to IP_ADD_MEMBERSHIP, the kernel will
 * arbitrarily choose one interface and kernel bypass acceleration will be lost.
 *
 * This option should not be used together with IP_ADD_MEMBERSHIP on the same
 * socket, but rather as an alternative, if needed.  If IGMP joins are still
 * required, additional steps need to be taken to make sure the multicast group
 * has been joined, for example joining the group in another process.
 *
 * Due to the design of exasock, an application should not configure more than
 * one accelerated socket receiving the same multicast group from the same
 * interface.  (Only one socket will receive the data.)
 *
 * SO_EXA_MCAST_LISTEN is not allowed if acceleration has already been disabled
 * on the socket.  (setsockopt() will fail with EPERM.)
 *
 * This is Exasock private socket level option (the level argument of
 * setsockopt() needs to be specified as SOL_EXASOCK).
 *
 * The argument is ip_mreqn structure (or alternatively ip_mreq structure), just
 * like in the case of IP_ADD_MEMBERSHIP socket option:
 * - imr_multiaddr: Contains the address of the multicast group. It must be a
 *                  valid multicast address (or setsockopt() fails with the
 *                  error EINVAL).
 * - imr_address:   The address of the local ExaNIC interface from which the
 *                  socket wants to receive the multicast data; if it is equal
 *                  to INADDR_ANY, the socket will receive the multicast data
 *                  arriving through any of local ExaNIC interfaces.
 * - imr_ifindex:   The interface index of the ExaNIC interface to receive data
 *                  from, or 0 to indicate any ExaNIC interface.
 */
#define SO_EXA_MCAST_LISTEN 2

/**
 * \brief Disable acceleration on the socket
 *
 * This is a helper function for disabling acceleration on the socket. This
 * function can be used instead of calling directly setsockopt() with
 * SO_EXA_NO_ACCEL Exasock private socket option.
 * Disabling of acceleration on a socket is not allowed if the socket has
 * already been accelerated (either by binding it to an ExaNIC interface
 * or joining a multicast group with an ExaNIC interface). In such a case
 * this function fails with EPERM error.
 *
 * \param[in]   fd
 *      Exasock socket to disable acceleration on
 *
 * \return 0 on success, or -1 if an error occurred
 */
static inline int exasock_disable_acceleration(int fd)
{
    int disable = 1;

    return setsockopt(fd, SOL_EXASOCK, SO_EXA_NO_ACCEL, &disable,
                      sizeof(disable));
}

/**
 * \brief Exasock message flag to mark the message to be sent as a fake one.
 *
 * Setting this flag in send(), sendto() or sendmsg() results in triggering
 * a dummy send, which purpose is solely to keep the send code path in cache.
 * A message passed to this call will be discarded in the end.
 * Calling a send() with MSG_EXA_WARM flag set on an accelerated socket shortly
 * before invoking this call for sending an actual data helps in minimizing
 * latency of getting the data on the wire.
 *
 * Ideally the length of the fake message should be equal (or at least similar)
 * to the length of a subsequent real message to be sent.
 */
#define MSG_EXA_WARM    0x100000

#endif /* EXASOCK_API_SOCKET_H */
