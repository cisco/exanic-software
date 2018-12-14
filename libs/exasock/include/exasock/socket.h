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
 * Using a zero value for this socket option will enable acceleration
 * when global acceleration is disabled. Note that even in this case,
 * manually disabling acceleration on the socket is permanent (as above).
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

/** \brief Exasock socket option for enabling Accelerated TCP Engine on the
 * socket
 *
 * An exasock accelerated socket configured with SO_EXA_ATE will use an ExaNIC
 * Accelerated TCP Engine (ATE) for transmitting TCP segments. This option takes
 * an integer value which is an ID of ExaNIC ATE to be used for this socket (-1
 * for disabled ATE). Each ExaNIC interface has its own range of available ATE
 * IDs, provided it does support the ATE feature. Each Accelerated TCP Engine
 * may be used only by one socket at a time. The ATE ID value given in this
 * option should specify an available ATE on the ExaNIC interface on which the
 * connection is to be established.
 *
 * Enabling of ATE is allowed only for TCP sockets (SOCK_STREAM type in AF_INET
 * domain) and needs to take place before the socket gets connected. It is also
 * not allowed if exasock acceleration has already been disabled on the socket.
 * If any of above rules is not followed setsocketopt() fails with EPERM error.
 *
 * Enabling of ATE on passive (listening) sockets is currently not supported.
 * An attempt to invoke listen() on an ATE-enabled socket will fail with the
 * error EOPNOTSUPP.
 *
 * Connecting of an ATE-enabled socket (invoking connect() call) will fail if
 * the socket is not able to use the requested ExaNIC Accelerated TCP Engine.
 * This may happen if:
 *  - the connection is not going to use an ExaNIC interface or the connection
 *    is not going to be accelerated (connect() fails with EOPNOTSUPP), or
 *  - the connection is going to use an ExaNIC interface which does not support
 *    the ATE feature (connect() fails with EOPNOTSUPP), or
 *  - ExaNIC Accelerated TCP Engine of the given ID is not available on the
 *    interface (connect() fails with EBUSY if the ATE is currently used by
 *    another socket, or with EINVAL if ATE ID is invalid).
 *
 * This is Exasock private socket level option (the level argument of
 * setsockopt()/getsockopt() needs to be specified as SOL_EXASOCK).
 */
#define SO_EXA_ATE          3

/**
 * \brief Disable acceleration on the socket
 *
 * This is a helper function for disabling acceleration on the socket. This
 * function can be used instead of calling directly setsockopt() with
 * \ref SO_EXA_NO_ACCEL Exasock private socket option.
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
 * \brief Connect the socket using ExaNIC Accelerated TCP Engine
 *
 * This is a helper function for enabling ExaNIC Accelerated TCP Engine on the
 * socket and connecting it to the specified address.
 * This function can be used instead of calling directly setsockopt() with
 * \ref SO_EXA_ATE Exasock private socket option followed by connect().
 * Please refer to \ref SO_EXA_ATE description for more details.
 *
 * \param[in]   fd
 *      Exasock socket to enable ATE on
 * \param[in]   ate_id
 *      ID of Accelerated TCP Engine to be used for the socket
 * \param[in]   addr
 *      Pointer to a generic socket address to connect to
 * \param[in]   addrlen
 *      Size of address
 *
 * \return 0 on success, or -1 if an error occurred
 */
static inline int exasock_ate_connect(int fd, int ate_id,
                                      const struct sockaddr *addr,
                                      socklen_t addrlen)
{
    int err;

    if (ate_id < 0)
    {
        errno = EINVAL;
        return -1;
    }

    err = setsockopt(fd, SOL_EXASOCK, SO_EXA_ATE, &ate_id, sizeof(ate_id));
    if (err)
        return err;

    return connect(fd, addr, addrlen);
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
 *
 * An attempt to send a message with MSG_EXA_WARM flag on not accelerated socket
 * is not effective. Exasock will return immediately without entering the send
 * code path at all.
 */
#define MSG_EXA_WARM    0x100000

#endif /* EXASOCK_API_SOCKET_H */
