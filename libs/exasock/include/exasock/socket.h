/**
 * \file
 * \brief Exasock private socket options
 */
#ifndef EXASOCK_API_SOCKET_H
#define EXASOCK_API_SOCKET_H

/** \brief Exasock private socket option level
 *
 * To manipulate socket options at Exasock level (i.e. manipulate an Exasock
 * private socket option specified in this file) the level argument of
 * setsockopt()/getsockopt() needs to be specified as SOL_EXASOCK.
 */
#define SOL_EXASOCK 0x200

/** \brief Exasock private socket option for disabling acceleration on the socket
 *
 * Disabling of acceleration on a socket is not allowed if the socket has
 * already been accelerated (either by binding it to an ExaNIC interface
 * or joining a multicast group with an ExaNIC interface). Once acceleration
 * has been disabled on the socket, it can no longer be re-enabled. If any of
 * above rules is not followed setsocketopt() fails with EPERM error.
 * This is Exasock private socket level option (the level argument of
 * setsockopt()/getsockopt() needs to be specified as SOL_EXASOCK).
 * This option takes an int value. This is a Boolean option.
 */
#define SO_EXA_NO_ACCEL     1

#endif /* EXASOCK_API_SOCKET_H */
