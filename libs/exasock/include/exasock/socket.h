/**
 * \file
 * \brief Exasock private socket options
 */
#ifndef EXASOCK_API_SOCKET_H
#define EXASOCK_API_SOCKET_H

#include <sys/socket.h>

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

#endif /* EXASOCK_API_SOCKET_H */
