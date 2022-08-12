/**
 * \file
 * \brief Exasock extension API
 */
#ifndef EXASOCK_API_EXTENSIONS_H
#define EXASOCK_API_EXTENSIONS_H

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

#define EXASOCK_VERSION(maj,min,rev) (((maj) << 16) + ((min) << 8) + (rev))

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Determine whether the current application is being run with Exasock.
 *
 * \return 1 if loaded, 0 if not
 */
int exasock_loaded(void);

/**
 * \brief Prints ExaSock library latencies
 *
 */
void print_exasock_latencies(void);

/**
 * \brief Clears ExaSock library latency data
 *
 */
void clear_latencies(void);

/**
 * \brief Determine the version of Exasock the current application is running with
 *
 * \return Version code
 */
uint32_t exasock_version_code(void);

/**
 * \brief Returns the version of Exasock library in string form
 *
 * \return Version string
 */
const char *exasock_version_text(void);

/**
 * \brief Look up the ExaNIC device name and port used by an Exasock TCP socket
 *
 * \param[in]   fd
 *      Exasock TCP socket
 * \param[out]  dev
 *      Pointer to a buffer to be populated with the ExaNIC device name
 * \param[in]   dev_len
 *      Length of buffer
 * \param[out]  port_num
 *      Pointer to an int to be populated with the port number
 *
 * \return 0 on success, or -1 if an error occurred
 */
int exasock_tcp_get_device(int fd, char *dev, size_t dev_len, int *port_num);

/**
 * \brief Prepare headers for an Exasock TCP connection
 *
 * This function provides the Ethernet, IP and TCP headers for the next
 * packet on the Exasock TCP connection.
 * The header is populated with the current TCP sequence numbers.
 * The caller will need to update it with the correct packet length and
 * checksum values.
 *
 * \param[in]   fd
 *      Exasock TCP socket
 * \param[out]  buf
 *      Pointer to a buffer to hold the header
 * \param[in]   len
 *      Length of buffer
 * \param[in]   offset
 *      Currently unused, must be set to 0
 * \param[in]   flags
 *      Currently unused, must be set to 0
 *
 * \return Length of header, or -1 if an error occurred
 */
ssize_t exasock_tcp_build_header(int fd, void *buf, size_t len, size_t offset,
                                 int flags);

/**
 * \brief Update IP header with a new packet length
 *
 * This is a helper function for updating the IP length and checksum fields
 * in a header provided by \ref exasock_tcp_build_header.
 *
 * \param[in]   hdr
 *      Pointer to a buffer containing the header
 * \param[in]   hdr_len
 *      Header length in bytes
 * \param[in]   data_len
 *      Data length in bytes
 *
 * \return 0 on success, or -1 if an error occurred
 */
int exasock_tcp_set_length(void *hdr, size_t hdr_len, size_t data_len);

/**
 * \brief Update TCP header checksum
 *
 * This is a helper function for updating the TCP checksum field in a header
 * provided by \ref exasock_tcp_build_header.
 *
 * \param[in]   hdr
 *      Pointer to a buffer containing the header
 * \param[in]   hdr_len
 *      Header length in bytes
 * \param[in]   data
 *      Pointer to a buffer containing the payload data
 * \param[in]   data_len
 *      Data length in bytes
 *
 * \return 0 on success, or -1 if an error occurred
 */
int exasock_tcp_calc_checksum(void *hdr, size_t hdr_len,
                              const void *data, size_t data_len);

/**
 * \brief Update TCP retransmit buffer
 *
 * This function adds the provided data to the TCP retransmit buffer and
 * advances the send sequence number.
 *
 * \param[in]   fd
 *      Exasock TCP socket
 * \param[in]   buf
 *      Pointer to a buffer containing the sent data
 * \param[in]   len
 *      Data length in bytes
 */
int exasock_tcp_send_advance(int fd, const void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* EXASOCK_API_EXTENSIONS_H */
