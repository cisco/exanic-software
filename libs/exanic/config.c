#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "exanic.h"
#include "config.h"
#include "pcie_if.h"
#include "ioctl.h"
#include "port.h"
#include "util.h"
#include "exanic_bonding.h"

static int check_exanic_and_port_number(exanic_t *exanic, int port_number)
{
    if (exanic_get_function_id(exanic) != EXANIC_FUNCTION_NIC &&
            exanic_get_function_id(exanic) != EXANIC_FUNCTION_DEVKIT &&
                exanic_get_function_id(exanic) != EXANIC_FUNCTION_PTP_GM)
    {
        exanic_err_printf("not a network interface");
        return -1;
    }
    if (port_number < 0 || port_number >= exanic->num_ports)
    {
        exanic_err_printf("invalid port number");
        return -1;
    }
    if (!exanic_port_rx_usable(exanic, port_number))
    {
        exanic_err_printf("port does not support RX");
        return -1;
    }
    if (exanic->if_index[port_number] == 0)
    {
        exanic_err_printf("interface not available");
        return -1;
    }
    /* Ports which can receive but not send are allowed */
    return 0;
}

static int netlink_request(void *request, size_t request_len,
                           void *reply, size_t *reply_len)
{
    int fd;
    ssize_t ret;

    fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (fd == -1)
    {
        exanic_err_printf("netlink socket error: %s\n", strerror(errno));
        return -1;
    }

    ret = send(fd, request, request_len, 0);
    if (ret == -1)
    {
        exanic_err_printf("netlink send error: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    ret = recv(fd, reply, *reply_len, 0);
    if (ret == -1)
    {
        exanic_err_printf("netlink recv error: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    *reply_len = ret;

    close(fd);
    return 0;
}

int exanic_get_interface_addr(exanic_t *exanic, int port_number,
                              exanic_if_addr_t *exa_addr)
{
    struct ifaddrs *ifaddrs;
    struct ifaddrs *ifa;
    char ifname[IF_NAMESIZE];

    if (check_exanic_and_port_number(exanic, port_number) == -1)
        return -1;

    if (exanic_get_interface_name(exanic, port_number, ifname, sizeof(ifname)) == -1)
        return -1;

    if (getifaddrs(&ifaddrs) == -1) {
        exanic_err_printf("getifaddrs failed");
        return -1;
    }

    for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next)
    {
        struct sockaddr_in *addr;
        struct sockaddr_in *broadaddr;
        struct sockaddr_in *netmask;

        if (ifa->ifa_addr == NULL || strcmp(ifa->ifa_name, ifname) != 0)
            continue;

        if (ifa->ifa_addr->sa_family != AF_INET)
            continue;

        /* Return first entry found for our interface */
        addr = (struct sockaddr_in *)ifa->ifa_addr;
        broadaddr = (struct sockaddr_in *)ifa->ifa_broadaddr;
        netmask = (struct sockaddr_in *)ifa->ifa_netmask;

        memset(exa_addr, 0, sizeof(exanic_if_addr_t));
        exa_addr->address = addr->sin_addr.s_addr;
        if (broadaddr != NULL)
            exa_addr->broadcast = broadaddr->sin_addr.s_addr;
        if (netmask != NULL)
            exa_addr->netmask = netmask->sin_addr.s_addr;

        freeifaddrs(ifaddrs);
        return 0;
    }

    freeifaddrs(ifaddrs);
    exanic_err_printf("interface has no address assigned");
    return -1;
}

int exanic_get_interface_name(exanic_t *exanic, int port_number, char *name,
                              size_t name_len)
{
    char buf[IF_NAMESIZE];

    if (check_exanic_and_port_number(exanic, port_number) == -1)
        return -1;

    if (if_indextoname(exanic->if_index[port_number], buf) == NULL)
    {
        exanic_err_printf("could not get interface name: %s", strerror(errno));
        return -1;
    }

    snprintf(name, name_len, "%s", buf);

    return 0;
}

int exanic_get_interface_index(exanic_t *exanic, int port_number)
{
    if (check_exanic_and_port_number(exanic, port_number) == -1)
        return -1;

    return exanic->if_index[port_number];
}

int exanic_find_port_by_ip_addr(in_addr_t addr, char *device,
                                size_t device_len, int *port_number)
{
    struct ifaddrs *ifaddrs;
    struct ifaddrs *ifa;
    int ret;

    if (getifaddrs(&ifaddrs) == -1) {
        exanic_err_printf("getifaddrs failed");
        return -1;
    }

    for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;

        if (ifa->ifa_addr->sa_family != AF_INET)
            continue;

        if (((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr != addr)
            continue;

        /* Interface found, now look up the exanic device and port number */
        ret = exanic_find_port_by_interface_name(ifa->ifa_name, device,
                device_len, port_number);
        freeifaddrs(ifaddrs);
        return ret;
    }

    freeifaddrs(ifaddrs);
    exanic_err_printf("interface not found");
    return -1;
}

int exanic_find_port_by_interface_name(const char *name, char *device,
                                       size_t device_len, int *port_number)
{
    struct ifreq ifr;
    struct ethtool_drvinfo drvinfo;
    struct exaioc_ifinfo exainfo;
    int fd;

    /* If it's a bond, just return port 0 with the device
     * node name filled out.
     */
    if (exanic_interface_is_exabond(name))
    {
        snprintf(device, device_len, "/dev/exabond-%s", name);
        *port_number = 0;
        return 0;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        exanic_err_printf("Failed to create socket fd : %s", strerror(errno));
        return -1;
    }

    /* Check that the interface is an exanic interface */
    memset(&ifr, 0, sizeof(ifr));
    memset(&drvinfo, 0, sizeof(drvinfo));
    drvinfo.cmd = ETHTOOL_GDRVINFO;
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    ifr.ifr_data = (void *)&drvinfo;

    if (ioctl(fd, SIOCETHTOOL, &ifr) == -1)
    {
        exanic_err_printf("interface not found: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (strcmp(drvinfo.driver, "exanic") != 0)
    {
        exanic_err_printf("not an ExaNIC interface");
        close(fd);
        return -1;
    }

    /* Get device name and port number using ioctl */
    memset(&ifr, 0, sizeof(ifr));
    memset(&exainfo, 0, sizeof(exainfo));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    ifr.ifr_data = (void *)&exainfo;

    if (ioctl(fd, EXAIOCGIFINFO, &ifr) == -1)
    {
        exanic_err_printf("EXAIOCGIFINFO ioctl failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    strncpy(device, exainfo.dev_name, device_len - 1);
    device[device_len - 1] = '\0';
    *port_number = exainfo.port_num;

    close(fd);
    return 0;
}

ssize_t exanic_get_all_ports(exanic_port_info_t *table, size_t table_size)
{
    struct if_nameindex *ifnames;
    size_t i, nports;

    ifnames = if_nameindex();
    if (ifnames == NULL)
    {
        exanic_err_printf("if_nameindex failed: %s\n", strerror(errno));
        return -1;
    }

    nports = 0;

    for (i = 0; ifnames[i].if_index != 0; i++)
    {
        if (nports * sizeof(exanic_port_info_t) >= table_size)
            break;

        if (exanic_find_port_by_interface_name(ifnames[i].if_name,
                    table[nports].device, sizeof(table[nports].device),
                    &table[nports].port_number) == 0)
            nports++;
    }

    if_freenameindex(ifnames);
    return nports;
}

ssize_t exanic_get_ip_routes(exanic_t *exanic, int port_number,
                             exanic_ip_route_t *table, size_t table_len)
{
    struct {
        struct nlmsghdr nl;
        struct rtmsg rt;
    } request;
    char reply[16384];
    size_t reply_len;
    struct nlmsghdr *nlh;
    int nll;
    size_t num_routes = 0;

    if (check_exanic_and_port_number(exanic, port_number) == -1)
        return -1;

    memset(&request, 0, sizeof(request));
    request.nl.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    request.nl.nlmsg_type = RTM_GETROUTE;
    request.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.rt.rtm_family = AF_INET;

    reply_len = sizeof(reply);
    if (netlink_request(&request, sizeof(request), reply, &reply_len) == -1)
        return -1;

    /* Loop through reply messages to construct the route table */
    for (nlh = (struct nlmsghdr *)reply, nll = reply_len;
            NLMSG_OK(nlh, nll); nlh = NLMSG_NEXT(nlh, nll))
    {
        struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nlh);
        struct rtattr *rta;
        int rtl;
        int rta_oif = 0;
        struct in_addr rta_dst = { 0 };
        struct in_addr rta_gateway = { 0 };

        if (rtm->rtm_type != RTN_UNICAST)
            continue;

        for (rta = RTM_RTA(rtm), rtl = RTM_PAYLOAD(nlh);
                RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl))
        {
            switch (rta->rta_type)
            {
            case RTA_DST:
                {
                    struct in_addr *a = RTA_DATA(rta);
                    rta_dst = *a;
                    break;
                }
            case RTA_OIF:
                {
                    int *n = RTA_DATA(rta);
                    rta_oif = *n;
                    break;
                }
            case RTA_GATEWAY:
                {
                    struct in_addr *a = RTA_DATA(rta);
                    rta_gateway = *a;
                    break;
                }
            }
        }

        if (rta_oif != exanic->if_index[port_number])
            continue;

        if (num_routes * sizeof(exanic_ip_route_t) >= table_len)
            break;

        /* Add entry to route table */
        table[num_routes].destination = rta_dst.s_addr;
        table[num_routes].netmask = htonl(~(uint32_t)0 << (32 - rtm->rtm_dst_len));
        table[num_routes].gateway = rta_gateway.s_addr;
        num_routes++;
    }

    /* TODO: filter and sort routes based on ip rules */

    return num_routes;
}
