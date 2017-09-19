/**
 * Kernel support for the ExaSock library
 * Copyright (C) 2011-2017 Exablaze Pty Ltd and its licensors
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/miscdevice.h>
#include <linux/inetdevice.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/file.h>
#include <linux/if_vlan.h>
#include <net/arp.h>
#include <net/netevent.h>

#include "../../libs/exasock/kernel/api.h"

#include "../exanic/exanic.h"
#include "exasock.h"
#include "exasock-stats.h"

static struct exasock_kernel_info *exasock_info_page;

static int exasock_net_event(struct notifier_block *notifier,
                             unsigned long event, void *ptr)
{
    switch (event)
    {
    case NETEVENT_NEIGH_UPDATE:
        {
            struct neighbour *neigh = ptr;
            if (neigh->tbl != &arp_tbl)
                break;
            exasock_dst_neigh_update(neigh);
            return NOTIFY_OK;
        }

    default:
        break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block exasock_net_notifier = {
    .notifier_call      = exasock_net_event
};

static int exasock_inetaddr_event(struct notifier_block *notifier,
                                  unsigned long event, void *ptr)
{
    struct in_ifaddr *ifa = ptr;

    switch (event)
    {
    case NETDEV_DOWN:
        exasock_dst_invalidate_src(ifa->ifa_address);
        break;

    default:
        break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block exasock_inetaddr_notifier = {
    .notifier_call      = exasock_inetaddr_event
};

static int exasock_dst_queue(uint32_t addr, uint32_t *src_addr,
                             const char __user *buf, size_t len)
{
    struct sk_buff *skb = NULL;
    int err;

    if (len > 0)
    {
        skb = alloc_skb(len + VLAN_ETH_HLEN, GFP_KERNEL);
        if (skb == NULL)
        {
            err = -ENOSPC;
            goto err_alloc_skb;
        }
        skb_reserve(skb, VLAN_ETH_HLEN);
        skb_put(skb, len);
        skb_reset_network_header(skb);

        if (copy_from_user(skb->data, buf, len) != 0)
        {
            err = -EFAULT;
            goto err_copy_from_user;
        }
    }

    return exasock_dst_insert(addr, src_addr, skb);

err_copy_from_user:
    kfree_skb(skb);
err_alloc_skb:
    return err;
}

/**
 * Each ExaSock socket maintains an open file descriptor to this device.
 */
static struct miscdevice exasock_dev;

static int exasock_dev_open(struct inode *inode, struct file *filp)
{
    filp->private_data = NULL;

    return 0;
}

static void exasock_socket_free(struct exasock_hdr *common)
{
    struct exasock_hdr_socket *socket = &common->socket;

    if (socket->domain == AF_INET && socket->type == SOCK_DGRAM)
    {
        exasock_udp_free((struct exasock_udp *)common);
        return;
    }
    else if (socket->domain == AF_INET && socket->type == SOCK_STREAM)
    {
        exasock_tcp_free((struct exasock_tcp *)common);
        return;
    }

    BUG();
}

static int exasock_dev_release(struct inode *inode, struct file *filp)
{
    void *priv = filp->private_data;
    enum exasock_type type;

    if (priv == NULL)
        return 0;

    type = *((enum exasock_type *)priv);

    switch (type)
    {
    case EXASOCK_TYPE_SOCKET:
        exasock_socket_free((struct exasock_hdr *)priv);
        return 0;
    case EXASOCK_TYPE_EPOLL:
        exasock_epoll_free((struct exasock_epoll *)priv);
        return 0;
    default:
        BUG();
    }
}

static int exasock_info_page_mmap(struct vm_area_struct *vma)
{
    if (vma->vm_flags & VM_WRITE)
        return -EACCES;

    return remap_vmalloc_range(vma, exasock_info_page, vma->vm_pgoff);
}

static int exasock_socket_mmap(struct exasock_hdr *common,
                               struct vm_area_struct *vma)
{
    struct exasock_hdr_socket *socket;

    if (common == NULL)
        return -EINVAL;

    if (common->type != EXASOCK_TYPE_SOCKET)
        return -EINVAL;

    socket = &common->socket;

    if (socket->domain != AF_INET)
        return -EINVAL;

    if (vma->vm_pgoff >= (EXASOCK_OFFSET_TX_BUFFER / PAGE_SIZE))
    {
        switch (socket->type)
        {
        case SOCK_STREAM:
            return exasock_tcp_tx_mmap((struct exasock_tcp *)common, vma);
        default:
            return -EINVAL;
        }
    }
    else if (vma->vm_pgoff >= (EXASOCK_OFFSET_RX_BUFFER / PAGE_SIZE))
    {
        switch (socket->type)
        {
        case SOCK_DGRAM:
            return exasock_udp_rx_mmap((struct exasock_udp *)common, vma);
        case SOCK_STREAM:
            return exasock_tcp_rx_mmap((struct exasock_tcp *)common, vma);
        default:
            return -EINVAL;
        }
    }
    else
    {
        switch (socket->type)
        {
        case SOCK_DGRAM:
            return exasock_udp_state_mmap((struct exasock_udp *)common, vma);
        case SOCK_STREAM:
            return exasock_tcp_state_mmap((struct exasock_tcp *)common, vma);
        default:
            return -EINVAL;
        }
    }
}

static int exasock_dev_mmap(struct file *filp, struct vm_area_struct *vma)
{
    void *priv = filp->private_data;

    if (vma->vm_pgoff >= (EXASOCK_OFFSET_EPOLL_STATE / PAGE_SIZE))
        return exasock_epoll_state_mmap((struct exasock_epoll *)priv, vma);
    else if (vma->vm_pgoff >= (EXASOCK_OFFSET_TX_BUFFER / PAGE_SIZE))
        return exasock_socket_mmap((struct exasock_hdr *)priv, vma);
    else if (vma->vm_pgoff >= (EXASOCK_OFFSET_RX_BUFFER / PAGE_SIZE))
        return exasock_socket_mmap((struct exasock_hdr *)priv, vma);
    else if (vma->vm_pgoff >= (EXASOCK_OFFSET_DST_USED_FLAGS / PAGE_SIZE))
        return exasock_dst_used_flags_mmap(vma);
    else if (vma->vm_pgoff >= (EXASOCK_OFFSET_DST_TABLE / PAGE_SIZE))
        return exasock_dst_table_mmap(vma);
    else if (vma->vm_pgoff >= (EXASOCK_OFFSET_SOCKET_STATE / PAGE_SIZE))
        return exasock_socket_mmap((struct exasock_hdr *)priv, vma);
    else
        return exasock_info_page_mmap(vma);
}

static long exasock_dev_ioctl(struct file *filp, unsigned int cmd,
                              unsigned long arg)
{
    if (_IOC_TYPE(cmd) != EXASOCK_IOCTL_TYPE)
        return -ENOTTY;

    switch (cmd)
    {
    case EXASOCK_IOCTL_SOCKET:
        {
            int sockfd;
            struct socket *sock;
            int err;

            if (copy_from_user(&sockfd, (void *)arg, sizeof(sockfd)) != 0)
                return -EFAULT;

            if (filp->private_data)
                return -EINVAL;

            sock = sockfd_lookup(sockfd, &err);
            if (sock == NULL)
                return err;

            if (sock->ops->family == AF_INET && sock->type == SOCK_DGRAM)
            {
                struct exasock_udp *udp = exasock_udp_alloc(sock, sockfd);
                if (IS_ERR(udp))
                {
                    sockfd_put(sock);
                    return PTR_ERR(udp);
                }
                else
                {
                    filp->private_data = udp;
                    return 0;
                }
            }
            else if (sock->ops->family == AF_INET && sock->type == SOCK_STREAM)
            {
                struct exasock_tcp *tcp = exasock_tcp_alloc(sock, sockfd);
                if (IS_ERR(tcp))
                {
                    sockfd_put(sock);
                    return PTR_ERR(tcp);
                }
                else
                {
                    filp->private_data = tcp;
                    return 0;
                }
            }
            else
            {
                sockfd_put(sock);
                return -EINVAL;
            }
        }

    case EXASOCK_IOCTL_BIND:
        {
            struct exasock_hdr *priv = filp->private_data;
            struct exasock_hdr_socket *socket;
            struct exasock_endpoint req;
            int err;

            if (copy_from_user(&req, (void *)arg, sizeof(req)) != 0)
                return -EFAULT;

            if (priv == NULL)
                return -EINVAL;

            if (priv->type != EXASOCK_TYPE_SOCKET)
                return -EINVAL;

            socket = &priv->socket;
            if (socket->domain == AF_INET && socket->type == SOCK_DGRAM)
            {
                err = exasock_udp_bind((struct exasock_udp *)priv,
                                       req.local_addr, &req.local_port);
                if (err)
                    return err;

                req.peer_addr = 0;
                req.peer_port = 0;
            }
            else if (socket->domain == AF_INET && socket->type == SOCK_STREAM)
            {
                err = exasock_tcp_bind((struct exasock_tcp *)priv,
                                       req.local_addr, &req.local_port);
                if (err)
                    return err;

                req.peer_addr = 0;
                req.peer_port = 0;
            }
            else
                return -EINVAL;

            if (copy_to_user((void *)arg, &req, sizeof(req)) != 0)
                return -EFAULT;

            return 0;
        }

    case EXASOCK_IOCTL_CONNECT:
        {
            struct exasock_hdr *priv = filp->private_data;
            struct exasock_hdr_socket *socket;
            struct exasock_endpoint req;
            int err;

            if (copy_from_user(&req, (void *)arg, sizeof(req)) != 0)
                return -EFAULT;

            if (priv == NULL)
                return -EINVAL;

            if (priv->type != EXASOCK_TYPE_SOCKET)
                return -EINVAL;

            socket = &priv->socket;
            if (socket->domain == AF_INET && socket->type == SOCK_DGRAM)
            {
                err = exasock_udp_connect((struct exasock_udp *)priv,
                                          &req.local_addr, &req.local_port,
                                          req.peer_addr, req.peer_port);
                if (err)
                    return err;
            }
            else
                return -EINVAL;

            if (copy_to_user((void *)arg, &req, sizeof(req)) != 0)
                return -EFAULT;

            return 0;
        }

    case EXASOCK_IOCTL_DST_QUEUE:
        {
            struct exasock_dst_request req;
            int err;

            if (copy_from_user(&req, (void *)arg, sizeof(req)) != 0)
                return -EFAULT;

            err = exasock_dst_queue(req.dst_addr, &req.src_addr, req.ip_packet,
                                    req.ip_packet_len);
            if (err)
                return err;

            if (copy_to_user((void *)arg, &req, sizeof(req)) != 0)
                return -EFAULT;

            return 0;
        }

    case EXASOCK_IOCTL_UPDATE:
        {
            struct exasock_hdr *priv = filp->private_data;
            struct exasock_hdr_socket *socket;
            struct exasock_endpoint req;

            if (copy_from_user(&req, (void *)arg, sizeof(req)) != 0)
                return -EFAULT;

            if (priv == NULL)
                return -EINVAL;

            if (priv->type != EXASOCK_TYPE_SOCKET)
                return -EINVAL;

            socket = &priv->socket;
            if (socket->domain == AF_INET && socket->type == SOCK_STREAM)
                exasock_tcp_update((struct exasock_tcp *)priv,
                                   req.local_addr, req.local_port,
                                   req.peer_addr, req.peer_port);
            else
                return -EINVAL;

            return 0;
        }

    case EXASOCK_IOCTL_SETSOCKOPT:
        {
            struct exasock_hdr *priv = filp->private_data;
            struct exasock_hdr_socket *socket;
            struct exasock_opt_request req;

            if (copy_from_user(&req, (void *)arg, sizeof(req)) != 0)
                return -EFAULT;

            if (priv == NULL)
                return -EINVAL;

            if (priv->type != EXASOCK_TYPE_SOCKET)
                return -EINVAL;

            socket = &priv->socket;
            if (socket->domain == AF_INET && socket->type == SOCK_DGRAM)
            {
                return exasock_udp_setsockopt((struct exasock_udp *)priv,
                                              req.level, req.optname,
                                              req.optval, req.optlen);
            }
            else if (socket->domain == AF_INET && socket->type == SOCK_STREAM)
            {
                return exasock_tcp_setsockopt((struct exasock_tcp *)priv,
                                              req.level, req.optname,
                                              req.optval, req.optlen);
            }
            else
                return -EINVAL;
        }

    case EXASOCK_IOCTL_GETSOCKOPT:
        {
            struct exasock_hdr *priv = filp->private_data;
            struct exasock_hdr_socket *socket;
            struct exasock_opt_request req;
            int err;

            if (copy_from_user(&req, (void *)arg, sizeof(req)) != 0)
                return -EFAULT;

            if (priv == NULL)
                return -EINVAL;

            if (priv->type != EXASOCK_TYPE_SOCKET)
                return -EINVAL;

            socket = &priv->socket;
            if (socket->domain == AF_INET && socket->type == SOCK_DGRAM)
                err = exasock_udp_getsockopt((struct exasock_udp *)priv,
                                             req.level, req.optname,
                                             req.optval, &req.optlen);
            else if (socket->domain == AF_INET && socket->type == SOCK_STREAM)
                err = exasock_tcp_getsockopt((struct exasock_tcp *)priv,
                                             req.level, req.optname,
                                             req.optval, &req.optlen);
            else
                return -EINVAL;

            if (err)
                return err;

            if (copy_to_user((void *)arg, &req, sizeof(req)) != 0)
                return -EFAULT;

            return 0;

        }

    case EXASOCK_IOCTL_EPOLL_CREATE:
        {
            struct exasock_epoll *epoll;

            if (filp->private_data)
                return -EINVAL;

            epoll = exasock_epoll_alloc();
            if (IS_ERR(epoll))
            {
                return PTR_ERR(epoll);
            }
            else
            {
                filp->private_data = epoll;
                return 0;
            }
        }

    case EXASOCK_IOCTL_EPOLL_CTL:
        {
            struct exasock_epoll_ctl_request req;
            void *priv = filp->private_data;
            enum exasock_type type;

            if (copy_from_user(&req, (void *)arg, sizeof(req)) != 0)
                return -EFAULT;

            if (priv == NULL)
                return -EINVAL;

            type = *((enum exasock_type *)priv);
            if (type != EXASOCK_TYPE_EPOLL)
                return -EINVAL;

            return exasock_epoll_ctl((struct exasock_epoll *)priv,
                                    (req.op == EXASOCK_EPOLL_CTL_ADD),
                                    req.local_addr, req.local_port, req.fd);
        }

    default:
        return -ENOTTY;
    }
}

static unsigned int exasock_dev_poll(struct file *filp, struct poll_table_struct *wait)
{
    /* Never report ready, so that this device can be added to poll/select
     * without affecting results. */
    return 0;
}

static struct file_operations exasock_fops = {
    .owner          = THIS_MODULE,
    .open           = exasock_dev_open,
    .release        = exasock_dev_release,
    .mmap           = exasock_dev_mmap,
    .unlocked_ioctl = exasock_dev_ioctl,
    .poll           = exasock_dev_poll,
};

/**
 * This function is called when the module is loaded.
 */
static int __init exasock_init(void)
{
    int err;

    /* Allocate destination table */
    err = exasock_dst_init();
    if (err)
        goto err_dst_init;

    /* Set up UDP */
    err = exasock_udp_init();
    if (err)
        goto err_udp_init;

    /* Set up TCP */
    err = exasock_tcp_init();
    if (err)
        goto err_tcp_init;

    /* Set up stats */
    err = exasock_stats_init();
    if (err)
        goto err_stats_init;

    /* Prepare kernel info page */
    exasock_info_page = vmalloc_user(PAGE_SIZE);
    if (exasock_info_page == NULL)
        goto err_vmalloc;

    exasock_info_page->api_version = EXASOCK_API_VERSION;
    exasock_info_page->dst_table_size = exasock_dst_table_size();

    /* Create /dev/exasock device */
    exasock_dev.minor = MISC_DYNAMIC_MINOR;
    exasock_dev.name = "exasock";
    exasock_dev.fops = &exasock_fops;
    err = misc_register(&exasock_dev);
    if (err)
    {
        pr_info("Failed to register exasock device: %d\n", err);
        goto err_miscdev;
    }

    /* Net event notifier for monitoring neighbour entry updates */
    register_netevent_notifier(&exasock_net_notifier);

    /* Notifier for monitoring IP address changes */
    register_inetaddr_notifier(&exasock_inetaddr_notifier);

    pr_info("ExaSock kernel support (ver " DRV_VERSION ") loaded.\n");
    return 0;

err_miscdev:
    vfree(exasock_info_page);
err_vmalloc:
    exasock_stats_exit();
err_stats_init:
    exasock_tcp_exit();
err_tcp_init:
    exasock_udp_exit();
err_udp_init:
    exasock_dst_exit();
err_dst_init:
    return err;
}
module_init(exasock_init);

/**
 * This function is called when the module is unloaded.
 */
static void __exit exasock_exit(void)
{
    unregister_netevent_notifier(&exasock_net_notifier);
    unregister_inetaddr_notifier(&exasock_inetaddr_notifier);
    misc_deregister(&exasock_dev);
    exasock_stats_exit();
    exasock_dst_exit();
    exasock_udp_exit();
    exasock_tcp_exit();
    vfree(exasock_info_page);

    pr_info("ExaSock kernel support unloaded.\n");
}
module_exit(exasock_exit);

MODULE_AUTHOR("Exablaze team <support@exablaze.com>");
MODULE_DESCRIPTION("ExaSock kernel support");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);
