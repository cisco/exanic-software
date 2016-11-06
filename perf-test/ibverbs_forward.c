#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <infiniband/verbs.h>

const uint8_t g_dgid[] = { 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0xfd, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff };
const uint8_t g_mgid[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/* RX_BUFFERS must be at least 2 (1 results in a slowdown) */
#define RX_BUFFERS 4
#define RX_BUFFER_SIZE 2048

int main(int argc, char *argv[])
{
    const char *device;
    struct ibv_device **devs;
    struct ibv_context *ctx;
    struct ibv_pd *pd;
    struct ibv_qp *send_qp, *recv_qp;
    struct ibv_mr *recv_mr;
    struct ibv_ah *ah;
    struct ibv_cq *send_cq, *recv_cq;
    struct ibv_comp_channel *comp_chan;
    struct ibv_recv_wr recv_wr[RX_BUFFERS], *bad_recv_wr;
    struct ibv_send_wr send_wr, *bad_send_wr;
    struct ibv_sge send_sge, recv_sge[RX_BUFFERS];
    struct ibv_qp_init_attr qp_attr;
    struct ibv_qp_attr qp_attr2;
    struct ibv_ah_attr ah_attr;
    struct ibv_wc wc;
    union ibv_gid gid;
    char *rx_buffer;
    int status, num_devices, i, tx_port, rx_port;

    if (argc < 4)
    {
        fprintf(stderr, "ibv_forward: waits for a packet on one port and forwards it out another\n");
        fprintf(stderr, "  usage: %s device rx_port tx_port\n", argv[0]);
        return 1;
    }
    device = argv[1];
    rx_port = atoi(argv[2]);
    tx_port = atoi(argv[3]);

    if (posix_memalign((void **)&rx_buffer, 4096, RX_BUFFERS*RX_BUFFER_SIZE) < 0)
    {
        fprintf(stderr, "posix_memalign failed\n");
        return 1;
    }

    /* INIT DEVICE */

    devs = ibv_get_device_list(&num_devices);
    if (!num_devices)
    {
        fprintf(stderr, "ibv_get_device_list: no devices\n");
        return 1;
    }
    for (i = 0; i < num_devices; i++)
    {
        if (strcmp(ibv_get_device_name(devs[i]), device) == 0)
            break;
    }
    if (i == num_devices)
    {
        fprintf(stderr, "%s: device not found\n", device);
        return 1;
    }
    ctx = ibv_open_device(devs[i]);
    if (!ctx)
    {
        fprintf(stderr, "ibv_open_device failed\n");
        return 1;
    }
    ibv_free_device_list(devs);

    pd = ibv_alloc_pd(ctx);
    if (!pd)
    {
	fprintf(stderr, "ibv_alloc_pd failed\n");
	return 1;
    }

    comp_chan = ibv_create_comp_channel(ctx);
    if (!comp_chan)
    {
	fprintf(stderr, "ibv_create_comp_channel failed\n");
	return 1;
    }


    /* INIT TX SIDE */

    memset(&ah_attr, 0, sizeof(ah_attr));
    ah_attr.port_num = tx_port;
    ah_attr.is_global = 1;
    memcpy(ah_attr.grh.dgid.raw, g_dgid, sizeof(ah_attr.grh.dgid.raw));
    ah = ibv_create_ah(pd, &ah_attr);
    if (!ah)
    {
	fprintf(stderr, "ibv_create_ah failed\n");
	return 1;
    }

    send_cq = ibv_create_cq(ctx, 1, NULL, comp_chan, 0);
    if (!send_cq)
    {
	fprintf(stderr, "ibv_create_cq failed\n");
	return 1;
    }

    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_attr.qp_context = ctx;
    qp_attr.send_cq = send_cq;
    qp_attr.recv_cq = send_cq;
    qp_attr.qp_type = IBV_QPT_RAW_PACKET;
    qp_attr.cap.max_send_wr = 1;
    qp_attr.cap.max_recv_wr = 0;
    qp_attr.cap.max_send_sge = 1;
    qp_attr.cap.max_recv_sge = 0;
    send_qp = ibv_create_qp(pd, &qp_attr);
    if (!send_qp)
    {
	fprintf(stderr, "ibv_create_qp failed\n");
	return 1;
    }

    memset(&qp_attr2, 0, sizeof(qp_attr2));
    qp_attr2.port_num = tx_port;
    qp_attr2.qp_state = IBV_QPS_INIT;
    if (ibv_modify_qp(send_qp, &qp_attr2, IBV_QP_PORT|IBV_QP_STATE) != 0)
	perror("ibv_modify_qp failed to transition to INIT");
    qp_attr2.qp_state = IBV_QPS_RTR;
    if (ibv_modify_qp(send_qp, &qp_attr2, IBV_QP_STATE) != 0)
	perror("ibv_modify_qp failed to transition to RTR");
    qp_attr2.qp_state = IBV_QPS_RTS;
    if (ibv_modify_qp(send_qp, &qp_attr2, IBV_QP_STATE) != 0)
	perror("ibv_modify_qp failed to transition to RTS");

    memset(&send_wr, 0, sizeof(send_wr));

    send_wr.wr_id = 0;
    send_wr.opcode = IBV_WR_SEND;
    send_wr.sg_list = &send_sge;
    send_wr.num_sge = 1;
    send_wr.send_flags = IBV_SEND_SIGNALED;
    send_wr.wr.ud.ah = ah;


    /* INIT RX SIDE */

    recv_mr = ibv_reg_mr(pd, rx_buffer, RX_BUFFERS*RX_BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
    if (!recv_mr)
    {
	fprintf(stderr, "ibv_reg_mr failed\n");
	return 1;
    }

    recv_cq = ibv_create_cq(ctx, 1, NULL, comp_chan, 0);
    if (!recv_cq)
    {
	fprintf(stderr, "ibv_create_cq failed\n");
	return 1;
    }

    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_attr.qp_context = ctx;
    qp_attr.send_cq = recv_cq;
    qp_attr.recv_cq = recv_cq;
    qp_attr.qp_type = IBV_QPT_RAW_PACKET;
    qp_attr.cap.max_send_wr = 0;
    qp_attr.cap.max_recv_wr = RX_BUFFERS;
    qp_attr.cap.max_send_sge = 0;
    qp_attr.cap.max_recv_sge = RX_BUFFERS;
    recv_qp = ibv_create_qp(pd, &qp_attr);
    if (!recv_qp)
    {
	fprintf(stderr, "ibv_create_qp failed\n");
	return 1;
    }

    memset(&qp_attr2, 0, sizeof(qp_attr2));
    qp_attr2.port_num = rx_port;
    qp_attr2.qp_state = IBV_QPS_INIT;
    if (ibv_modify_qp(recv_qp, &qp_attr2, IBV_QP_PORT|IBV_QP_STATE) != 0)
	perror("ibv_modify_qp failed to transition to INIT");

    memcpy(&gid.raw, g_mgid, 16);
    if (ibv_attach_mcast(recv_qp, &gid, 0))
    {
	perror("ibv_attach_mcast");
	return 1;
    }

    qp_attr2.qp_state = IBV_QPS_RTR;
    if (ibv_modify_qp(recv_qp, &qp_attr2, IBV_QP_STATE) != 0)
	perror("ibv_modify_qp failed to transition to RTR");
    qp_attr2.qp_state = IBV_QPS_RTS;
    if (ibv_modify_qp(recv_qp, &qp_attr2, IBV_QP_STATE) != 0)
	perror("ibv_modify_qp failed to transition to RTS");

    memset(recv_wr, 0, sizeof(recv_wr));
    memset(rx_buffer, 0xff, sizeof(rx_buffer)); 

    for (i = 0; i < RX_BUFFERS; i++)
    { 
	recv_sge[i].addr = (uintptr_t)rx_buffer + RX_BUFFER_SIZE*i;
	recv_sge[i].length = RX_BUFFER_SIZE;
	recv_sge[i].lkey = recv_mr->lkey;

	recv_wr[i].wr_id = i;
	recv_wr[i].sg_list = &recv_sge[i];
	recv_wr[i].num_sge = 1;

	status = ibv_post_recv(recv_qp, &recv_wr[i], &bad_recv_wr);
	if (status != 0)
	    printf("ibv_post_recv: %d\n", status);
    }


    /* MAIN LOOP */

    send_sge.lkey = recv_mr->lkey;
    while (1)
    {
	while (ibv_poll_cq(recv_cq, 1, &wc) < 1)
	    ;

	if (wc.status != IBV_WC_SUCCESS)
	    continue;

	send_sge.addr = (uintptr_t)&rx_buffer[RX_BUFFER_SIZE*wc.wr_id];
	send_sge.length = wc.byte_len;

	ibv_post_send(send_qp, &send_wr, &bad_send_wr);
	while (ibv_poll_cq(send_cq, 1, &wc) < 1)
	    ;

	status = ibv_post_recv(recv_qp, &recv_wr[wc.wr_id], &bad_recv_wr);
    }

    ibv_destroy_qp(recv_qp);
    ibv_destroy_cq(recv_cq);
    ibv_dereg_mr(recv_mr);
    ibv_destroy_qp(send_qp);
    ibv_destroy_cq(send_cq);
    ibv_destroy_ah(ah);
    ibv_destroy_comp_channel(comp_chan);
    ibv_dealloc_pd(pd);
    ibv_close_device(ctx);
    return 0;
}

