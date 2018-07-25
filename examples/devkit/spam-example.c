/**
 * ExaNIC Firmware Development Kit 'spam' example.
 *
 * To be used with "exanic_*_native_spam_example.fw" generated from the
 * devkit examples.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <exanic/exanic.h>
#include <exanic/util.h>
#include <exanic/port.h>
#include <time.h>

#define REG_FIRMWARE_ID         0x0000
#define REG_FIRMWARE_VERSION    0x0001
#define REG_ENABLE              0x0002
#define REG_NUM_FRAMES          0x0003
#define REG_FRAME_LEN_MIN       0x0004
#define REG_FRAME_LEN_MAX       0x0005
#define REG_FRAME_WAIT_CYCLES   0x0006
#define REG_SRC_MAC_LOWER       0x0007
#define REG_SRC_MAC_UPPER       0x0008
#define REG_DST_MAC_LOWER       0x0009
#define REG_DST_MAC_UPPER       0x000A
#define REG_ETHERTYPE           0x000B
#define REG_NUM_BURSTS          0x000C
#define REG_BURST_WAIT_CYCLES   0x000D
#define REG_FRAME_COUNT_REM     0x000E
#define REG_BURST_COUNT_REM     0x000F
#define REG_NUM_BYTES_SENT_LOWER 0x0010
#define REG_NUM_BYTES_SENT_UPPER 0x0011

#define FIRMWARE_ID             0xEB000003
#define FIRMWARE_VERSION        0x00000001

static inline int64_t timenow_ns()
{
    struct timespec now_ts = {0};
    clock_gettime(CLOCK_REALTIME, &now_ts);
    return now_ts.tv_sec * 1000ULL * 1000 * 1000 + now_ts.tv_nsec;
}

int stop = 0;

void signal_handler(int signum)
{
    printf("Caught signal %i, shutting down\n", signum);
    if (stop == 1)
    {
        printf("Hard exit\n");
		exit(1);
    }
    stop = 1;
}

int main(int argc, char *argv[])
{
    const char *device;
    long num_frames;
    int frame_len_min, frame_len_max, frame_wait_cycles;
    uint8_t src_mac[6];
    uint32_t src_mac_lower, src_mac_upper;
    exanic_t *exanic;
    volatile uint32_t *application_registers;
    int opt;
    long num_bursts;
    int burst_wait_cycles;
    uint32_t hw_frame_count_rem, hw_burst_count_rem;
    uint64_t hw_num_bytes_sent_lower, hw_num_bytes_sent_upper;

    signal(SIGHUP, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGPIPE, signal_handler);
    signal(SIGALRM, signal_handler);
    signal(SIGTERM, signal_handler);

    device = "";
    num_frames = 0xFFFFFFFF;
    frame_len_min = -1;
    frame_len_max = -1;
    frame_wait_cycles = 0;
    num_bursts = 0xFFFFFFFF;
    burst_wait_cycles = 0;

    while ((opt = getopt(argc, argv, "c:s:S:g:b:G:")) != -1)
    {
        switch (opt) {
        case 'c':
            num_frames = atol(optarg);
            if (num_frames < 0)
                goto usage_error;
            break;
        case 's':
            frame_len_min = atoi(optarg);
            if (frame_len_min <= 0)
                goto usage_error;
            break;
        case 'S':
            frame_len_max = atoi(optarg);
            if (frame_len_max <= 0)
                goto usage_error;
            break;
        case 'g':
            frame_wait_cycles = atoi(optarg);
            if (frame_wait_cycles < 0)
                goto usage_error;
            break;
        case 'b':
            num_bursts = atoi(optarg);
            if (num_bursts < 0)
                goto usage_error;
            break;
        case 'G':
            burst_wait_cycles = atoi(optarg);
            if (burst_wait_cycles < 0)
                goto usage_error;
            break;
        default:
            goto usage_error;
        }
    }

    if (argc != optind + 1)
        goto usage_error;

    device = argv[optind];
    if (frame_len_min == -1 && frame_len_max == -1)
        frame_len_min = frame_len_max = 60;
    else if (frame_len_max == -1)
        frame_len_max = frame_len_min;
    else if (frame_len_min == -1)
        frame_len_min = frame_len_max;

    if ((exanic = exanic_acquire_handle(device)) == NULL)
    {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        return -1;
    }

    if (exanic_get_function_id(exanic) != EXANIC_FUNCTION_DEVKIT)
    {
        fprintf(stderr, "%s: Device is not a development kit device\n", device);
        return -1;
    }

    if ((application_registers = exanic_get_devkit_registers(exanic)) == NULL)
    {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        return -1;
    }

    if (application_registers[REG_FIRMWARE_ID] != FIRMWARE_ID)
    {
        fprintf(stderr, "Application ID register does not match expected (got %x, expected %x)\n",
                    application_registers[REG_FIRMWARE_ID], FIRMWARE_ID);
        fprintf(stderr, "This program requires the native_spam_example firmware\n");
        return -1;
    }

    if (application_registers[REG_FIRMWARE_VERSION] != FIRMWARE_VERSION)
    {
        fprintf(stderr, "Application version register does not match expected (got %x, expected %x)\n",
                    application_registers[REG_FIRMWARE_VERSION], FIRMWARE_VERSION);
        return -1;
    }

    /* Use MAC address of ExaNIC as source address */
    exanic_get_mac_addr(exanic, 0, src_mac);
    src_mac_lower = src_mac[0] | (src_mac[1] << 8) | (src_mac[2] << 16) | (src_mac[3] << 24);
    src_mac_upper = src_mac[4] | (src_mac[5] << 8);

    /* Write packet generator settings to hardware */
    application_registers[REG_NUM_FRAMES] = num_frames;
    application_registers[REG_FRAME_LEN_MIN] = frame_len_min;
    application_registers[REG_FRAME_LEN_MAX] = frame_len_max;
    application_registers[REG_FRAME_WAIT_CYCLES] = frame_wait_cycles;
    application_registers[REG_SRC_MAC_LOWER] = src_mac_lower;
    application_registers[REG_SRC_MAC_UPPER] = src_mac_upper;
    application_registers[REG_DST_MAC_LOWER] = 0xffffffff;
    application_registers[REG_DST_MAC_UPPER] = 0xffff;
    application_registers[REG_ETHERTYPE] = 0xB688;
    application_registers[REG_NUM_BURSTS] = num_bursts;
    /* in current implementation, the burst gap replaces the frame gap for the last frame
     * in a burst, instead of actually being added to it. Therefore we need to add them here */
    application_registers[REG_BURST_WAIT_CYCLES] = burst_wait_cycles + frame_wait_cycles;

    /* Read back registers to confirm settings */
    num_frames = application_registers[REG_NUM_FRAMES];
    frame_len_min = application_registers[REG_FRAME_LEN_MIN];
    frame_len_max = application_registers[REG_FRAME_LEN_MAX];
    frame_wait_cycles = application_registers[REG_FRAME_WAIT_CYCLES];
    num_bursts = application_registers[REG_NUM_BURSTS];
    burst_wait_cycles = application_registers[REG_BURST_WAIT_CYCLES] - frame_wait_cycles;

    printf("Number of frames : %lu\n", num_frames);
    printf("Frame size       : %u to %u\n", frame_len_min, frame_len_max);
    printf("Extra frame gap  : %u\n", frame_wait_cycles);
    if (num_bursts == 0xFFFFFFFF)
        printf("Number of bursts : unlimited\n");
    else
        printf("Number of bursts : %lu\n", num_bursts);
    printf("Extra burst gap  : %u\n", burst_wait_cycles);

    uint64_t now_ns = 0;
    uint64_t timestart_ns = timenow_ns();
    uint64_t timestop_ns;
    uint64_t timetick;

    const int64_t timeout_ns = 1000ULL * 1000 * 1000; /* 1 second timeout */
    long int total_pkt_cnt_new = 0;
    long int total_pkt_cnt_old = 0;
    long int diff_pkt_cnt = 0;
    double frame_rate_mpps, frame_rate_gbps;
    uint64_t total_hw_num_bytes_sent_old = 0;
    uint64_t total_hw_num_bytes_sent_new = 0;
    uint64_t diff_hw_num_bytes_sent = 0;
    double avg_frame_length;

    /* Start the packet generator */
    application_registers[REG_ENABLE] = 1;

    hw_frame_count_rem = application_registers[REG_FRAME_COUNT_REM];
    hw_burst_count_rem = application_registers[REG_BURST_COUNT_REM];

    printf("---------------------------------\n");

    timestart_ns = timenow_ns();
    timetick = timestart_ns;

    /* only for the first loop iteration, if both burst and frame counters are 1,
     * the loop executes, o.w. at least one of these counters should be > 1
     * in order to enter the loop */
    while(!stop && hw_frame_count_rem && hw_burst_count_rem &&
        ((total_pkt_cnt_new == 0) || (hw_frame_count_rem > 1) || (hw_burst_count_rem > 1)))
    {
        now_ns = timenow_ns();
        if (now_ns > timetick + timeout_ns)
        {
            //Do register reads here
            hw_frame_count_rem = application_registers[REG_FRAME_COUNT_REM];
            hw_burst_count_rem = application_registers[REG_BURST_COUNT_REM];

            hw_num_bytes_sent_lower = application_registers[REG_NUM_BYTES_SENT_LOWER];
            hw_num_bytes_sent_upper = application_registers[REG_NUM_BYTES_SENT_UPPER];
            total_hw_num_bytes_sent_new = (hw_num_bytes_sent_upper << 32) | hw_num_bytes_sent_lower;
            diff_hw_num_bytes_sent = total_hw_num_bytes_sent_new - total_hw_num_bytes_sent_old;

            total_pkt_cnt_new = (num_bursts-hw_burst_count_rem)*num_frames + (num_frames-hw_frame_count_rem+1);
            diff_pkt_cnt = total_pkt_cnt_new - total_pkt_cnt_old;

            frame_rate_mpps = diff_pkt_cnt*1000.0/timeout_ns;
            frame_rate_gbps = diff_hw_num_bytes_sent*8.0/timeout_ns;
            avg_frame_length = (double) diff_hw_num_bytes_sent/diff_pkt_cnt;

            if (num_bursts != 0xFFFFFFFF)
                printf("Bursts: %8li/%li, Packets: %15li/%li", num_bursts-hw_burst_count_rem,
                        num_bursts, total_pkt_cnt_new, num_bursts*num_frames);
            else
                printf("Bursts: %8li/Inf, Packets: %15li/Inf", num_bursts-hw_burst_count_rem,
                        total_pkt_cnt_new);
            printf(" (+%li P : %.4f MP/s), %llu B (+%llu B : %.4f Gbps) -- Avg frame len = %.2f B\n",
                    diff_pkt_cnt, frame_rate_mpps, total_hw_num_bytes_sent_new, diff_hw_num_bytes_sent,
                    frame_rate_gbps, avg_frame_length);

            total_pkt_cnt_old = total_pkt_cnt_new;
            total_hw_num_bytes_sent_old = total_hw_num_bytes_sent_new;
            timetick = now_ns;
        }
    }

    timestop_ns = timenow_ns();

    /* Stop the packet generator */
    application_registers[REG_ENABLE] = 0;

    /* read final register values and update stats (necessary in case
     * we break out of the loop by the 'stop' interrupt) */
    hw_frame_count_rem = application_registers[REG_FRAME_COUNT_REM];
    hw_burst_count_rem = application_registers[REG_BURST_COUNT_REM];
    total_pkt_cnt_new = (num_bursts-hw_burst_count_rem)*num_frames + (num_frames-hw_frame_count_rem+1);

    hw_num_bytes_sent_lower = application_registers[REG_NUM_BYTES_SENT_LOWER];
    hw_num_bytes_sent_upper = application_registers[REG_NUM_BYTES_SENT_UPPER];
    total_hw_num_bytes_sent_new = (hw_num_bytes_sent_upper << 32) | hw_num_bytes_sent_lower;

    frame_rate_mpps = total_pkt_cnt_new*1000.0/(timestop_ns-timestart_ns);
    frame_rate_gbps = total_hw_num_bytes_sent_new*8.0/(timestop_ns-timestart_ns);
    avg_frame_length = (double) total_hw_num_bytes_sent_new/total_pkt_cnt_new;

    printf("---------------------------------\n");
    printf("Total data sent:\n");
    printf("%-30s: %li (Avg %.4f MP/s)\n", "Packets", total_pkt_cnt_new, frame_rate_mpps);
    printf("%-30s: %.1f MB (Avg %.4f Gbps)\n", "Bytes", total_hw_num_bytes_sent_new/(1024.0*1024), frame_rate_gbps);
    printf("%-30s: %.2f B\n","Average frame length", avg_frame_length);

    return 0;

usage_error:
    fprintf(stderr, "Usage: %s <device> [-c num-frames] [-s min-size] [-S max-size] [-g inter-frame-gap] [-b num-bursts] [-G inter-burst-gap]\n", argv[0]);
    return -1;
}
