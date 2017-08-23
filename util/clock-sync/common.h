#ifndef EXANIC_CLOCK_SYNC_COMMON_H_A1E81DE87A7B817E07A2AD5671E2FAAD
#define EXANIC_CLOCK_SYNC_COMMON_H_A1E81DE87A7B817E07A2AD5671E2FAAD

#define POLL_INTERVAL 1.0
#define PPS_POLL_INTERVAL 0.3
#define SHORT_POLL_INTERVAL 0.1
#define LOG_INTERVAL 60

enum sync_status
{
    SYNC_OK = 0,
    SYNC_FAST_POLL = 1,
    SYNC_FAILED = -1,
};

int get_clock_adj(int clkfd, double *adj);
int set_clock_adj(int clkfd, double adj);
int get_clock_time(int clkfd, uint64_t *time_ns);
int set_clock_time(int clkfd, uint64_t time_ns);

int get_tai_offset(int *offset);
int set_tai_offset(int offset);

enum phc_source
{
    PHC_SOURCE_NONE = 0,
    PHC_SOURCE_EXANIC_GPS,
    PHC_SOURCE_SYNC, /* Synced by exanic-clock-sync */
};

enum phc_status
{
    PHC_STATUS_UNKNOWN = 0,
    PHC_STATUS_SYNCED = 1,
    PHC_STATUS_HOLDOVER = 2
};

void set_phc_synced(int clkfd);
enum phc_source get_phc_source(int clkfd, exanic_t *exanic);

int check_exanic_gps_time(exanic_t *exanic);
int get_exanic_gps_tai_offset(exanic_t *exanic, int *offset);

void update_phc_status(int clkfd, enum phc_status status);
enum phc_status get_phc_status(int clkfd);

#define DRIFT_LEN 8

struct drift
{
    double drift[DRIFT_LEN];
    double weight[DRIFT_LEN];
    int n;
    int startup;
};

void reset_drift(struct drift *d);
int calc_drift(struct drift *d, double *val);
void record_drift(struct drift *d, double val, double weight);

#define ERROR_LEN 8

struct error
{
    double error[ERROR_LEN];
    int n;
    int startup;
};

void reset_error(struct error *e);
int calc_error(struct error *e, double *val);
void record_error(struct error *e, double correction, double val);

#define RATE_ERROR_LEN 64

struct rate_error
{
    double error[RATE_ERROR_LEN];
    double partial;
    int n;
    int startup;
    double interval;
};

void reset_rate_error(struct rate_error *r, double interval);
int calc_rate_error(struct rate_error *r, double *err);
int calc_rate_error_adev(struct rate_error *r, double *adev);
void record_rate_error(struct rate_error *r, double err, double interval);

void log_printf(int priority, const char *fmt, ...);

extern int verbose;

#endif /* EXANIC_CLOCK_SYNC_COMMON_H_A1E81DE87A7B817E07A2AD5671E2FAAD */
