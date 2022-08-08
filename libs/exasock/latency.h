#ifndef EXASOCK_LATENCY_H
#define EXASOCK_LATENCY_H

#ifdef MEASURE_LATENCY

#define LATENCY_START_POINT(index) latency_measure(__FUNCTION__, __LINE__, true, index)

#define LATENCY_END_POINT(index) latency_measure(__FUNCTION__, __LINE__, false, index);

void latency_measure(const char* function_name, int line, bool start, int index);
void clear_latencies(void);
void print_exasock_latencies(void);

#else /* ifdef MEASURE_LATENCY */

#define LATENCY_START_POINT(index)
#define LATENCY_END_POINT(index)
#endif /* ifdef MEASURE_LATENCY */

#endif /* ifdef EXASOCK_LATENCY_H */