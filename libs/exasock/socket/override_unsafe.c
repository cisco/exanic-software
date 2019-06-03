
#include "../common.h"

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <dlfcn.h>
#include <assert.h>

#include "../override.h"

bool __thread override_unsafe;

static struct hostent * (*__libc_gethostbyname)(const char *);
static struct hostent * (*__libc_gethostbyaddr)(const void *, socklen_t, int);
static struct hostent * (*__libc_gethostent)(void);
static int (*__libc_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static struct hostent * (*__libc_gethostbyname2)(const char *, int);
static int (*__libc_gethostent_r)(struct hostent *, char *, size_t, struct hostent **, int);
static int (*__libc_gethostbyaddr_r)(const void *, socklen_t, int, struct hostent *, char *, size_t, struct hostent **, int *);
static int (*__libc_gethostbyname_r)(const char *, struct hostent *, char *, size_t, struct hostent **, int *);
static int (*__libc_gethostbyname2_r)(const char *, int, struct hostent *, char *, size_t, struct hostent **, int *);
static struct netent * (*__libc_getnetent)(void);
static struct netent * (*__libc_getnetbyaddr)(uint32_t, int);
static struct netent * (*__libc_getnetbyname)(const char *);
static int (*__libc_getnetent_r)(struct netent *, char *, size_t, struct netent **, int *);
static int (*__libc_getnetbyaddr_r)(uint32_t, int, struct netent *, char *, size_t, struct netent **, int *);
static int (*__libc_getnetbyname_r)(const char *, struct netent *, char *, size_t, struct netent **, int *);
static struct servent * (*__libc_getservent)(void);
static struct servent * (*__libc_getservbyname)(const char *, const char *);
static struct servent * (*__libc_getservbyport)(int, const char *);
static int (*__libc_getservent_r)(struct servent *, char *, size_t, struct servent **);
static int (*__libc_getservbyname_r)(const char *, const char *, struct servent *, char *, size_t, struct servent **);
static int (*__libc_getservbyport_r)(int, const char *, struct servent *, char *, size_t, struct servent **);
static struct protoent * (*__libc_getprotoent)(void);
static struct protoent * (*__libc_getprotobyname)(const char *);
static struct protoent * (*__libc_getprotobynumber)(int);
static int (*__libc_getprotoent_r)(struct protoent *, char *, size_t, struct protoent **);
static int (*__libc_getprotobyname_r)(const char *, struct protoent *, char *, size_t, struct protoent **);
static int (*__libc_getprotobynumber_r)(int, struct protoent *, char *, size_t, struct protoent **);
static int (*__libc_getnetgrent)(char **, char **, char **);
static int (*__libc_getnetgrent_r)(char **, char **, char **, char *, size_t);
static int (*__libc_rcmd)(char **, unsigned short int, const char *, const char *, const char *, int *);
static int (*__libc_rcmd_af)(char **, unsigned short int, const char *, const char *, const char *, int *, sa_family_t);
static int (*__libc_rexec)(char **, int, const char *, const char *, const char *, int *);
static int (*__libc_rexec_af)(char **, int, const char *, const char *, const char *, int *, sa_family_t);
static int (*__libc_ruserok)(const char *, int, const char *, const char *);
static int (*__libc_ruserok_af)(const char *, int, const char *, const char *, sa_family_t);
static int (*__libc_iruserok)(uint32_t, int, const char *, const char *);
static int (*__libc_iruserok_af)(const void *, int, const char *, const char *, sa_family_t);
static int (*__libc_rresvport)(int *);
static int (*__libc_rresvport_af)(int *, sa_family_t);
static int (*__libc_getnameinfo)(const struct sockaddr *, socklen_t, char *, socklen_t, char *, socklen_t,
#if GETNAMEINFO_HAS_SIGNED_FLAGS
                                int);
#else
                                unsigned int);
#endif
static int (*__libc_getaddrinfo_a)(int, struct gaicb **, int, struct sigevent *);

__attribute__((constructor))
void __exasock_unsafe_functions_wrapper_init(void)
{

    __libc_gethostbyname = dlsym(RTLD_NEXT, "gethostbyname");
    __libc_gethostbyaddr = dlsym(RTLD_NEXT, "gethostbyaddr");
    __libc_gethostent = dlsym(RTLD_NEXT, "gethostent");
    __libc_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
    __libc_gethostbyname2 = dlsym(RTLD_NEXT, "gethostbyname2");
    __libc_gethostent_r = dlsym(RTLD_NEXT, "gethostent_r");
    __libc_gethostbyaddr_r = dlsym(RTLD_NEXT, "gethostbyaddr_r");
    __libc_gethostbyname_r = dlsym(RTLD_NEXT, "gethostbyname_r");
    __libc_gethostbyname2_r = dlsym(RTLD_NEXT, "gethostbyname2_r");
    __libc_getnetent = dlsym(RTLD_NEXT, "getnetent");
    __libc_getnetbyaddr = dlsym(RTLD_NEXT, "getnetbyaddr");
    __libc_getnetbyname = dlsym(RTLD_NEXT, "getnetbyname");
    __libc_getnetent_r = dlsym(RTLD_NEXT, "getnetent_r");
    __libc_getnetbyaddr_r = dlsym(RTLD_NEXT, "getnetbyaddr_r");
    __libc_getnetbyname_r = dlsym(RTLD_NEXT, "getnetbyname_r");
    __libc_getservent = dlsym(RTLD_NEXT, "getservent");
    __libc_getservbyname = dlsym(RTLD_NEXT, "getservbyname");
    __libc_getservbyport = dlsym(RTLD_NEXT, "getservbyport");
    __libc_getservent_r = dlsym(RTLD_NEXT, "getservent_r");
    __libc_getservbyname_r = dlsym(RTLD_NEXT, "getservbyname_r");
    __libc_getservbyport_r = dlsym(RTLD_NEXT, "getservbyport_r");
    __libc_getprotoent = dlsym(RTLD_NEXT, "getprotoent");
    __libc_getprotobyname = dlsym(RTLD_NEXT, "getprotobyname");
    __libc_getprotobynumber = dlsym(RTLD_NEXT, "getprotobynumber");
    __libc_getprotoent_r = dlsym(RTLD_NEXT, "getprotoent_r");
    __libc_getprotobyname_r = dlsym(RTLD_NEXT, "getprotobyname_r");
    __libc_getprotobynumber_r = dlsym(RTLD_NEXT, "getprotobynumber_r");
    __libc_getnetgrent = dlsym(RTLD_NEXT, "getnetgrent");
    __libc_getnetgrent_r = dlsym(RTLD_NEXT, "getnetgrent_r");
    __libc_rcmd = dlsym(RTLD_NEXT, "rcmd");
    __libc_rcmd_af = dlsym(RTLD_NEXT, "rcmd_af");
    __libc_rexec = dlsym(RTLD_NEXT, "rexec");
    __libc_rexec_af = dlsym(RTLD_NEXT, "rexec_af");
    __libc_ruserok = dlsym(RTLD_NEXT, "ruserok");
    __libc_ruserok_af = dlsym(RTLD_NEXT, "ruserok_af");
    __libc_iruserok = dlsym(RTLD_NEXT, "iruserok");
    __libc_iruserok_af = dlsym(RTLD_NEXT, "iruserok_af");
    __libc_rresvport = dlsym(RTLD_NEXT, "rresvport");
    __libc_rresvport_af = dlsym(RTLD_NEXT, "rresvport_af");
    __libc_getnameinfo = dlsym(RTLD_NEXT, "getnameinfo");
    __libc_getaddrinfo_a = dlsym(RTLD_NEXT, "getaddrinfo_a");
}

__attribute__((visibility("default")))
struct hostent * gethostbyname(const char * name)
{
    struct hostent * libc_result;
    override_unsafe = true;
    libc_result = __libc_gethostbyname(name);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
struct hostent * gethostbyaddr(const void * addr, socklen_t len, int type)
{
    struct hostent * libc_result;
    override_unsafe = true;
    libc_result = __libc_gethostbyaddr(addr, len, type);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
struct hostent * gethostent(void)
{
    struct hostent * libc_result;
    override_unsafe = true;
    libc_result = __libc_gethostent();
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int getaddrinfo(const char * node, const char * service, const struct addrinfo * hints, struct addrinfo ** res)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_getaddrinfo(node, service, hints, res);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
struct hostent * gethostbyname2(const char * name, int af)
{
    struct hostent * libc_result;
    override_unsafe = true;
    libc_result = __libc_gethostbyname2(name, af);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int gethostent_r(struct hostent * ret, char * buf, size_t buflen, struct hostent ** result, int *h_errnop)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_gethostent_r(ret, buf, buflen, result, *h_errnop);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int gethostbyaddr_r(const void * addr, socklen_t len, int type, struct hostent * ret, char * buf, size_t buflen, struct hostent ** result, int * h_errnop)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_gethostbyaddr_r(addr, len, type, ret, buf, buflen, result, h_errnop);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int gethostbyname_r(const char * name, struct hostent * ret, char * buf, size_t buflen, struct hostent ** result, int * h_errnop)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_gethostbyname_r(name, ret, buf, buflen, result, h_errnop);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int gethostbyname2_r(const char * name, int af, struct hostent * ret, char * buf, size_t buflen, struct hostent ** result, int * h_errnop)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_gethostbyname2_r(name, af, ret, buf, buflen, result, h_errnop);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
struct netent * getnetent(void)
{
    struct netent * libc_result;
    override_unsafe = true;
    libc_result = __libc_getnetent();
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
struct netent * getnetbyaddr(uint32_t net, int type)
{
    struct netent * libc_result;
    override_unsafe = true;
    libc_result = __libc_getnetbyaddr(net, type);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
struct netent * getnetbyname(const char * name)
{
    struct netent * libc_result;
    override_unsafe = true;
    libc_result = __libc_getnetbyname(name);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int getnetent_r(struct netent * result_buf, char * buf, size_t buflen, struct netent ** result, int * h_errnop)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_getnetent_r(result_buf, buf, buflen, result, h_errnop);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int getnetbyaddr_r(uint32_t net, int type, struct netent * result_buf, char * buf, size_t buflen, struct netent ** result, int * h_errnop)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_getnetbyaddr_r(net, type, result_buf, buf, buflen, result, h_errnop);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int getnetbyname_r(const char * name, struct netent * result_buf, char * buf, size_t buflen, struct netent ** result, int * h_errnop)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_getnetbyname_r(name, result_buf, buf, buflen, result, h_errnop);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
struct servent * getservent(void)
{
    struct servent * libc_result;
    override_unsafe = true;
    libc_result = __libc_getservent();
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
struct servent * getservbyname(const char * name, const char * proto)
{
    struct servent * libc_result;
    override_unsafe = true;
    libc_result = __libc_getservbyname(name, proto);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
struct servent * getservbyport(int port, const char * proto)
{
    struct servent * libc_result;
    override_unsafe = true;
    libc_result = __libc_getservbyport(port, proto);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int getservent_r(struct servent * result_buf, char * buf, size_t buflen, struct servent ** result)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_getservent_r(result_buf, buf, buflen, result);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int getservbyname_r(const char * name, const char * proto, struct servent * result_buf, char * buf, size_t buflen, struct servent ** result)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_getservbyname_r(name, proto, result_buf, buf, buflen, result);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int getservbyport_r(int port, const char * proto, struct servent * result_buf, char * buf, size_t buflen, struct servent ** result)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_getservbyport_r(port, proto, result_buf, buf, buflen, result);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
struct protoent * getprotoent(void)
{
    struct protoent * libc_result;
    override_unsafe = true;
    libc_result = __libc_getprotoent();
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
struct protoent * getprotobyname(const char * name)
{
    struct protoent * libc_result;
    override_unsafe = true;
    libc_result = __libc_getprotobyname(name);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
struct protoent * getprotobynumber(int proto)
{
    struct protoent * libc_result;
    override_unsafe = true;
    libc_result = __libc_getprotobynumber(proto);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int getprotoent_r(struct protoent * result_buf, char * buf, size_t buflen, struct protoent ** result)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_getprotoent_r(result_buf, buf, buflen, result);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int getprotobyname_r(const char * name, struct protoent * result_buf, char * buf, size_t buflen, struct protoent ** result)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_getprotobyname_r(name, result_buf, buf, buflen, result);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int getprotobynumber_r(int proto, struct protoent * result_buf, char * buf, size_t buflen, struct protoent ** result)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_getprotobynumber_r(proto, result_buf, buf, buflen, result);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int getnetgrent(char ** hostp, char ** userp, char ** domainp)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_getnetgrent(hostp, userp, domainp);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int getnetgrent_r(char ** hostp, char ** userp, char ** domainp, char * buffer, size_t buflen)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_getnetgrent_r(hostp, userp, domainp, buffer, buflen);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int rcmd(char ** ahost, unsigned short int rport, const char * locuser, const char * remuser, const char * cmd, int * fd2p)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_rcmd(ahost, rport, locuser, remuser, cmd, fd2p);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int rcmd_af(char ** ahost, unsigned short int rport, const char * locuser, const char * remuser, const char * cmd, int * fd2p, sa_family_t af)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_rcmd_af(ahost, rport, locuser, remuser, cmd, fd2p, af);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int rexec(char ** ahost, int rport, const char * name, const char * pass, const char * cmd, int * fd2p)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_rexec(ahost, rport, name, pass, cmd, fd2p);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int rexec_af(char ** ahost, int rport, const char * name, const char * pass, const char * cmd, int * fd2p, sa_family_t af)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_rexec_af(ahost, rport, name, pass, cmd, fd2p, af);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int ruserok(const char * rhost, int suser, const char * remuser, const char * locuser)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_ruserok(rhost, suser, remuser, locuser);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int ruserok_af(const char * rhost, int suser, const char * remuser, const char * locuser, sa_family_t af)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_ruserok_af(rhost, suser, remuser, locuser, af);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int iruserok(uint32_t raddr, int suser, const char * remuser, const char * locuser)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_iruserok(raddr, suser, remuser, locuser);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int iruserok_af(const void * raddr, int suser, const char * remuser, const char * locuser, sa_family_t af)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_iruserok_af(raddr, suser, remuser, locuser, af);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int rresvport(int * alport)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_rresvport(alport);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int rresvport_af(int * alport, sa_family_t af)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_rresvport_af(alport, af);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int getnameinfo(const struct sockaddr * sa, socklen_t salen, char * host, socklen_t hostlen, char * serv, socklen_t servlen,
#if GETNAMEINFO_HAS_SIGNED_FLAGS
                int flags)
#else
                unsigned int flags)
#endif
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
    override_unsafe = false;
    return libc_result;
}

__attribute__((visibility("default")))
int getaddrinfo_a(int mode, struct gaicb ** list, int ent, struct sigevent * sig)
{
    int libc_result;
    override_unsafe = true;
    libc_result = __libc_getaddrinfo_a(mode, list, ent, sig);
    override_unsafe = false;
    return libc_result;
}

