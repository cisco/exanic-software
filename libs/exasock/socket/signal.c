#include "../common.h"

#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <sched.h>
#include <poll.h>

#include "override.h"
#include "trace.h"

static bool signal_override[NSIG];
static struct sigaction sa_user[NSIG];

bool __thread signal_received;
bool __thread signal_interrupted;

static void
signal_override_handler(int signum)
{
    int tmp;
    TRACE_SIGNAL_ENTRY(tmp);

    signal_received = true;
    if (!(sa_user[signum].sa_flags & SA_RESTART))
        signal_interrupted = true;
    if (signum >= 0 && signum < NSIG && signal_override[signum])
        sa_user[signum].sa_handler(signum);

    TRACE_SIGNAL_EXIT(tmp);
}

static void
sigaction_override_handler(int signum, siginfo_t *siginfo, void *context)
{
    int tmp;
    TRACE_SIGNAL_ENTRY(tmp);

    signal_received = true;
    if (!(sa_user[signum].sa_flags & SA_RESTART))
        signal_interrupted = true;
    if (signum >= 0 && signum < NSIG && signal_override[signum])
        sa_user[signum].sa_sigaction(signum, siginfo, context);

    TRACE_SIGNAL_EXIT(tmp);
}

__attribute__((visibility("default")))
sighandler_t
signal(int signum, sighandler_t handler)
{
    sighandler_t old;

    TRACE_CALL("signal");
    TRACE_ARG(INT, signum);
    TRACE_LAST_ARG(SIGHANDLER, handler);
    TRACE_FLUSH();

    if (signum < 0 || signum >= NSIG)
        old = LIBC(signal, signum, handler);
    else if (signal_override[signum])
    {
        if (sa_user[signum].sa_flags & SA_SIGINFO)
            old = (sighandler_t)sa_user[signum].sa_sigaction;
        else
            old = sa_user[signum].sa_handler;

        if (handler == SIG_DFL || handler == SIG_IGN)
        {
            /* Don't override SIG_DFL or SIG_IGN */
            signal_override[signum] = false;
            LIBC(signal, signum, handler);
        }
        else
        {
            /* Install override */
            sa_user[signum].sa_handler = handler;
            sigemptyset(&sa_user[signum].sa_mask);
            sa_user[signum].sa_flags = 0;
            LIBC(signal, signum, signal_override_handler);
        }
    }
    else
    {
        if (handler == SIG_DFL || handler == SIG_IGN)
            old = LIBC(signal, signum, handler);
        else
        {
            /* Install override */
            signal_override[signum] = true;
            sa_user[signum].sa_handler = handler;
            sigemptyset(&sa_user[signum].sa_mask);
            sa_user[signum].sa_flags = 0;
            old = LIBC(signal, signum, signal_override_handler);
        }
    }

    TRACE_RETURN(SIGHANDLER, old);

    return old;
}

__attribute__((visibility("default")))
int
sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
    int ret;

    TRACE_CALL("sigaction");
    TRACE_ARG(INT, signum);
    TRACE_ARG(SIGACTION_PTR, act);
    TRACE_FLUSH();

    if (signum < 0 || signum >= NSIG)
        ret = LIBC(sigaction, signum, act, oldact);
    else if (signal_override[signum])
    {
        struct sigaction sa_override;

        if (oldact)
            *oldact = sa_user[signum];

        if (act)
        {
            /* Don't override SIG_DFL or SIG_IGN */
            if (act->sa_handler == SIG_DFL || act->sa_handler == SIG_IGN)
            {
                signal_override[signum] = false;
                ret = LIBC(sigaction, signum, act, NULL);
            }
            else
            {
                /* Install override */
                sa_override = sa_user[signum] = *act;
                if (sa_override.sa_flags & SA_SIGINFO)
                    sa_override.sa_sigaction = sigaction_override_handler;
                else
                    sa_override.sa_handler = signal_override_handler;
                ret = LIBC(sigaction, signum, &sa_override, NULL);
            }
        }
        else
            ret = 0;
    }
    else
    {
        struct sigaction sa_override;

        if (act == NULL || act->sa_handler == SIG_DFL ||
            act->sa_handler == SIG_IGN)
        {
            /* No need to install override */
            ret = LIBC(sigaction, signum, act, oldact);
        }
        else
        {
            /* Install override */
            sa_override = sa_user[signum] = *act;
            if (sa_override.sa_flags & SA_SIGINFO)
                sa_override.sa_sigaction = sigaction_override_handler;
            else
                sa_override.sa_handler = signal_override_handler;
            signal_override[signum] = true;
            ret = LIBC(sigaction, signum, &sa_override, oldact);
        }
    }

    TRACE_LAST_ARG(SIGACTION_PTR, oldact);
    TRACE_RETURN(INT, ret);

    return ret;
}

__attribute__((visibility("default")))
int
siginterrupt(int signum, int flag)
{
    int ret;

    TRACE_CALL("siginterrupt");
    TRACE_ARG(INT, signum);
    TRACE_LAST_ARG(INT, flag);
    TRACE_FLUSH();

    if (signum >= 0 && signum < NSIG)
    {
        if (flag)
            sa_user[signum].sa_flags &= ~SA_RESTART;
        else
            sa_user[signum].sa_flags |= SA_RESTART;
    }

    ret = LIBC(siginterrupt, signum, flag);

    TRACE_RETURN(INT, ret);

    return ret;
}
