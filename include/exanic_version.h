#ifndef EXANIC_VERSION_H
#define EXANIC_VERSION_H

/* Edit the 4 macros below should the version change */

#define EXANIC_VERSION_MAJOR        2
#define EXANIC_VERSION_MINOR        7
#define EXANIC_VERSION_REV          2
#define EXANIC_VERSION_EXTRA        "-git"

/* Do not edit these macros */

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)
#define EXANIC_VERSION_TEXT         STR(EXANIC_VERSION_MAJOR) "." STR(EXANIC_VERSION_MINOR) "." \
                                    STR(EXANIC_VERSION_REV) EXANIC_VERSION_EXTRA

#endif
