#ifndef _VERSION_H_
#define _VERSION_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* check lighttpd version */
#if LIGHTTPD_VERSION_ID < 0x10500
#define LIGHTTPD_V14 1
#else
#define LIGHTTPD_V15 1
#endif

#ifdef HAVE_VERSION_H
# include "versionstamp.h"
#else
# define REPO_VERSION ""
#endif

#define PACKAGE_DESC PACKAGE_NAME "/" PACKAGE_VERSION REPO_VERSION

#endif
