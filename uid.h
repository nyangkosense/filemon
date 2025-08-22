/* See LICENSE file for copyright and license details. */

#ifndef UID_H
#define UID_H

#include <sys/types.h>

void uidinit(void);
const char *uidname(uid_t uid);

#endif
