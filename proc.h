/* See LICENSE file for copyright and license details. */

#ifndef PROC_H
#define PROC_H

#include <sys/types.h>
#include <time.h>

#define MAX_PATH 4096

typedef struct Process {
	pid_t pid;
	pid_t ppid;
	uid_t uid;
	gid_t gid;
	char comm[16];
	char cwd[MAX_PATH];
	time_t start;
	int active;
} Process;

void getcomm(Process *proc);
void getprocwd(Process *proc);
void getids(Process *proc);
void updateproc(Process *proc);

#endif
