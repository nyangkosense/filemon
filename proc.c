/* See LICENSE file for copyright and license details. */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "proc.h"

void
getcomm(Process *proc)
{
	char path[256], buf[256];
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/comm", proc->pid);
	if ((f = fopen(path, "r"))) {
		if (fgets(buf, sizeof(buf), f))
			buf[strcspn(buf, "\n")] = '\0';
		strncpy(proc->comm, buf, sizeof(proc->comm) - 1);
		proc->comm[sizeof(proc->comm) - 1] = '\0';
		fclose(f);
	}
}

void
getprocwd(Process *proc)
{
	char path[256];
	ssize_t len;

	snprintf(path, sizeof(path), "/proc/%d/cwd", proc->pid);
	len = readlink(path, proc->cwd, sizeof(proc->cwd) - 1);
	
	if (len != -1)
		proc->cwd[len] = '\0';
	else
		strcpy(proc->cwd, "unknown");
}

void
getids(Process *proc)
{
	char path[256], buf[256];
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/status", proc->pid);
	if ((f = fopen(path, "r"))) {
		while (fgets(buf, sizeof(buf), f)) {
			if (!strncmp(buf, "Uid:", 4))
				sscanf(buf, "Uid:\t%u", &proc->uid);
			else if (!strncmp(buf, "Gid:", 4))
				sscanf(buf, "Gid:\t%u", &proc->gid);
		}
		fclose(f);
	}
}

void
updateproc(Process *proc)
{
	getcomm(proc);
	getprocwd(proc);
	getids(proc);
}
