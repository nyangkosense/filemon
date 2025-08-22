/* See LICENSE file for copyright and license details.
 * who - file change process tracker
 * Monitors directory recursively and tracks which processes modify files
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <dirent.h>
#include <libgen.h>
#include <limits.h>

#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>

#include "proc.h"

#define MAX_EVENTS 10
#define MAX_PROCS 1024
#define MAX_PATH 4096
#define PROC_BUF_SIZE 1024

enum {
	STATE_INIT,
	STATE_MONITORING,
	STATE_SHUTDOWN
};

typedef struct FileEvent {
	char path[MAX_PATH];
	time_t ts;
	uint32_t mask;
} FileEvent;

/* global state */
static int state = STATE_INIT;
static int nlfd = -1;
static int ifd = -1;
static int efd = -1;
static FILE *out = NULL;
static Process procs[MAX_PROCS];
static int nprocs = 0;
static char dir[MAX_PATH];

/* function declarations */
static void die(const char *fmt, ...);
static void usage(void);
static int initnetlink(void);
static int initinotify(const char *dir);
static int addwatch(int fd, const char *path);
static void handleproc(void);
static void handlefile(void);
static Process *findproc(pid_t pid);
static void addproc(pid_t pid, pid_t ppid, const char *comm);
static void rmproc(pid_t pid);
static Process *correlate(const char *path, time_t timestamp);
static void logchange(const char *path, Process *proc, uint32_t mask);
static void cleanup(void);
static void sighandler(int sig);
static void scanprocs(void);

static void
die(const char *fmt, ...)
{
	va_list ap;
	int saved_errno;

	saved_errno = errno;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	if (fmt[0] && fmt[strlen(fmt)-1] == ':')
		fprintf(stderr, " %s", strerror(saved_errno));
	fputc('\n', stderr);

	exit(1);
}

static void
usage(void)
{
	die("usage: who [-o output] directory\n");
}

int
main(int argc, char *argv[])
{
	const char *outpath;
	int opt, nfds;
	struct epoll_event events[MAX_EVENTS];

	outpath = "who.log";

	while ((opt = getopt(argc, argv, "o:")) != -1) {
		switch (opt) {
		case 'o':
			outpath = optarg;
			break;
		default:
			usage();
		}
	}

	if (optind >= argc)
		usage();

	if (strlen(argv[optind]) >= MAX_PATH)
		die("directory path too long");

	strcpy(dir, argv[optind]);

	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);

	out = fopen(outpath, "w");
	if (!out)
		die("fopen %s:", outpath);

	efd = epoll_create1(EPOLL_CLOEXEC);
	if (efd == -1)
		die("epoll_create1:");

	nlfd = initnetlink();
	ifd = initinotify(dir);

	scanprocs();

	state = STATE_MONITORING;
	fprintf(out, "# Who - started monitoring %s\n", dir);
	fprintf(out, "# Active processes: %d\n", nprocs);
	fflush(out);

	while (state == STATE_MONITORING) {
		nfds = epoll_wait(efd, events, MAX_EVENTS, -1);
		if (nfds == -1) {
			if (errno == EINTR)
				continue;
			die("epoll_wait:");
		}

		for (int i = 0; i < nfds; i++) {
			if (events[i].data.fd == nlfd) {
				handleproc();
			} else if (events[i].data.fd == ifd) {
				handlefile();
			}
		}
	}

	cleanup();
	return 0;
}

static void
sighandler(int sig)
{
	(void)sig;
	state = STATE_SHUTDOWN;
}

static int
initnetlink(void)
{
	struct sockaddr_nl sa_nl;
	struct epoll_event ev;
	int sock;

	sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
	if (sock == -1)
		die("socket:");

	memset(&sa_nl, 0, sizeof(sa_nl));
	sa_nl.nl_family = AF_NETLINK;
	sa_nl.nl_groups = CN_IDX_PROC;
	sa_nl.nl_pid = getpid();

	if (bind(sock, (struct sockaddr *)&sa_nl, sizeof(sa_nl)) == -1)
		die("bind:");

	/* Increase socket buffer size */
	int bufsize = 65536;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize)) == -1)
		die("setsockopt:");

	struct {
		struct nlmsghdr nl_hdr;
		struct cn_msg cn_msg;
		enum proc_cn_mcast_op cn_mcast;
	} msg;

	memset(&msg, 0, sizeof(msg));
	msg.nl_hdr.nlmsg_len = sizeof(msg);
	msg.nl_hdr.nlmsg_type = NLMSG_DONE;
	msg.nl_hdr.nlmsg_flags = 0;
	msg.nl_hdr.nlmsg_seq = 0;
	msg.nl_hdr.nlmsg_pid = getpid();

	msg.cn_msg.id.idx = CN_IDX_PROC;
	msg.cn_msg.id.val = CN_VAL_PROC;
	msg.cn_msg.len = sizeof(enum proc_cn_mcast_op);
	msg.cn_mcast = PROC_CN_MCAST_LISTEN;

	if (send(sock, &msg, sizeof(msg), 0) == -1)
		die("send:");

	ev.events = EPOLLIN;
	ev.data.fd = sock;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, sock, &ev) == -1)
		die("epoll_ctl:");

	return sock;
}

static void
handleproc(void)
{
	struct {
		struct nlmsghdr nl_hdr;
		struct cn_msg cn_msg;
		struct proc_event proc_ev;
	} msg;
	ssize_t len;
	struct proc_event *ev;

	len = recv(nlfd, &msg, sizeof(msg), 0);
	if (len == -1) {
		if (errno == EINTR || errno == EAGAIN)
			return;
		die("recv:");
	}

	if (len < (ssize_t)(sizeof(msg.nl_hdr) + sizeof(msg.cn_msg)))
		return;

	ev = &msg.proc_ev;

	switch (ev->what) {
	case PROC_EVENT_EXEC:
		addproc(ev->event_data.exec.process_pid,
		        ev->event_data.exec.process_tgid,
		        "unknown");
		break;
	case PROC_EVENT_EXIT:
		rmproc(ev->event_data.exit.process_pid);
		break;
	case PROC_EVENT_FORK:
		addproc(ev->event_data.fork.child_pid,
		        ev->event_data.fork.parent_pid,
		        "unknown");
		break;
	default:
		break;
	}
}

static Process *
findproc(pid_t pid)
{
	int i;

	for (i = 0; i < nprocs; i++) {
		if (procs[i].active && procs[i].pid == pid)
			return &procs[i];
	}
	return NULL;
}

static void
addproc(pid_t pid, pid_t ppid, const char *comm)
{
	Process *proc;
	int i;

	proc = findproc(pid);
	if (!proc) {
		for (i = 0; i < MAX_PROCS; i++) {
			if (!procs[i].active) {
				proc = &procs[i];
				nprocs++;
				break;
			}
		}
	}

	if (!proc)
		return;

	proc->pid = pid;
	proc->ppid = ppid;
	proc->active = 1;
	proc->start = time(NULL);
	strncpy(proc->comm, comm, sizeof(proc->comm) - 1);
	proc->comm[sizeof(proc->comm) - 1] = '\0';

	updateproc(proc);
}

static void
rmproc(pid_t pid)
{
	Process *proc;

	proc = findproc(pid);
	if (proc) {
		proc->active = 0;
		nprocs--;
	}
}

static int
initinotify(const char *dir)
{
	struct epoll_event ev;
	int fd;

	fd = inotify_init1(IN_CLOEXEC);
	if (fd == -1)
		die("inotify_init1:");

	if (addwatch(fd, dir) == -1) {
		close(fd);
		die("add_watch_recursive:");
	}

	ev.events = EPOLLIN;
	ev.data.fd = fd;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		close(fd);
		die("epoll_ctl:");
	}

	return fd;
}

static int
addwatch(int fd, const char *path)
{
	DIR *dir;
	struct dirent *entry;
	struct stat statbuf;
	char fullpath[MAX_PATH];
	int wd;

	wd = inotify_add_watch(fd, path, IN_CREATE | IN_DELETE | IN_MODIFY |
	                       IN_MOVED_FROM | IN_MOVED_TO | IN_CLOSE_WRITE);
	if (wd == -1)
		return -1;

	dir = opendir(path);
	if (!dir)
		return -1;

	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0)
			continue;

		if (snprintf(fullpath, sizeof(fullpath), "%s/%s",
		            path, entry->d_name) >= (int)sizeof(fullpath)) {
			closedir(dir);
			return -1;
		}

		if (stat(fullpath, &statbuf) == -1)
			continue;

		if (S_ISDIR(statbuf.st_mode)) {
			if (addwatch(fd, fullpath) == -1) {
				closedir(dir);
				return -1;
			}
		}
	}

	closedir(dir);
	return 0;
}

static void
handlefile(void)
{
	char buffer[4096], path[MAX_PATH], *ptr;
	ssize_t len;
	struct inotify_event *event;
	Process *proc;

	len = read(ifd, buffer, sizeof(buffer));
	if (len == -1) {
		if (errno == EINTR || errno == EAGAIN)
			return;
		die("read:");
	}

	ptr = buffer;
	while (ptr < buffer + len) {
		event = (struct inotify_event *)ptr;

		if (event->len > 0) {
			if (dir[strlen(dir) - 1] == '/') {
				snprintf(path, sizeof(path), "%s%s",
				         dir, event->name);
			} else {
				snprintf(path, sizeof(path), "%s/%s",
				         dir, event->name);
			}

			proc = correlate(path, time(NULL));

			logchange(path, proc, event->mask);

			if (event->mask & IN_CREATE) {
				struct stat statbuf;
				if (stat(path, &statbuf) == 0 &&
				    S_ISDIR(statbuf.st_mode)) {
					addwatch(ifd, path);
				}
			}
		}

			ptr += sizeof(struct inotify_event) + event->len;
	}
}


static int
hasaccess(Process *proc, const char *filepath)
{
	char *fdir, *dpath;
	int cwdlen, dpathlen;

	if (!(fdir = strdup(filepath)))
		return 0;
	dpath = dirname(fdir);

	if (!proc->cwd[0] || !strcmp(proc->cwd, "unknown")) {
		free(fdir);
		return 0;
	}

	cwdlen = strlen(proc->cwd);
	dpathlen = strlen(dpath);

	int result = !strcmp(dpath, proc->cwd) ||
	            (!strncmp(dpath, proc->cwd, cwdlen) && dpath[cwdlen] == '/') ||
	            (!strncmp(proc->cwd, dpath, dpathlen) && proc->cwd[dpathlen] == '/');

	free(fdir);
	return result;
}

static Process *
correlate(const char *path, time_t ts)
{
	Process *best, *proc;
	time_t bestdiff, diff;
	int i;

	best = NULL;
	bestdiff = LONG_MAX;

	for (i = 0; i < MAX_PROCS; i++) {
		proc = &procs[i];

		if (!proc->active || proc->start > ts)
			continue;

		if (proc->pid < 100 || ts - proc->start > 86400 || 
		    strstr(proc->comm, "kworker") || strstr(proc->comm, "ksoftirqd") ||
		    strstr(proc->comm, "migration") || proc->comm[0] == '[')
			continue;

		/* Only update process info if it's stale */
		if (ts - proc->start > 60)
			updateproc(proc);

		if (!hasaccess(proc, path))
			continue;

		diff = ts - proc->start;
		if (diff < bestdiff) {
			bestdiff = diff;
			best = proc;
		}
	}

	return best;
}

static const char *
maskstr(uint32_t mask)
{
	if (mask & IN_CREATE)
		return "CREATE";
	if (mask & IN_DELETE)
		return "DELETE";
	if (mask & IN_MODIFY)
		return "MODIFY";
	if (mask & IN_CLOSE_WRITE)
		return "WRITE";
	if (mask & IN_MOVED_FROM)
		return "MOVE_FROM";
	if (mask & IN_MOVED_TO)
		return "MOVE_TO";
	return "UNKNOWN";
}

static void
logchange(const char *path, Process *proc, uint32_t mask)
{
	time_t now;
	struct tm *tm;
	char ts[32];

	now = time(NULL);
	tm = localtime(&now);
	strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

	if (proc) {
		fprintf(out, "%s %s %s pid=%d uid=%d gid=%d comm=%s cwd=%s\n",
		        ts, maskstr(mask), path,
		        proc->pid, proc->uid, proc->gid, proc->comm, proc->cwd);
	} else {
		fprintf(out, "%s %s %s pid=? uid=? gid=? comm=? cwd=?\n",
		        ts, maskstr(mask), path);
	}

	fflush(out);
}

static void
cleanup(void)
{
	if (out) {
		fprintf(out, "# Who - shutdown\n");
		fclose(out);
	}
	if (nlfd != -1)
		close(nlfd);
	if (ifd != -1)
		close(ifd);
	if (efd != -1)
		close(efd);
}

static void
scanprocs(void)
{
	DIR *proc_dir;
	struct dirent *entry;
	pid_t pid;
	char *endptr;

	proc_dir = opendir("/proc");
	if (!proc_dir)
		return;

	while ((entry = readdir(proc_dir)) != NULL) {
		pid = strtol(entry->d_name, &endptr, 10);
		if (*endptr != '\0' || pid <= 0)
			continue;

		addproc(pid, 0, "existing");
	}

	closedir(proc_dir);
}
