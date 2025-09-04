/* See LICENSE file for copyright and license details.
 * filemon - monitors directory recursively and tracks which processes modify files
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

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
#include <sys/select.h>
#include <time.h>
#include <unistd.h>

#include <dirent.h>
#include <libgen.h>
#include <limits.h>

#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>
#include <sys/fanotify.h>

#include "proc.h"
#include "uid.h"

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
static Process procs[MAX_PROCS];
static int nprocs = 0;
static char dir[MAX_PATH];

static int usefan = -1, fanfd = -1;

struct fev {
	char path[256];
	pid_t pid;
	time_t ts;
};

static struct fev fevs[32];
static int nfevs = 0;

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
static int initfan(void);
static Process *corfan(const char *path, time_t ts);
static Process *corheur(const char *path, time_t ts);

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
	die("usage: filemon directory\n");
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
	int sock, bufsize = 65536;

	sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
	if (sock < 0)
		die("socket:");

	memset(&sa_nl, 0, sizeof(sa_nl));
	sa_nl.nl_family = AF_NETLINK;
	sa_nl.nl_groups = CN_IDX_PROC;
	sa_nl.nl_pid = getpid();

	if (bind(sock, (struct sockaddr *)&sa_nl, sizeof(sa_nl)) < 0)
		die("bind:");

	if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize)) < 0)
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

	if (send(sock, &msg, sizeof(msg), 0) < 0)
		die("send:");

	ev.events = EPOLLIN;
	ev.data.fd = sock;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, sock, &ev) < 0)
		die("epoll_ctl:");

	return sock;
}

static void
readfan(void)
{
    char buf[4096], path[256], fdpath[64];
    struct fanotify_event_metadata *meta;
    ssize_t len, plen;

    if ((len = read(fanfd, buf, sizeof(buf))) < (ssize_t)sizeof(*meta))
        return;

    for (meta = (struct fanotify_event_metadata *)buf; 
         FAN_EVENT_OK(meta, len); 
         meta = FAN_EVENT_NEXT(meta, len)) 
    {
        if (meta->fd >= 0)
            close(meta->fd);

        if (meta->vers != FANOTIFY_METADATA_VERSION || meta->fd < 0 || nfevs >= 32)
            continue;

        snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", meta->fd);

        if ((plen = readlink(fdpath, path, sizeof(path) - 1)) <= 0)
            continue;

        path[plen] = 0;

        strncpy(fevs[nfevs].path, path, sizeof(fevs[nfevs].path) - 1);
        fevs[nfevs].path[sizeof(fevs[nfevs].path) - 1] = 0;
        fevs[nfevs].pid = meta->pid;
        fevs[nfevs].ts = time(NULL);
        ++nfevs;
    }
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
	if (len < 0) {
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
	Process *p = procs;

	for (; p < procs + MAX_PROCS && (p->pid != pid || !p->active); ++p);
	return p < procs + MAX_PROCS ? p : NULL;
}

static void
addproc(pid_t pid, pid_t ppid, const char *comm)
{
	Process *proc = findproc(pid);
	
	if (!proc && (proc = procs, 1))
		for (; proc < procs + MAX_PROCS && proc->active; ++proc);
	if (proc >= procs + MAX_PROCS)
		return;
	proc->active || nprocs++;

	*proc = (Process){pid, ppid, 0, 0, "", "", time(NULL), 1};
	strncpy(proc->comm, comm, sizeof(proc->comm) - 1);
	proc->comm[sizeof(proc->comm) - 1] = '\0';

	updateproc(proc);
}

static void
rmproc(pid_t pid)
{
	Process *proc = findproc(pid);
	
	(proc && (proc->active = 0, nprocs--, 0));
}

static int
initinotify(const char *dir)
{
	struct epoll_event ev;
	int fd;

	fd = inotify_init1(IN_CLOEXEC);
	if (fd < 0)
		die("inotify_init1:");

	if (addwatch(fd, dir) < 0) {
		close(fd);
		die("add_watch_recursive:");
	}

	ev.events = EPOLLIN;
	ev.data.fd = fd;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev) < 0) {
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
	if (wd < 0)
		return -1;

	dir = opendir(path);
	if (!dir)
		return -1;

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.' && (!entry->d_name[1] || 
		    (entry->d_name[1] == '.' && !entry->d_name[2])))
			continue;

		if (snprintf(fullpath, sizeof(fullpath), "%s/%s",
		            path, entry->d_name) >= (int)sizeof(fullpath)) {
			closedir(dir);
			return -1;
		}

		if (stat(fullpath, &statbuf) < 0)
			continue;

		if (S_ISDIR(statbuf.st_mode)) {
			if (addwatch(fd, fullpath) < 0) {
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
	if (len < 0) {
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
	int cwdlen, dpathlen, result;

	if (!(fdir = strdup(filepath)))
		return 0;
	dpath = dirname(fdir);

	if (!proc->cwd[0] || !strcmp(proc->cwd, "unknown")) {
		free(fdir);
		return 0;
	}

	cwdlen = strlen(proc->cwd);
	dpathlen = strlen(dpath);

	result = !strcmp(dpath, proc->cwd) ||
	         (!strncmp(dpath, proc->cwd, cwdlen) && dpath[cwdlen] == '/') ||
	         (!strncmp(proc->cwd, dpath, dpathlen) && proc->cwd[dpathlen] == '/');

	free(fdir);
	return result;
}

static Process *
corheur(const char *path, time_t ts)
{
	Process *best, *proc;
	time_t bestdiff, diff;

	best = NULL;
	bestdiff = LONG_MAX;

	for (proc = procs; proc < procs + MAX_PROCS; ++proc) {
		if (!proc->active || proc->start > ts ||
		    proc->pid < 100 || ts - proc->start > 86400 || 
		    strstr(proc->comm, "kworker") || strstr(proc->comm, "ksoftirqd") ||
		    strstr(proc->comm, "migration") || proc->comm[0] == '[')
			continue;

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

static Process *
corfan(const char *path, time_t ts)
{
	int i;

    for (i = 0; i < nfevs; ++i) {
        if (ts - fevs[i].ts > 5 || strcmp(fevs[i].path, path)) {
            continue;
        }
        Process *proc = findproc(fevs[i].pid);
        if (proc) {
            updateproc(proc);
            return proc;
        }
        addproc(fevs[i].pid, 0, "fanotify");
        if ((proc = findproc(fevs[i].pid))) {
            updateproc(proc);
            return proc;
        }
        return NULL;
    }
    return NULL;
}

static Process *
correlate(const char *path, time_t ts)
{
    Process *proc;
    fd_set rfds;
	int result;
    struct timeval tv = {0, 0};

    if (usefan < 0) {
        initfan();
    }

    if (usefan && fanfd >= 0) {
        FD_ZERO(&rfds);
        FD_SET(fanfd, &rfds);

        result = select(fanfd + 1, &rfds, NULL, NULL, &tv);

        if (result > 0) {
            readfan();
        }
    }

    if (usefan) {
        proc = corfan(path, ts);
        if (proc) {
            return proc;
        }
    }

    return corheur(path, ts);
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
		printf("%s %s %s pid=%d user=%s gid=%d comm=%s cwd=%s\n",
		       ts, maskstr(mask), path,
		       proc->pid, uidname(proc->uid), proc->gid, proc->comm, proc->cwd);
	} else {
		printf("%s %s %s pid=? user=? gid=? comm=? cwd=?\n",
		       ts, maskstr(mask), path);
	}

	fflush(stdout);
}

static void
cleanup(void)
{
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

	while ((entry = readdir(proc_dir))) {
		pid = strtol(entry->d_name, &endptr, 10);
		if (!(*endptr || pid <= 0))
			addproc(pid, 0, "existing");
	}

	closedir(proc_dir);
}

static int
initfan(void)
{
	struct epoll_event ev;
	
	return usefan != -1 ? usefan :
	       (usefan = 0,
	        !getuid() &&
	        (fanfd = fanotify_init(FAN_CLASS_NOTIF, O_RDONLY | O_LARGEFILE)) >= 0 &&
	        !fanotify_mark(fanfd, FAN_MARK_ADD | FAN_MARK_MOUNT, 
	                      FAN_MODIFY | FAN_CLOSE_WRITE | FAN_OPEN | FAN_ACCESS, AT_FDCWD, dir) &&
	        (ev.events = EPOLLIN, ev.data.fd = fanfd,
	         !epoll_ctl(efd, EPOLL_CTL_ADD, fanfd, &ev)) ?
	        (usefan = 1) : (fanfd >= 0 && close(fanfd), fanfd = -1, 0));
}

int
main(int argc, char **argv)
{
  (void)argc;
	int nfds;
	struct epoll_event events[MAX_EVENTS];

	if (!*++argv)
		usage();

	if (strlen(*argv) >= MAX_PATH)
		die("directory path too long");

	strcpy(dir, *argv);

	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);


	efd = epoll_create1(EPOLL_CLOEXEC);
	if (efd < 0)
		die("epoll_create1:");

	nlfd = initnetlink();
	ifd = initinotify(dir);
	

	uidinit();
	scanprocs();

	printf("filemon - started monitoring %s\n", dir);
	printf("active processes: %d\n", nprocs);
	fflush(stdout);

  for (; state != STATE_SHUTDOWN;) {
		nfds = epoll_wait(efd, events, MAX_EVENTS, -1);
		if (nfds < 0) {
			if (errno == EINTR)
				continue;
			die("epoll_wait:");
		}

		for (struct epoll_event *ev = events; ev < events + nfds; ++ev)
			ev->data.fd == nlfd ? handleproc() :
			ev->data.fd == fanfd ? readfan() : handlefile();
	}

	cleanup();
	return 0;
}
