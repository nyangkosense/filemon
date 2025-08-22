# who

who is a simple file monitor that tracks which processes modify files

## usage

	who [-o output] directory

monitor `directory` recursively and log file changes to `output` (default: who.log)

## build

	make

requires linux with netlink connector support

## how it works

- uses inotify for file events
- uses netlink connector for process events  
- correlates file changes to processes via /proc filesystem
- filters kernel threads and long-running daemons
- prefers recently started user processes

## output format

	timestamp action path pid=N uid=N gid=N comm=name cwd=dir

## requirements

- linux 2.6.14+
- root privileges (for netlink connector)
- gcc with c99 support

## architecture

uses kernel apis directly instead of heavyweight frameworks:

- netlink connector catches all process lifecycle events (fork/exec/exit)
- inotify provides efficient file change notifications
- /proc filesystem gives process context (cwd, uid, comm)
- epoll multiplexes events in single thread

correlation heuristic: prefer recently started processes with directory access

who tracks process lifecycle events via netlink. processes started before
it's initialization are not tracked and may be incorrectly attributed to
long-running parent processes (shells, multiplexers). start who before
launching monitored applications for accurate correlation.

## limitations

- linux specific (netlink, /proc, inotify)
- requires root for netlink connector
- correlation is heuristic, not guaranteed accurate
- no support for containers/namespaces
- limited to MAX_PROCS (1024) tracked processes
- long pathnames may be truncated
- processes started before who cannot be correlated accurately

## license

MIT
