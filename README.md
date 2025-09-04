# filemon

*filemon tracks which processes modify files on Linux*. 
It gives you the PID, user, command, and working directory without pulling in a web of dependencies or frameworks. Why should finding out which process wrote to a file require complex setups, containers, or megabytes of libraries? 

No configuration files, no plugins, no threads, using built-in Linux interfaces like fanotify or falls back to simple heuristics when permissions or kernel limitations demand it. If any part of the system fails, it degrades, it doesn't crash. 

Example output:
```
filemon - started monitoring /tmp/
active processes: 326
2025-09-04 11:50:43 CREATE /tmp/dddd pid=31486 user=smi gid=1000 comm=mksh cwd=/tmp
2025-09-04 11:50:49 DELETE /tmp/dddd pid=31486 user=smi gid=1000 comm=mksh cwd=/tmp
```

filemon prints directly to `stdout` because that is a universal interface.
Other formats (e.g., JSON, XML, or databases) impose structure and assumptions on the output, locking you into specific use cases or requiring additional processing tools.
If you want JSON for example, you can pipe the output to a formatter. If you want to filter specific fields, `grep`, `sed`, `cut` or `awk` can do it for you.

## How It Works

filemon uses `inotify` to monitor file operations, enhanced by two methods for associating events with processes:

 When running as root, it uses `fanotify` to obtain exact PIDs for write operations. Events from inotify and fanotify are correlated by matching paths and timestamps. 
 
 Without root privileges, a heuristic approach is used instead: the process table is scanned for processes that started before the event and are likely responsible. While this fallback is less precise, it works for most scenarios.

Some events, like metadata updates (`chmod`, `unlink`) or deletes, do not generate fanotify notifications, even with root. These always rely on the heuristic. The process table is maintained dynamically using netlink to track active processes, ensuring it is accurate during correlation.

## Design and Implementation

Events are processed sequentially, avoiding threads or dependencies. Fanotify events are cached in a lightweight ring buffer indexed by path. On an inotify event, this cache is checked first. If no match exists, filemon falls back to consulting the process table. 

## Limitations

Accurate PID detection requires root. Without it, the heuristic may miss operations that occur quickly or involve multiple writers. Metadata operations and deletes always use the heuristic, regardless of privileges, due to kernel limitations. Network filesystems may not emit events depending on their mount options and protocols. The program is designed only for local filesystems. Modern distributions with restrictions on kernel interfaces such as `eBPF` may further constrain the heuristic's effectiveness.

## Compatibility

The program requires Linux 2.6.37 or newer to use fanotify. For older kernels, only heuristic correlation is available. It has been tested on kernel versions from 3.10 to 6.x and works in containers when fanotify is permitted. It compiles on any POSIX system, but the monitoring is Linux-specific. There are no runtime dependencies, special kernel modules, or configuration files. A single binary can run anywhere. 

## Testing

Testing is manual to preserve simplicity. Automated process correlation testing would introduce unnecessary complexity that goes against the program's minimalistic design.
