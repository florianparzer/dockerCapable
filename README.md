# DockerCapable
## notes
### execsnoop with clone
to check if a new container process is created by clone one could hook for
the return of the clone syscall and check the result value as this shows the pid of
the new process. however this pid is in the context of the pid namespace and therefore
not suitable for the capability tracing. To get the global pid one could check if the
ppid is already known as a pid of a container process and check the file 
/sys/fs/cgroup/system.slice/docker-<containerID>.scope/cgroup.procs of this
container for new entries. And then check the global pids status file
/proc/<pid>/status for the pid in the namespace