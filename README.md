# dockercon-workshop
#### Dockercon 2016 Security Workshop

## cgroups

cgroups, short for "control groups," implement resource accounting and limiting in Docker containers. They provide a lot of very useful metrics, but they also help to ensure that each container gets its fair share of memory, CPU, disk I/O; and, more importantly, that a single container cannot bring the system down by exhausting one of those resources.


## cgroups fom Docker CLI

cgroups are specified as flags to `docker run`.  In particular, the following flags are of note for this exercise:
```
$ docker run --help
...
  --cgroup-parent                 Optional parent cgroup for the container
  ...
  --cpu-period                    Limit CPU CFS (Completely Fair Scheduler) period
  --cpu-quota                     Limit CPU CFS (Completely Fair Scheduler) quota
  --cpuset-cpus                   CPUs in which to allow execution (0-3, 0,1)
  ...
  --pids-limit                    Tune container pids limit (set -1 for unlimited)
```
Each of these (and more) resource-limiting flags (for memory, IO, etc.) are described in-depth in the [Docker run reference](https://docs.docker.com/engine/reference/run/#specifying-custom-cgroups), though we'll focus on the above flags for this workshop.


## Restricting a cpu-hungry container

Let's dig deeper into the cpu cgroups!  We've put together a demo in the `cpu-stress` directory in this branch.



## cgroups from Docker Compose

While there is a fairly direct translation to the same flags in docker-compose, be aware that there are some slight differences.  To view the differences, check out this section of the [Docker compose file reference](https://docs.docker.com/compose/compose-file/#cpu-shares-cpu-quota-cpuset-domainname-hostname-ipc-mac-address-mem-limit-memswap-limit-privileged-read-only-restart-shm-size-stdin-open-tty-user-working-dir).

There are slight differences in the option names, for example `cpuset` corresponds to `cpuset-cpus`, and requires a string argument.




## Stopping a fork bomb!

- fork bomb demo


`docker run --rm -it --pids-limit 200 debian:jessie bash`
`:(){ :|: & };:`
