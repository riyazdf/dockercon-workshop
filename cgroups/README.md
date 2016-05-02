# dockercon-workshop
#### Dockercon 2016 Security Workshop

## cgroups

cgroups, short for "control groups," implement resource accounting and limiting in Docker containers. They provide a lot of very useful metrics, but they also help to ensure that each container gets its fair share of memory, CPU, disk I/O; and, more importantly, that a single container cannot bring the system down by exhausting one of those resources.


## cgroups fom Docker CLI

cgroups are specified as flags to `docker run`.  In particular, the following flags are of note for this exercise:
```
$ docker run --help
...
  --cpu-shares                    CPU shares (relative weight)
  ...
  --cpuset-cpus                   CPUs in which to allow execution (0-3, 0,1)
  ...
  --pids-limit                    Tune container pids limit (set -1 for unlimited)
```

Each of these (and more) resource-limiting flags (for memory, IO, etc.) are described in-depth in the [Docker run reference](https://docs.docker.com/engine/reference/run/#specifying-custom-cgroups), though we'll focus on the above flags for this workshop.


## Restricting a cpu-hungry container

Let's dig deeper into the cpu cgroups!  We've put together a demo in the `cpu-stress` directory in this branch:

1. Go to the `cpu-stress` directory: `cd cpu-stress`

2. Open the `Dockerfile` - you should notice that it's a simple ubuntu image that downloads a tool called [`stress`](http://people.seas.harvard.edu/~apw/stress/).  `stress` can generate workloads to max out resources on a machine.  In this Dockerfile, we're specifying stress to fill up the computing power of two cpus.

3. Build the image specified in the `Dockerfile`: `docker build -t stress_cpu .`

4. Run the image you just built in a container: `docker run stress_cpu` -- now, in a separate terminal run `htop` to view this container maxing out two CPUs. If you don't have `htop` installed, you can get it with `apt get install htop`.

5. Kill the `stress_cpu` container after viewing the `htop` results.

6. Let's use cgroups to restrict this image to only one CPU!  The `--cpuset-cpus` flag can let us specify which CPU (zero-indexed) to allow the container to run on: run `docker run --cpuset-cpus 0 stress_cpu`.

7. Look at `htop` again in a separate terminal -- note that only one CPU (the first one) is maxed out!  You should also notice that there are still two `stress` processes running, each taking around 50% CPU since we specified two "stress CPU hogs," but cgroups have limited our container to CPU 0.

8. Kill the `stress_cpu` container after viewing the `htop` results.

9. By default, Docker containers get the same proportion of CPU resources. We can use the `--cpu-shares` cgroup flag to change the relative weights of CPU resources between running containers.  Let's give this a try with multiple stress containers:

   - The default CPU share amount is 1024 ([reference here](https://docs.docker.com/engine/reference/run/#cpu-share-constraint): so let's spin up two stress containers with 512 shares each: run `docker run --cpuset-cpus 0 --cpu-shares 512 stress_cpu` in two separate terminals

   - In a third terminal, run `htop` - you should see four stress hogs, each with 25% share of the first CPU.  You can re-run these containers with different weights to try to understand how the shares work; how would you split CPU shares to have one container take 25% of the first CPU and the other take 75%


## cgroups from Docker Compose

While there is a fairly direct translation to the same flags in docker-compose, be aware that there are some slight differences.  To view the differences, check out this section of the [Docker compose file reference](https://docs.docker.com/compose/compose-file/#cpu-shares-cpu-quota-cpuset-domainname-hostname-ipc-mac-address-mem-limit-memswap-limit-privileged-read-only-restart-shm-size-stdin-open-tty-user-working-dir).

There are slight differences in the option names, for example `cpuset` corresponds to `cpuset-cpus`, and requires a string argument.

1.  Edit the provided `docker-compose.yml` to add a `cpuset` option that restricts the stress container to CPU 0, like we did in the previous exercise.  Verify your compose setup by running `docker-compose up` and checking `htop` in a separate terminal.


## Stopping a fork bomb!

In Docker 1.11, we added the `--pids-limit` cgroup option to `docker run`, which limits the number of processes a Docker container can fork during runtime -- we'll use this cgroup to protect us from fork bombs!

1.  When you're ready, try running debian with a 200 PID limit, and watch a fork-bomb fail:
    `docker run --rm -it --pids-limit 200 debian:jessie bash`
    If you see `WARNING: Your kernel does not support pids limit capabilities, pids limit discarded.` - DO NOT run the following command, instead watch this video: https://asciinema.org/a/cw02ou3qjbojlf3peh2tdaff1?loop=1&speed=4

    Else, run the fork bomb below:

    `/# :(){ :|: & };: # Run at your own risk`

    You'll need to Ctrl-C to escape, but your machine will do so and you'll survive unscathed :)