# dockercon-workshop
#### Dockercon 2016 Security Workshop

_Note: this exercise assumes your are on a host with direct access to the docker daemon and docker 1.10+, the instructions below are tailored to Ubuntu 16.04 running docker 1.11_

## Users in docker

By default, because the docker daemon runs as root, docker containers also run as root.  This gives our containers more privilege during runtime, but also means that they also hold root privileges on the underlying host.  Let's explore how we can achieve a more secure configuration: 

## The --users flag

1.  To verify that our docker daemon is running as root, try finding its process by running `ps aux | grep docker`

    You should see something like the output below, the first line is the process for running the `grep` command:
    ```
    ubuntu@node:~$ ps aux | grep docker
    ubuntu   10478  0.0  0.0  12944  1088 pts/0    S+   23:51   0:00 grep --color=auto docker
    root     23963  0.0  0.6 430616 49620 ?        Ssl  18:06   0:07 /usr/bin/docker daemon -H fd://
    root     23969  0.0  0.1 140572 14376 ?        Ssl  18:06   0:00 docker-containerd -l /var/run/docker/libcontainerd/docker-containerd.sock --runtime docker-runc --start-timeout 2m
	```

2.  To verify that docker containers default to running as root, run an alpine container with the `id` command:
	
	`docker run --rm alpine id`

3.  Let's try using the `--user` flag to change this.  `--user` is a flag to `docker run`, which can take a variety of argument types:
    `--user=[ user | user:group | uid | uid:gid | user:gid | uid:group ]`

    We'll use the `uid:gid` syntax, but please explore other argument formats at your leisure!  Let's make our container run as 10000:10000, and confirm that the flag worked by checking `id`:

	`docker run --rm --user 10000:10000 alpine id`

## Enabling user namespaces

Using the `--users` flag indeed useful, but what if our containers need to think they are the root process and we don't want them to actually be root?  Enter user namespaces: a tool long in the linux kernel, available in Docker 1.10+.  With user namespaces, we can enable the docker daemon to create a namespace for our containers that look like a root namespace, while in reality they map to a user namespace on the underlying host.  If you'd like to read more about how user namespaces work in Docker, please refer to the [daemon documentation](https://docs.docker.com/engine/reference/commandline/daemon/#daemon-user-namespace-options).  In particular, pay special attention to the `userns-remap` docker daemon flag.

Note of caution when you enable user namespaces, you'll have to account for permission changes on your image layers and volumes -- for this reason, it's advised to keep the daemon stably in user namespace mode if possible rather than switching back and forth between root and user namespaces.

For our next exercise, we'll enable user namespaces on our docker daemon:

1.  Stop your docker daemon.  Enabling user namespaces requires starting the docker daemon from a stopped state.  Run: `sudo systemctl stop docker`

2.  Restart the docker daemon with user namespaces in a background process -- we'll use the default settings for now: `sudo docker daemon --userns-remap=default &`.

    In the default settings, docker will create the `dockremap` user, which takes ranges from `/etc/subuid` and `/etc/subgid` -- open those files and try to understand what's going on!

    When you look closely, you'll notice that `dockremap` is allocated a particular block of 65536 PIDs, with the `X` number shown in the `X:65536` mapping to root in a container user namespace.  Check out the [daemon documentation](https://docs.docker.com/v1.10/engine/reference/commandline/daemon/#starting-the-daemon-with-user-namespaces-enabled) for more information.

3.  Let's check that we enabled user namespaces correctly!  Start an interactive alpine container: `docker run --rm -it alpine sh` and run `id`.  What do you see?  Try to also mount volumes that are owned by root on the end host (like `/proc`) -- can you access these from within the container?

    Also try running the same run command with the `--privileged` flag -- what do you see?  Privileged mode is incompatible with user namespaces, so the command will fail!

