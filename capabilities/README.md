# dockercon-workshop
#### Dockercon 2016 Security Workshop

## Capabilities

Capabilities split up the privileges of the root user into multiple sets, allowing the root user to not be all-powerful and/or a regular user to gain some of the capabilities normally associated with root without having to actually execute with full root access.
Capabilities apply to both threads and files.
File capabilities allow users to execute programs with higher privileges than themselves, similarly to how the setuid bit works.
Thread capabilities keep track of the current state of capabilities in running programs.
In a Linux system there are multiple capability sets per thread and they interact in complex ways with the capability bits on files.
When using docker there are certain limitations that make managing capabilities much simpler.
Docker images don't have files with capabilities because extended attributes are stripped during build.
It's still possible to put files with capabilities into docker containers using volumes, bind mounts or by adding files during run time, but this is not recommended.
In an environment without file based capabilities, it's not possible for applications to escalate their privileges beyond the "bounding set".
Docker sets the bounding set before starting a container.
You can use docker commands to add or remove capabilities to or from the bounding set.

### Docker capabilities

Docker allows your to specify what capabilities you want your docker container's root process to have when running a docker image.

Examples:

```
docker run --rm -it --cap-add $CAP alpine sh
docker run --rm -it --cap-drop $CAP alpine sh
docker run --rm -it --cap-drop ALL --cap-add $CAP alpine sh
```

Docker capabilities constants are not prefixed with `CAP_` but otherwise match the kernel's constants.

The man page for capabilities has the full list: http://man7.org/linux/man-pages/man7/capabilities.7.html

You have 3 options for using capabilities with docker right now as of docker 1.12:

1. run as root with a large set of capabilities and try to manage capabilities within your container manually
2. run as root with limited capabilities and never change them within a container
3. run as an unprivileged user and no capabilities

The first option should be avoided whenever possible. The best case scenario is number 3. The second option is the best you can do right now if you do need some capabilities.

Another option may be added in future versions of docker to run a non-root user with some capabilities. The correct way of doing this requires ambient capabilities and was added in kernel version 4.3. Whether or not it's possible for docker to approximate this behaviour in older kernels requires more research.

### Tools

There are two main sets of tools for managing capabilities: libcap and libcap-ng.
Libcap focuses more on manipulating capabilities while libcap-ng has some really useful tools for auditing.
Here are the most useful commands from them.

libcap

* capsh - lets you modify capabilities within its own process in arbitrary ways and then execute a shell
* setcap - set capability bits on a file
  * `setcap cap_sys_admin+pie ls`
  * `setcap -r ls`
* getcap - get the capability bits from a file
  * `getcap -r .`

libcap-ng

* pscap - list the capabilities of running processes
* filecap - list the capabilities of files
* captest - check what capabilities are available to the captest process

#### More libcap/libcap-ng usage examples

**Printing out all capabilities**

In alpine you need to install the libcap package to use capsh:
```
$ docker run --rm -it alpine sh -c 'apk add -U libcap; capsh --print'
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

The syntax for the "Current" sets is confusing. "Current" is multiple sets separated by a space. Multiple capabilities within the same set are separated by a `,`. The letters after the `+` suffix describe what the set is. `e` is effective `i` is inheritable `p` is permitted. See the capabilities manpage to understand what these sets mean.

**Experimenting with capabilities**

capsh usage:
```
usage: capsh [args ...]
  --help         this message (or try 'man capsh')
  --print        display capability relevant state
  --decode=xxx   decode a hex string to a list of caps
  --supports=xxx exit 1 if capability xxx unsupported
  --drop=xxx     remove xxx,.. capabilities from bset
  --caps=xxx     set caps as per cap_from_text()
  --inh=xxx      set xxx,.. inheritiable set
  --secbits=<n>  write a new value for securebits
  --keep=<n>     set keep-capabability bit to <n>
  --uid=<n>      set uid to <n> (hint: id <username>)
  --gid=<n>      set gid to <n> (hint: id <username>)
  --groups=g,... set the supplemental groups
  --user=<name>  set uid,gid and groups to that of user
  --chroot=path  chroot(2) to this path
  --killit=<n>   send signal(n) to child
  --forkfor=<n>  fork and make child sleep for <n> sec
  ==             re-exec(capsh) with args as for --
  --             remaing arguments are for /bin/bash
                 (without -- [capsh] will simply exit(0))
```

> Warning:
> `--drop` sounds like what you want to do, but it affects only the bounding set. This can be very confusing because it doesn't actually take away the capability from the effective or inheritable set. You almost always want to use `--caps`.

**Modifying capabilities**

You can use libcap:

```
$ setcap cap_net_raw=ep $file
```

Or libcap-ng:

```
$ filecap /absolute/path net_raw
```

**Auditing**

There are multiple ways to read out the capabilites from a file.

Using libcap:

```
$ getcap $file
```

Using libcap-ng:

```
$ filecap /absolue/path/to/file
```

Using extended attributes (attr package):

```
$ getfattr -n security.capability $file
# file: $file
security.capability=0sAQAAAgAgAAAAAAAAAAAAAAAAAAA=
```

### Demo

This succeeds because by default root has the chown capability.

```
$ docker run --rm -it alpine chown nobody /
```

This shows that the chown command works when it has only the chown capability.

```
$ docker run --rm -it --cap-drop ALL --cap-add CHOWN alpine chown nobody /
```

This fails because we removed the chown capability from root.

```
$ docker run --rm -it --cap-drop CHOWN alpine chown nobody /
chown: /: Operation not permitted
```

This shows that docker doesn't currently support adding capabilities to non-root users.

```
$ docker run --rm -it --cap-add chown -u nobody alpine chown nobody /
chown: /: Operation not permitted
```

### Tips

Your docker images can't have files with capability bits set, so it's unlikely that programs
in docker containers can use capabilities to escalate privileges. You should make sure 
that none of the volumes you are mounting into docker containers contain files with capability bits set.

You can audit directories for capability bits withe the following commands:
```
# with libcap
getcap -r /
# with libcap-ng
filecap -a
```

To remove capability bits you can use.
```
# with libcap
setcap -r $file
# with libcap-ng
filecap /path/to/file none
```

### Further reading:

This explains capabilities in a lot of detail. If you plan to run privileged docker containers and manage capabilities manually inside the containers, this will help you understand how capability sets interact with each other.
https://www.kernel.org/doc/ols/2008/ols2008v1-pages-163-172.pdf

This is the man page for capabilities. Most of the complex interactions between capability sets don't affect docker containers as long as there are no files with capability bits set.
http://man7.org/linux/man-pages/man7/capabilities.7.html




