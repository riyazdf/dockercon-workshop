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








## Seccomp

Seccomp is a firewall for your system calls.
It uses Berkeley Packet Filter (BPF) programs to filter system calls and control how they are handled.
BPF programs are a simple interpreted assemby-like language that is limited in where it can read data from and write data to.
BPF programs can't have backward jumps and are limited in size.
This means that there's an upper limit to the run time of filters and they are guaranteed to termminate.
These filters can be used to significantly limit the attack surface of the linux kernel, especially for simple applications.

### Checking if seccomp is enabled:

In the kernel:

```
$ grep SECCOMP /boot/config-$(uname -r) # or zgrep SECCOMP /proc/config.gz
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
```

In docker:

```
$ docker run --rm alpine grep Seccomp /proc/self/status
```

In docker 1.12:

```
$ docker info
```

### Seccomp and Docker

The original seccomp was what's now called "strict mode" where the only system calls allowed are `read`, `write`, `_exit` and `sigreturn`. This is not useful for docker containers because all docker programs need many other system calls just to initialize, load dynamic libraries, etc. The mode used by docker is called "filter mode". It uses BPF filters to control exactly which system calls to allow.

Docker has a JSON based DSL which allows defining seccomp profiles that compile down to seccomp filters. Profiles are passed to the `--run` command with the following flag:

```
--security-opt seccomp=profile.json
```

The JSON file is sent from the Docker client to the Docker daemon and the docker daemon
compiles it into a BPF program using a thin go wrapper around libseccomp: github.com/seccomp/libseccomp-golang.

The best way to test the effect of your seccomp profiles is to add all capabilities and disable apparmor.
The following example uses one of the profiles included in this guide to show how to prevent a program from making any system calls at all.
This is a reliable way to make sure your seccomp profile is enforced.

```
$ docker run --rm -it --cap-add ALL --security-opt apparmor=unconfined --security-opt seccomp=seccomp-profiles/deny.json alpine sh
```

### Writing a seccomp profile

The layout of a docker seccomp profile looks like this:

```
{
    "defaultAction": "SCMP_ACT_ERRNO",
    "architectures": [
        "SCMP_ARCH_X86_64",
        "SCMP_ARCH_X86",
        "SCMP_ARCH_X32"
    ],
    "syscalls": [
        {
            "name": "accept",
            "action": "SCMP_ACT_ALLOW",
            "args": []
        },
        {
            "name": "accept4",
            "action": "SCMP_ACT_ALLOW",
            "args": []
        },
        ...
    ]
}
```

The most authoritative source for how to write a docker seccomp profile is the structs used to deserialize the json.

* https://github.com/docker/engine-api/blob/c15549e10366236b069e50ef26562fb24f5911d4/types/seccomp.go
* https://github.com/opencontainers/runtime-spec/blob/master/specs-go/config.go#L357

The possible actions in order of precedence (higher actions overrule lower actions):

|----------------|--------------------------------------------------------------------------|
| SCMP_ACT_KILL  | Kill with a exit status of `0x80 + 31 (SIGSYS) = 159`                    |
| SCMP_ACT_TRAP  | Send a `SIGSYS` signal without executing the system call                 |
| SCMP_ACT_ERRNO | Set `errno` without executing the system call                            |
| SCMP_ACT_TRACE | Invoke a ptracer to make a decision or set `errno` to `-ENOSYS`          |
| SCMP_ACT_ALLOW | Allow                                                                    |

The most important ones for docker users are `SCMP_ACT_ERRNO` and `SCMP_ACT_ALLOW`.

Profiles can contain more granular filters based on the value of the arguments to the system call.

```
{
    ...
    "syscalls": [
        {
            "name": "accept",
            "action": "SCMP_ACT_ALLOW",
            "args": [
                {
                    "index": 0,
                    "op": "SCMP_CMP_MASKED_EQ",
                    "value": 2080505856,
                    "valueTwo": 0
                }
            ]
        }
    ]
}
```

* `index` is the index of the system call argument
* `op` is the operation to perform on the argument. It can be one of:
    * SCMP_CMP_NE - not equal
    * SCMP_CMP_LT - less than
    * SCMP_CMP_LE - less than or equal to
    * SCMP_CMP_EQ - equal to
    * SCMP_CMP_GE - greater than
    * SCMP_CMP_GT - greater or equal to
    * SCMP_CMP_MASKED_EQ - masked equal: true iff `(value & arg == valueTwo)`
* `value` is a parameter for the operation
* `valueTwo` is used only for SCMP_CMP_MASKED_EQ

The rule matches if **all** args match. To achieve the effect of an or, add multiple rules.

Strace can be used to get a list of all system calls made by a program.
It's a very good starting point for writing seccomp policies.
Here's an example of how we can list all system calls made by `ls`:

```
$ strace -c -f -S name ls 2>&1 1>/dev/null | tail -n +3 | head -n -2 | awk '{print $(NF)}'
```

### Demo

Inspiration for this demo:
Seccomp sandboxes and memcached example, part 2 by Stanisław Pitucha
http://blog.viraptor.info/post/seccomp-sandboxes-and-memcached-example-part-2

(Optional) Preparation

```
$ docker run --name mem alpine sh -c 'apk add -U strace memcached'
$ docker commit mem vikstrous/seccomp-demo
```

Tracing

```
$ docker run --rm -it --cap-add SYS_PTRACE --security-opt seccomp=unconfined vikstrous/seccomp-demo strace memcached -u root
```

Taking a sample

```
$ docker run --rm -it --cap-add SYS_PTRACE --security-opt seccomp=unconfined vikstrous/seccomp-demo strace -c -f -S name memcached -u root > table.txt
```

Cleaning up

```
$ cat table.txt | grep -v strace | tail -n +3 | head -n -2 | awk '{print $(NF)}'
```

Result:

```
arch_prctl
bind
brk
clock_gettime
clone
close
connect
dup
epoll_create1
epoll_ctl
epoll_pwait
execve
fcntl
fstat
futex
geteuid
getsockname
getsockopt
getuid
listen
mmap
mprotect
nanosleep
open
pipe
prlimit64
read
readv
rt_sigaction
rt_sigprocmask
set_tid_address
setgid
setsockopt
setuid
socket
socketpair
write
```

Turn that list into a profile. This sed command might save you some time:

```
$ sed 's/.*/\\t\\t{\\n\\t\\t\\t"name": "\\0",\\n\\t\\t\\t"action":"SCMP_ACT_ALLOW",\\n\\t\\t\\t"args": []\\n\\t\\t},/'
```

The profile should look like this (you can find it in `seccomp-profiles/memcached.json`):

```
{
	"defaultAction": "SCMP_ACT_ERRNO",
	"architectures": [
		"SCMP_ARCH_X86_64",
		"SCMP_ARCH_X86",
		"SCMP_ARCH_X32"
	],
	"syscalls": [
		{
			"name": "read",
			"action": "SCMP_ACT_ALLOW",
			"args": []
		},
        ...
    }
}
```

Test out our profile

TODO: this doesn't work

```
$ docker run --rm -it --security-opt seccomp=memcached.json vikstrous/seccomp-demo memcached -u root
$ telnet localhost 11211
stats
quit
```

Let's restrict the ports it can listen on

```
$ docker run -u nobody vikstrous/seccomp-demo strace memcached 2>&1 | grep bind
bind(26, {sa_family=AF_INET, sin_port=htons(11211), sin_addr=inet_addr("0.0.0.0")}, 16) = 0
...
$ docker run -u nobody vikstrous/seccomp-demo strace memcached -p 1234 2>&1 | grep bind
bind(26, {sa_family=AF_INET, sin_port=htons(1234), sin_addr=inet_addr("0.0.0.0")}, 16) = 0
...
```

### Gotchas

There are some things that you can easily miss when using seccomp with docker.

#### Truncation

When writing a seccomp filter sometimes arguments are truncated by the operating system after the filter has run, so you have to be careful how you write your filters.

> When checking values from args against a blacklist, keep in mind that
> arguments are often silently truncated before being processed, but
> after the seccomp check.  For example, this happens if the i386 ABI
> is used on an x86-64 kernel: although the kernel will normally not
> look beyond the 32 lowest bits of the arguments, the values of the
> full 64-bit registers will be present in the seccomp data.  A less
> surprising example is that if the x86-64 ABI is used to perform a
> system call that takes an argument of type int, the more-significant
> half of the argument register is ignored by the system call, but
> visible in the seccomp data.

https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt

#### Seccomp escapes

* Syscall numbers are architecture dependant, so raw BPF filters are not very portable.
Luckily docker abstract this issue away, so you don't need to worry about it if using docker seccomp profiles.

* ptrace is disabled by default and you should not enable it because it allows bypassing seccomp.
You can use this script to test for seccomp escapes through ptrace:
https://gist.github.com/thejh/8346f47e359adecd1d53

#### Differences between docker versions

* Seccomp is supported as of Docker 1.10.

* Using `--privileged` disables seccomp in all versions of docker even if you specify a seccomp profile with it.
In general you should try to avoid ever using `--privileged` because it does too many things.
You can achieve the same goal with `--cap-add ALL --security-opt apparmor=unconfined --security-opt seccomp=unconfined`.
If you need access to devices use `--device`.

* In docker 1.10-1.12+ docker exec `--privileged` does not bypass seccomp. This may change in future versions https://github.com/docker/docker/issues/21984

* In docker 1.12+ adding a capability disables the relevant seccomp filter in the default seccomp profile. It can't disable apparmor, though.

### Using multiple filters

The only way to use multiple seccomp filters right now is to load addition filters within your program at run time.
The kernel supports layering filters.
When using multiple layered filters they are always all executed, starting with the most recently added.
The highest precedence action returned is taken.
See the man page for all the details: http://man7.org/linux/man-pages/man2/seccomp.2.html

### Misc

You can enable JITing of BPF filters (if it isn't already enabled) this way:

```
$ echo 1 > /proc/sys/net/core/bpf_jit_enable
```

There is no easy to use seccomp in a mode that reports errors without crashing the program, but it's possible to implement in one of several ways.
One way to do this is to use SCMP_ACT_TRAP and make your process handle SIGSYS and report the error in a useful way.
There's some information about how Firefox handles seccomp violations here: https://wiki.mozilla.org/Security/Sandbox/Seccomp

### Further reading:

Very comprehensive presentation about seccomp that goes into more detail than this document.
https://lwn.net/Articles/656307/
http://man7.org/conf/lpc2015/limiting_kernel_attack_surface_with_seccomp-LPC_2015-Kerrisk.pdf

Chrome's DSL for generating seccomp BPF programs:
https://cs.chromium.org/chromium/src/sandbox/linux/bpf_dsl/bpf_dsl.h?sq=package:chromium&dr=CSs
