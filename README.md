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
setcap cap_net_raw=ep $file
```

Or libcap-ng:

```
filecap /absolute/path net_raw
```

**Auditing**

There are multiple ways to read out the capabilites from a file.

Using libcap:

```
getcap $file
```

Using libcap-ng:

```
filecap /absolue/path/to/file
```

Using extended attributes (attr package):

```
getfattr -n security.capability $file
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
docker run --rm -it --cap-drop ALL --cap-add CHOWN alpine chown nobody /
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

Docs: https://docs.docker.com/engine/security/seccomp/

### Checking if seccomp is enabled:

```
zgrep SECCOMP /proc/config.gz
```

or

```
docker run --rm alpine grep Seccomp /proc/self/status
```

or in docker 1.12:

```
docker info
```

### Seccomp modes

SECCOMP_MODE_STRICT: allow only `read`, `write`, `_exit` and `sigreturn`
SECCOMP_MODE_FILTER: BPF filters for any system call

Docker supports only filter mode, which is a superset of strict mode.

### Using seccomp with docker

The security profile is sent from the Docker client to the Docker daemon,
so the path to the profile can be local to the client and relative to the current directory.

```
docker run --rm -it --cap-add ALL --security-opt apparmor=unconfined --security-opt seccomp=./profiles/deny.json alpine sh
```

### Writing a policy

Seccomp filters support arbitrary terminating programs defined by BPF code with a limit on the size of the programs.

Docker uses json files to define seccomp filters. The layout of the filter files looks like this:

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

The most authoritative source for how to write a docker seccomp policy is the structs used to deserialize the json. [3] [4]

Possible actions in order of precedence (higher actions overrule lower actions):

|----------------|--------------------------------------------------------------------------|
| SCMP_ACT_KILL  | Kill with a exit status of `0x80 + 31 (SIGSYS) = 159` |
| SCMP_ACT_TRAP  | Send a `SIGSYS` signal without executing the system call |
| SCMP_ACT_ERRNO | Set `errno` to `SECCOMP_RET_DATA` without executing the system call |
| SCMP_ACT_TRACE | Invoke a ptracer to make a decision or set `errno` to `-ENOSYS` |
| SCMP_ACT_ALLOW | Allow |

More complex example:

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

`index` is the index of the system call argument
`op` is the operation to perform on the argument. It can be one of:
    * SCMP_CMP_NE
    * SCMP_CMP_LT
    * SCMP_CMP_LE
    * SCMP_CMP_EQ
    * SCMP_CMP_GE
    * SCMP_CMP_GT
    * SCMP_CMP_MASKED_EQ
`value` is a parameter for the operation
`valueTwo` is used only for SCMP_CMP_MASKED_EQ to represent a second parameter. The first is the mask, the second is the value to compare to.

The rule applies if **all** args match. To achieve the effect of an or, add multiple rules.

### Using multiple filters

When using multiple filters they are always all executed, starting with the most recently added. The highest precedence action returned is taken.

### Example

One potentially dangerous 

### Tips

Strace is your friend. Here's a hacky oneliner to get a very nice summary of what system calls a program makes:

```
strace -c -f -S name $CMD 2>&1 1>/dev/null | tail -n +3 | head -n -2 | awk '{print $(NF)}'
```

This works as long as the program doesn't print to stderr. Dealing with programs that print to stderr is left as an exercise for the reader.

You can enable JITing of BPF filters (if it isn't already enabled) this way:

```
echo 1 > /proc/sys/net/core/bpf_jit_enable
```

Exit status of process killed by signal is 128 + signum and SIGSYS is 31, so you can expect your process to die with exit status 159 when it violates a seccomp policy.

There is no easy to use seccomp warn mode, but it's theoretically possible to implement. [2]

If you have setuid programs in your container, a malicious program could create a seccomp policy that denies specific system calls and causes unexpected behaviour in your setuid program. This is why you might want to use seccomp to disable the seccomp system call within your containers.

### Demo

Inspiration for this demo:
Seccomp sandboxes and memcached example, part 2 by Stanisław Pitucha
http://blog.viraptor.info/post/seccomp-sandboxes-and-memcached-example-part-2

Preparation

```
$ docker run --name mem alpine sh -c 'apk add -U strace memcached'
$ docker commit mem vikstrous/seccomp-demo
```

Tracing

```
$ docker run -u nobody vikstrous/seccomp-demo strace memcached
```

Taking a sample

```
$ docker run -u nobody vikstrous/seccomp-demo strace -c -f -S name memcached 2> table.txt
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
rt_sigaction
rt_sigprocmask
set_tid_address
setsockopt
socket
socketpair
write
```

Turn that list into a policy...

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

Test out our policy

```
$ docker run -u nobody -p 11211:11211 --security-opt seccomp=memcached.json vikstrous/seccomp-demo memcached
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

There are some things that you can easily miss when writing seccomp filters.

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

[[1]](https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt)

#### Seccomp escapes

Architecture dependent syscall numbers

ptrace is disabled by default and you should not enable it because it allows bypassing seccomp
https://gist.github.com/thejh/8346f47e359adecd1d53

seccomp
prctl
ptrace

#### Differences between docker versions

Seccomp is supported as of Docker 1.10.

In Docker 1.10 using `--privileged` does not disable seccomp.
TODO: verify^

In Docker 1.11+ using `--privileged` disables seccomp for docker run, but not for docker exec. https://github.com/docker/docker/issues/21984. Try to avoid ever using `--privileged`. You can achieve the same goal with `--cap-add ALL --security-opt apparmor=unconfined --security-opt seccomp=unconfined`.

In docker 1.12+ adding a capability disables the relevant seccomp filter in the default seccomp policy. It can't disable apparmor, though.

### TODO

research the interactions between ptrace and seccomp more - is the only issue when using SECCOMP_RET_TRACE and not restricting ptrace?

read
what is this? http://thread.gmane.org/gmane.linux.ports.parisc/26854
https://www.kernel.org/doc/ols/2008/ols2008v1-pages-163-172.pdf

capabilities:
http://www.insanitybit.com/2014/09/08/sandboxing-linux-capabilities/


useful resources:
https://lwn.net/Articles/656307/ (summary of: http://man7.org/conf/lpc2015/limiting_kernel_attack_surface_with_seccomp-LPC_2015-Kerrisk.pdf )

chrome's DSL for generating seccomp BPF programs (also used in firefox [2]):
https://cs.chromium.org/chromium/src/sandbox/linux/bpf_dsl/bpf_dsl.h?sq=package:chromium&dr=CSs

**Sources**

*[1] https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt*
*[2] https://wiki.mozilla.org/Security/Sandbox/Seccomp*
*[3] https://github.com/docker/engine-api/blob/c15549e10366236b069e50ef26562fb24f5911d4/types/seccomp.go*
*[4] https://github.com/opencontainers/runtime-spec/blob/master/specs-go/config.go#L357*
