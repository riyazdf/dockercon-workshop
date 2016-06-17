# dockercon-workshop
#### Dockercon 2016 Security Workshop

## Secure bits

Secure bits can be used as another layer of protection to prevent privilege escalation from within a container.

Setting secure bits requires CAP_SETPCAP, which docker allows by default.

Secure bits are set through `prctl()` and affect how capabilities are passed on. They can be used to prevent setuid programs from gaining or dropping privileges.

* SECBIT_NOROOT – don't grant capabilities to setuid programs or processes exec'd as root
* SECBIT_NO_SETUID_FIXUP – don't clear capabilities when transitioning from or to uid 0 using the setuid binary
* SECBIT_KEEP_CAPS – don't clear capabilities when switching from uid 0 to non-uid 0
* SECBIT_NO_CAP_AMBIENT_RAISE - disallow raising ambient capabilities

Also there are corresponding \_LOCKED variables that prevent the bits from being changed again and are inherited when execing. SECBIT_KEEP_CAPS is always cleared on `execve()`.

These bits are set with `prctl(PR_SET_SECUREBITS, X);`


https://lwn.net/Articles/280279/
http://lxr.free-electrons.com/source/include/uapi/linux/securebits.h#L21

### Secure bits example

In this example we execute sudo without making it actually run as root.

Example setting SECBIT_NOROOT
```
/ # apk add -U libcap bash sudo
/ # capsh --secbits=0x03 --uid=65534 -- -c 'sudo ls'
sudo: PERM_SUDOERS: setresuid(-1, 1, -1): Operation not permitted
sudo: no valid sudoers sources found, quitting
sudo: setresuid() [0, 0, 0] -> [65534, -1, -1]: Operation not permitted
sudo: unable to initialize policy plugin
```

## Capabilities

Capability sets and security bits are much more complex in a standard linux system. When using docker there are certain limitations that make managing capabilities much simpler. TODO: shorten the summary, focus on the docker part, then give all the details in the advanced section

Whenever a user executes a file that has a certain set of capabilities associated with it, the process it spawns gains those capabilities. This works similarly to the setuid flag, but much more granular.

File capabilities can be one of:

* Permitted - all threads that exec this file receive its capabilities
* Inheritable - this set is ANDed with the thread's inheritable set
* Effective bit - whether to make new capabilities effective after exec; if not set, the process needs to give itself effective capabilities up to the permitted set

Thread capability sets:

* Permitted - limiting superset of effective capabilities; can only be removed from by a thread
* Inheritable - preserved across execve, but remain inheritable; must exec a binary with the same capabilities in its inheritable set to actually gain these capabilities; having CAP_SETPCAP allows adding permissions to this set up to the permitted set
* Effective - current capabilities; subset of permitted, can be dropped or added
* Ambient - new in kernel 4.3, subset of permitted and inheritable; inherited as permitted/effective as long as no setuid/capabilities programs are called
* Bounding - the set of capabilities that a program or its children is ever allowed to receive; these can only be dropped and when dropped remove the corresponding capability from the permitted set; dropping capabilities requires CAP_SETPCAP

> Note that the bounding set masks the file permitted capabilities, but
> not the inherited capabilities.  If a thread maintains a capability
> in its inherited set that is not in its bounding set, then it can
> still gain that capability in its permitted set by executing a file
> that has the capability in its inherited set.

http://man7.org/linux/man-pages/man7/capabilities.7.html

TODO: draw some pretty venn diagrams of these sets? I can also show on the diagram what actions a thread is allowed to do, how it interacts with file capabilities, how securebits affect this process, etc.

File capabilities are stored in an extended attribute `security.capability`.


### Docker capabilities

Docker allows your to specify what capabilities you want your docker container's root process to have.

Examples:

```
docker run --rm -it --cap-add $CAP alpine sh
docker run --rm -it --cap-drop $CAP alpine sh
docker run --rm -it --cap-drop ALL --cap-add $CAP alpine sh
```

Docker capabilities constants are not prefixed with `CAP_` but otherwise match the kernel's constants.

Docker doesn't support file capabilities in images right now. They are stripped during builds. There is some interest in fixing that in the future, but older versions of AUFS didn't support extended attributes, so we can't assume that all filesystem drivers support them. This can make images less portable if we ever allow them.

If you give a container capabilities but run as non root, all these capabilities are dropped on exec of the command, and can only be raised via filesystem capabilities or suid programs. This means that you can't add capabilities to non-root users, only take away capabilities from the root user. This feature may be added to Docker in future versions, but it will require kernels >=4.3 because it requires ambient capabilities.

In practice you have 3 options right now:

* run as root with a large set of capabilities and try to manage capabilities within your container manually - not recommended unless you know exactly what you are doing
* run as root with limited capabilities to begin with; use --cap-add and --cap-drop in `docker run` to achieve this
* run as an unprivileged user and no capabilities

One more option *may* be added in the future:

* run as a non-root user and a small set of specific capabilities

### Tools

libcap
* capsh
* setcap
* getcap

libcap-ng

* pscap
* filecap
* captest


Printing out all capabilities

In alpine
```
$ docker run --rm -it alpine sh -c 'apk add -U libcap; capsh --print'
```

The syntax is confusing. "Current" is multiple sets separated by a space. Multiple capabilities within the same set are separated by a `,`. The `+` suffix describes what the set is. `e` is effective `i` is inheritable `p` is permitted.

capsh
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

Warning:
`--drop` sounds like what you want to do, but it affects only the bounding set. This can be very confusing because it doesn't actually take away the capability from the effective or inheritable set. You almost always want to use `--caps`, which uses the same syntax as the output of `--print`.

```
$ docker run --rm -it alpine sh -c 'apk add -U libcap-ng-utils; captest'
```

Very cool feature of libcap-ng's captest:
```
Attempting to regain root...SUCCESS - PRIVILEGE ESCALATION POSSIBLE
```
Not the most useful thing because "root" doesn't really mean the same thing within docker.


```
TODO: setcap example
setcap cap_net_raw=ep $file
getcap $file
TODO: getxattr example
getfattr -n security.capability $file
# file: $file
security.capability=0sAQAAAgAgAAAAAAAAAAAAAAAAAAA=
```

In Ubuntu:
```
$ docker run --rm -it ubuntu capsh --print
```

### Demo

```
$ docker run --rm -it --cap-drop CHOWN alpine chown nobody /
```

```
$ docker run --rm -it alpine chown nobody /
chown: /: Operation not permitted
```

This doesn't actually drop the capability - dropping from the bounding set doesn't remove it from the inheritable/effective sets
```
$ docker run --rm -it alpine sh -c 'apk add -U libcap bash; capsh --drop=cap_chown -- -c "chown nobody /"'
```

```
$ docker run --rm -it --cap-drop SETPCAP alpine sh -c 'apk add -U libcap; capsh --drop=cap_chown'
unable to raise CAP_SETPCAP for BSET changes: Operation not permitted
```


### Tips

Your docker images can't have files with capability bits set, so it's unlikely that programs in docker containers can use capabilities to escalate privileges. You might still want to make sure that none of the volumes you are mounting into docker containers contain files with capability bits set.

TODO: show how to audit directories for capability bits.

TODO: show how to remove capability bits

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
docker run --rm -it --cap-add ALL --security-opt apparmor=unconfined --security-opt seccomp=./profiles/empty.json alpine sh
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

|-------------------|--------------------------------------------------------------------------|
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
                    "op": "SCMP_CMP_MASKED_EQ"
                    "value": 2080505856,
                    "valueTwo": 0,
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
strace -c -f -S name $CMD 2>&1 1>/dev/null | tail -n +4 | head -n -2 | awk '{print $(NF)}'
```

This works as long as the program doesn't print to stderr. Dealing with programs that print to stderr is left as an exercise for the reader.

You can enable JITing of BPF filters (if it isn't already enabled) this way:

```
echo 1 > /proc/sys/net/core/bpf_jit_enable
```

Exit status of process killed by signal is 128 + signum and SIGSYS is 31, so you can expect your process to die with exit status 159 when it violates a seccomp policy.

There is no easy to use seccomp warn mode, but it's theoretically possible to implement. [2]

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
