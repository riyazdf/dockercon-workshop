# dockercon-workshop
#### Dockercon 2016 Security Workshop

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

| Action         | Description                                                              |
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

By copying the default docker profile and then removing system calls selectively we can show that we are able to intercept system calls with seccomp. For this demo we've removed chmod, fchmod and chmodat from the default profile.

```
$ docker run --rm -it --security-opt seccomp=default-no-chmod.json alpine chmod 777 /
```

### Gotchas

There are some things that you can easily miss when using seccomp with docker.

#### Timing of application of seccomp policies

In versions before 1.12 seccomp polices tend to be applied too soon.
This means that you may need to add system calls that your application doesn't use in order for the container to be started successfully.
This behavior hasn't been thoroughly documented yet. See: https://github.com/docker/docker/issues/22252 https://github.com/opencontainers/runc/pull/789

The best way to avoid this issue is to use

```
--security-opt no-new-privileges
```

Note that this also disables gaining privileges through setuid binaries.

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
