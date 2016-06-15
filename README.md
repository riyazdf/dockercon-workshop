# dockercon-workshop
#### Dockercon 2016 Security Workshop

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
docker hacks: https://github.com/docker/docker/issues/21984


useful resources:
https://lwn.net/Articles/656307/ (summary of: http://man7.org/conf/lpc2015/limiting_kernel_attack_surface_with_seccomp-LPC_2015-Kerrisk.pdf )

chrome's DSL for generating seccomp BPF programs (also used in firefox [2]):
https://cs.chromium.org/chromium/src/sandbox/linux/bpf_dsl/bpf_dsl.h?sq=package:chromium&dr=CSs

**Sources**

*[1] https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt*
*[2] https://wiki.mozilla.org/Security/Sandbox/Seccomp*
*[3] https://github.com/docker/engine-api/blob/c15549e10366236b069e50ef26562fb24f5911d4/types/seccomp.go*
*[4] https://github.com/opencontainers/runtime-spec/blob/master/specs-go/config.go#L357*
