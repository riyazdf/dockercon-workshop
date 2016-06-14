# dockercon-workshop
#### Dockercon 2016 Security Workshop

Docs: https://docs.docker.com/engine/security/seccomp/

### Checking if seccomp is enabled:

```
zcat /proc/config.gz | grep seccomp -i
```

or

```
docker run --rm alpine cat /proc/self/status | grep seccomp -i
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

Possible actions in order of precedence (higher actions overrule lower actions):

|-------------------|--------------------------------------------------------------------------|
| SECCOMP_RET_KILL  | Kill with a exit status that when masked with `&0x7f` equals SIGSYS (31) |
| SECCOMP_RET_TRAP  | Send a `SIGSYS` signal without executing the system call |
| SECCOMP_RET_ERRNO | Set `errno` to `SECCOMP_RET_DATA` without executing the system call |
| SECCOMP_RET_TRACE | Invoke a ptracer to make a decision or set `errno` to `-ENOSYS` |
| SECCOMP_RET_ALLOW | Allow |

[[1]](https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt)



A filter returns 32 bits: 16 bits of SECCOMP_RET_ACTION and 16 bits of SECCOMP_RET_DATA


### Using multiple filters

When using multiple filters they are always all executed, starting with the most recently added. The highest precedence action returned is taken.

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

#### Differences between docker versions

In docker 1.11 using --privileged disables seccomp

In docker 1.12 adding a capability disables the relevant seccomp filter in the default seccomp policy. It can't disable apparmor though.

### TODO

research the interactions between ptrace and seccomp more - is the only issue when using SECCOMP_RET_TRACE and not restricting ptrace?

What a mess:
https://github.com/docker/docker/issues/21984
How do we show off seccomp if we can't use --privileged to disable all other checks?

What version of docker added seccomp?

**Sources**

*[1] https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt*
