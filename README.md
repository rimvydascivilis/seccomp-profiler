# seccomp-profiler

eBPF-based tool that records every syscall made by Docker containers and produces per-container allowlists ready to use as seccomp profiles.

## How it works

1. An **OCI prestart hook** registers each container's cgroup v2 ID in a pinned BPF map before its first syscall fires.
2. A **BPF tracepoint** on `raw_syscalls/sys_enter` records `(cgid, syscall_nr)` pairs for tracked containers only — zero overhead for everything else.
3. The **daemon** watches Docker events and, on container exit, reads the BPF map, resolves syscall numbers to names, and writes the result to disk.

## Requirements

**Kernel:** Linux 5.8+, BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`), cgroup v2.

**Build:** `clang`, `llvm`, `libbpf-dev`, `linux-libc-dev`, Go 1.21+.

```sh
make install-deps-debian   # or install-deps-rhel
```

**Runtime:** Docker, root (for `CAP_BPF` + `CAP_PERFMON`).

## Build

```sh
make deps      # download Go modules
make           # compile BPF + build binaries → bin/
```

## Install

```sh
sudo make install
```

Installs the hook binary to `/usr/local/libexec/oci/hooks.d/seccomp-profiler` and the hook spec to `/usr/local/share/containers/oci/hooks.d/seccomp-profiler.json`. Podman and CRI-O pick this up automatically for every container.

## Run

```sh
sudo bin/seccomp-profiler [-out <dir>] [-format text|seccomp]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-out` | `output` | Directory for per-container result files |
| `-format` | `text` | `text` — one syscall per line; `seccomp` — Docker/OCI JSON profile |

Stop with `Ctrl+C` — the daemon flushes any still-running containers before exiting.

## Output

Each container produces one file named `<container>_<short-id>.<ext>`:

**`text` format** (`nginx_abc123def456.txt`):
```
execve
mmap
openat
read
write
```

**`seccomp` format** (`nginx_abc123def456.json`):
```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [{ "names": ["execve", "mmap", ...], "action": "SCMP_ACT_ALLOW" }]
}
```

The seccomp JSON can be passed directly to `docker run --security-opt seccomp=<file>`.

## Limitations

- x86_64 only
- cgroup v2 required
- Max 128 concurrent containers (compile-time constant)
