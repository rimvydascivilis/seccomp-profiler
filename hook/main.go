// Command seccomp-profiler-hook is the OCI prestart hook for seccomp-profiler.
// runc calls it synchronously before executing the container init process.
// It reads the container PID from the OCI state on stdin, resolves the cgroup v2 ID,
// and writes it to the pinned BPF tracked_cgids map so the daemon starts tracing
// before the first container syscall fires.
//
// Install: sudo make install  (installs to /usr/local/libexec/oci/hooks.d/seccomp-profiler)
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"

	"github.com/cilium/ebpf"

	"github.com/rimvydascivilis/seccomp-profiler/internal/cgroup"
)

const (
	pinnedMap = "/sys/fs/bpf/seccomp-profiler/tracked_cgids"
	stateDir  = "/run/seccomp-profiler"
)

// ociState mirrors the OCI Runtime Spec state object passed via stdin.
type ociState struct {
	ID  string `json:"id"`
	Pid int    `json:"pid"`
}

func main() {
	var state ociState
	if err := json.NewDecoder(os.Stdin).Decode(&state); err != nil {
		// Non-fatal: if we can't parse state, just let the container start.
		os.Exit(0)
	}
	if state.Pid == 0 {
		os.Exit(0)
	}

	cgid, err := cgroup.IDFromPid(state.Pid)
	if err != nil {
		// Non-fatal: daemon will fall back to docker inspect.
		os.Exit(0)
	}

	// Write cgid to pinned BPF map. If daemon is not running (map not pinned),
	// fail silently — container must not be blocked by a missing profiler.
	if m, err := ebpf.LoadPinnedMap(pinnedMap, nil); err == nil {
		one := uint8(1)
		m.Put(cgid, one)
		m.Close()
	}

	// Write state file so the daemon can look up cgid when the container stops.
	os.MkdirAll(stateDir, 0o755)
	os.WriteFile(
		filepath.Join(stateDir, state.ID+".cgid"),
		[]byte(strconv.FormatUint(cgid, 10)),
		0o644,
	)
}
