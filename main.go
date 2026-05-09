// Command seccomp-profiler is a daemon that profiles Docker containers via eBPF.
// BPF maps are pinned to /sys/fs/bpf/seccomp-profiler/ so the OCI hook binary
// can write each container's cgroup ID before its first syscall fires.
// The daemon listens to docker events only for container stop to collect results.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I/usr/include -I/usr/include/x86_64-linux-gnu" Tracker bpf/syscall_tracker.c
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/rimvydascivilis/seccomp-profiler/internal/cgroup"
)

const (
	pinDir        = "/sys/fs/bpf/seccomp-profiler"
	stateDir      = "/run/seccomp-profiler"
	maxContainers = 128 // must match tracked_cgids max_entries in bpf/syscall_tracker.c
	maxSyscallNr  = 512 // must match the BPF C guard: if (nr >= 512) return 0
)

// outputFormat selects how per-container results are written to disk.
type outputFormat string

const (
	formatText    outputFormat = "text"
	formatSeccomp outputFormat = "seccomp"
)

func (f outputFormat) ext() string {
	if f == formatSeccomp {
		return ".json"
	}
	return ".txt"
}

func (f outputFormat) write(path string, names []string) error {
	if f == formatSeccomp {
		return writeSeccompOutput(path, names)
	}
	return writeTextOutput(path, names)
}

type containerInfo struct {
	id   string
	name string
	cgid uint64
}

type profiler struct {
	objs      TrackerObjects
	outDir    string
	outFormat outputFormat

	mu         sync.Mutex
	containers map[uint64]containerInfo
}

// OCI / Docker seccomp profile format.
type seccompProfile struct {
	DefaultAction string           `json:"defaultAction"`
	Architectures []string         `json:"architectures,omitempty"`
	Syscalls      []seccompSyscall `json:"syscalls"`
}

type seccompSyscall struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	outDir := flag.String("out", "output", "Directory for per-container syscall files")
	format := flag.String("format", "text", "Output format: text or seccomp")
	flag.Parse()

	outFmt := outputFormat(*format)
	switch outFmt {
	case formatText, formatSeccomp:
	default:
		return fmt.Errorf("unknown format %q — use text or seccomp", *format)
	}

	for _, dir := range []string{*outDir, pinDir, stateDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create dir %s: %w", dir, err)
		}
	}

	cleanupStaleStateFiles()

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}

	// Load and customise the BPF collection spec before committing to the kernel
	// so map limits are configurable without recompilation.
	spec, err := LoadTracker()
	if err != nil {
		return fmt.Errorf("load BPF spec (requires kernel 5.8+ with CONFIG_DEBUG_INFO_BTF=y): %w", err)
	}
	spec.Maps["tracked_cgids"].MaxEntries = maxContainers
	spec.Maps["syscall_seen"].MaxEntries = maxContainers * maxSyscallNr

	var objs TrackerObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("load BPF objects: %w", err)
	}
	defer objs.Close()

	// Pin maps so the OCI hook binary can open them without a running file descriptor.
	if err := pinMap(objs.TrackedCgids, filepath.Join(pinDir, "tracked_cgids")); err != nil {
		return err
	}
	if err := pinMap(objs.SyscallSeen, filepath.Join(pinDir, "syscall_seen")); err != nil {
		return err
	}

	tp, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.TraceSysEnter, nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint raw_syscalls/sys_enter: %w", err)
	}
	defer tp.Close()

	p := &profiler{
		objs:       objs,
		outDir:     *outDir,
		outFormat:  outFmt,
		containers: make(map[uint64]containerInfo),
	}

	// Register containers that were already running before we started.
	// The hook was not called for them, so fall back to docker inspect.
	p.trackRunningContainers()

	slog.Info("ready", "pin_dir", pinDir, "output", *outDir, "format", *format)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go p.streamDockerEvents(ctx)

	<-ctx.Done()
	fmt.Fprintln(os.Stderr)

	os.Remove(filepath.Join(pinDir, "tracked_cgids"))
	os.Remove(filepath.Join(pinDir, "syscall_seen"))

	slog.Info("flushing remaining containers")
	p.flushAll()
	return nil
}

func pinMap(m *ebpf.Map, path string) error {
	os.Remove(path) // remove stale pin from a previous run
	if err := m.Pin(path); err != nil {
		return fmt.Errorf("pin map to %s: %w", path, err)
	}
	return nil
}

// cleanupStaleStateFiles removes /run/seccomp-profiler/<cid>.cgid files left
// behind by a previous daemon that exited without a clean shutdown.
func cleanupStaleStateFiles() {
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		return
	}
	out, err := exec.Command("docker", "ps", "--no-trunc", "-q").Output()
	if err != nil {
		return
	}
	running := make(map[string]struct{})
	for _, id := range strings.Fields(string(out)) {
		running[id] = struct{}{}
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".cgid") {
			continue
		}
		cid := strings.TrimSuffix(e.Name(), ".cgid")
		if _, ok := running[cid]; !ok {
			path := filepath.Join(stateDir, e.Name())
			slog.Info("removing stale state file", "path", path)
			os.Remove(path)
		}
	}
}

type dockerEvent struct {
	Action string `json:"Action"`
	Type   string `json:"Type"`
	Actor  struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
}

// streamDockerEvents watches docker events and restarts the subprocess with
// exponential backoff if it exits unexpectedly (e.g. Docker daemon restart).
func (p *profiler) streamDockerEvents(ctx context.Context) {
	const maxBackoff = 30 * time.Second
	backoff := time.Second
	for {
		if err := p.runDockerEvents(ctx); err == nil || ctx.Err() != nil {
			return
		} else {
			slog.Warn("docker events exited, restarting", "backoff", backoff, "error", err)
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
		if backoff < maxBackoff {
			backoff *= 2
		}
	}
}

func (p *profiler) runDockerEvents(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "events", "--format", "{{json .}}")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		var ev dockerEvent
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue
		}
		if ev.Type != "container" {
			continue
		}
		switch ev.Action {
		case "start":
			go p.onContainerStart(ev.Actor.ID, ev.Actor.Attributes["name"])
		case "die", "stop", "kill":
			go p.onContainerStop(ev.Actor.ID, ev.Actor.Attributes["name"])
		}
	}

	cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return fmt.Errorf("docker events subprocess exited unexpectedly")
}

func (p *profiler) onContainerStart(cid, name string) {
	cgid, err := containerCgroupID(cid)
	if err != nil {
		slog.Warn("could not get cgid", "container", name, "error", err)
		return
	}
	one := uint8(1)
	if err := p.objs.TrackedCgids.Put(cgid, one); err != nil {
		slog.Warn("BPF put cgid failed", "container", name, "error", err)
		return
	}
	p.mu.Lock()
	p.containers[cgid] = containerInfo{id: cid, name: name, cgid: cgid}
	p.mu.Unlock()
	slog.Info("tracking new container", "name", name, "cgid", cgid)
}

// onContainerStop is called when a container exits. It looks up the cgid that
// the OCI hook registered (via the state file written by the hook) and collects
// the syscall results.
func (p *profiler) onContainerStop(cid, name string) {
	cgid, err := readCgidStateFile(cid)
	if err != nil {
		// Might not have been tracked (no hook, or daemon started after container).
		p.mu.Lock()
		for cg, info := range p.containers {
			if info.id == cid {
				cgid = cg
				break
			}
		}
		p.mu.Unlock()
	}
	if cgid == 0 {
		return
	}
	p.collectAndRemove(containerInfo{id: cid, name: name, cgid: cgid})
	os.Remove(cgidStateFile(cid))
}

func (p *profiler) flushAll() {
	p.mu.Lock()
	infos := make([]containerInfo, 0, len(p.containers))
	for _, c := range p.containers {
		infos = append(infos, c)
	}
	p.mu.Unlock()
	for _, c := range infos {
		p.collectAndRemove(c)
	}
}

func (p *profiler) collectAndRemove(info containerInfo) {
	defer func() {
		p.objs.TrackedCgids.Delete(info.cgid)
		p.mu.Lock()
		delete(p.containers, info.cgid)
		p.mu.Unlock()
	}()

	names, err := p.collectSyscalls(info.cgid)
	if err != nil {
		slog.Error("collecting syscalls", "container", info.name, "error", err)
		return
	}
	base := sanitizeName(info.name) + "_" + shortID(info.id)
	path := filepath.Join(p.outDir, base+p.outFormat.ext())
	if err := p.outFormat.write(path, names); err != nil {
		slog.Error("writing output", "path", path, "error", err)
		return
	}
	slog.Info("saved syscalls", "container", info.name, "count", len(names), "path", path)
}

func (p *profiler) trackRunningContainers() {
	out, err := exec.Command("docker", "ps", "--format", "{{.ID}}\t{{.Names}}").Output()
	if err != nil {
		slog.Warn("docker ps failed, skipping pre-existing containers", "error", err)
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		cid, name := parts[0], ""
		if len(parts) == 2 {
			name = parts[1]
		}
		cgid, err := containerCgroupID(cid)
		if err != nil {
			slog.Warn("could not get cgid", "container", name, "error", err)
			continue
		}
		one := uint8(1)
		if err := p.objs.TrackedCgids.Put(cgid, one); err != nil {
			slog.Warn("BPF put cgid failed", "container", name, "error", err)
			continue
		}
		p.mu.Lock()
		p.containers[cgid] = containerInfo{id: cid, name: name, cgid: cgid}
		p.mu.Unlock()
		slog.Info("tracking existing container", "name", name, "cgid", cgid)
	}
}

func cgidStateFile(cid string) string {
	return filepath.Join(stateDir, cid+".cgid")
}

func readCgidStateFile(cid string) (uint64, error) {
	data, err := os.ReadFile(cgidStateFile(cid))
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

func containerCgroupID(cid string) (uint64, error) {
	out, err := exec.Command("docker", "inspect", "--format", "{{.State.Pid}}", cid).Output()
	if err != nil {
		return 0, fmt.Errorf("docker inspect: %w", err)
	}
	pid := strings.TrimSpace(string(out))
	if pid == "" || pid == "0" {
		return 0, fmt.Errorf("container not running")
	}
	pidInt, err := strconv.Atoi(pid)
	if err != nil {
		return 0, fmt.Errorf("parse pid %q: %w", pid, err)
	}
	return cgroup.IDFromPid(pidInt)
}

// collectSyscalls reads which syscalls were observed for cgid by probing each
// possible syscall number explicitly. This is O(maxSyscallNr) map lookups per
// container rather than a full map scan that grows with total container count.
func (p *profiler) collectSyscalls(cgid uint64) ([]string, error) {
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("get possible CPUs: %w", err)
	}

	vals := make([]uint8, numCPU)
	var seen []string

	for nr := uint32(0); nr < maxSyscallNr; nr++ {
		key := TrackerCgidSyscallKey{Cgid: cgid, Nr: nr}
		if err := p.objs.SyscallSeen.Lookup(&key, &vals); err != nil {
			continue
		}
		for _, v := range vals {
			if v != 0 {
				seen = append(seen, syscallName(nr))
				break
			}
		}
	}

	sort.Strings(seen)
	return seen, nil
}

func createOutputFile(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	return os.Create(path)
}

func writeTextOutput(path string, names []string) error {
	f, err := createOutputFile(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, n := range names {
		fmt.Fprintln(f, n)
	}
	return nil
}

func writeSeccompOutput(path string, names []string) error {
	profile := seccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls:      []seccompSyscall{{Names: names, Action: "SCMP_ACT_ALLOW"}},
	}
	f, err := createOutputFile(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(profile)
}

func sanitizeName(name string) string {
	name = strings.TrimPrefix(name, "/")
	var b strings.Builder
	for _, r := range name {
		if r == '/' || r == ' ' {
			b.WriteRune('_')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
