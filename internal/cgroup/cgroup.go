package cgroup

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// IDFromPid resolves the cgroup v2 ID for the given process PID by reading
// /proc/<pid>/cgroup and stat-ing the cgroup directory. The inode number is
// the stable kernel-assigned cgroup ID used by bpf_get_current_cgroup_id().
func IDFromPid(pid int) (uint64, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if line := scanner.Text(); strings.HasPrefix(line, "0::") {
			dir := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(line, "0::"))
			var st syscall.Stat_t
			if err := syscall.Stat(dir, &st); err != nil {
				return 0, fmt.Errorf("stat %s: %w", dir, err)
			}
			return st.Ino, nil
		}
	}
	return 0, fmt.Errorf("cgroup v2 entry not found in /proc/%d/cgroup", pid)
}
