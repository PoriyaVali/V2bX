package memguard

import (
	"os"
	"strings"
)

func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// cgroupDir finds this process's cgroup v2 directory, if any.
func cgroupDir() string {
	for _, line := range strings.Split(readFile("/proc/self/cgroup"), "\n") {
		if strings.HasPrefix(line, "0::") {
			return "/sys/fs/cgroup" + strings.TrimPrefix(line, "0::")
		}
	}
	return ""
}

func cgroupMax() uint64 {
	if dir := cgroupDir(); dir != "" {
		if v := cgroupLimit(readFile(dir + "/memory.max")); v != 0 {
			return v
		}
	}
	if v := cgroupLimit(readFile("/sys/fs/cgroup/memory.max")); v != 0 {
		return v
	}
	return cgroupLimit(readFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"))
}

func cgroupUsage() uint64 {
	if dir := cgroupDir(); dir != "" {
		if v := cgroupLimit(readFile(dir + "/memory.current")); v != 0 {
			return v
		}
	}
	return cgroupLimit(readFile("/sys/fs/cgroup/memory/memory.usage_in_bytes"))
}

// ceilingBytes is the RAM this process can actually have: the cgroup limit if
// one is set (a container, or a systemd MemoryMax=), otherwise the machine's.
func ceilingBytes() uint64 {
	return smaller(cgroupMax(), meminfoField(readFile("/proc/meminfo"), "MemTotal"))
}

// availableBytes is what can still be allocated: the kernel's MemAvailable,
// or the cgroup's headroom when that is tighter.
func availableBytes() uint64 {
	avail := meminfoField(readFile("/proc/meminfo"), "MemAvailable")
	if max := cgroupMax(); max != 0 {
		if used := cgroupUsage(); used != 0 && used < max {
			avail = smaller(avail, max-used)
		}
	}
	return avail
}

func rssBytes() uint64 {
	return meminfoField(readFile("/proc/self/status"), "VmRSS")
}

func openFiles() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0
	}
	return len(entries)
}
