package memguard

import (
	"bufio"
	"strconv"
	"strings"
)

// meminfoField returns a /proc/meminfo value (reported in kB) in bytes.
func meminfoField(meminfo, name string) uint64 {
	sc := bufio.NewScanner(strings.NewReader(meminfo))
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, name+":") {
			continue
		}
		fields := strings.Fields(line[len(name)+1:])
		if len(fields) == 0 {
			return 0
		}
		v, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0
		}
		return v * 1024
	}
	return 0
}

// cgroupLimit parses a cgroup memory limit file: cgroup v2 memory.max holds
// "max" when unlimited; cgroup v1 memory.limit_in_bytes holds a huge number
// (about 2^63) instead. Both mean "no limit" and come back as 0.
func cgroupLimit(content string) uint64 {
	s := strings.TrimSpace(content)
	if s == "" || s == "max" {
		return 0
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v >= 1<<60 {
		return 0
	}
	return v
}

// smaller returns the smaller non-zero value; 0 means unknown.
func smaller(a, b uint64) uint64 {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	case a < b:
		return a
	}
	return b
}
