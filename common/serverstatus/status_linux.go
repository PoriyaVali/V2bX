//go:build linux

package serverstatus

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var lastIdle, lastTotal uint64

func GetSystemStatus() (*SystemStatus, error) {
	cpu, _ := getCPU()
	mem, swap, _ := getMem()
	disk, _ := getDisk("/")
	return &SystemStatus{CPU: cpu, Mem: mem, Swap: swap, Disk: disk}, nil
}

func getCPU() (float64, error) {
	read := func() (idle, total uint64, err error) {
		f, err := os.Open("/proc/stat")
		if err != nil {
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Scan()
		fields := strings.Fields(sc.Text())
		for i, v := range fields[1:] {
			n, _ := strconv.ParseUint(v, 10, 64)
			total += n
			if i == 3 {
				idle = n
			}
		}
		return
	}

	if lastTotal == 0 {
		lastIdle, lastTotal, _ = read()
		time.Sleep(200 * time.Millisecond)
	}
	idle, total, err := read()
	if err != nil || total == lastTotal {
		return 0, err
	}
	usage := (1.0 - float64(idle-lastIdle)/float64(total-lastTotal)) * 100.0
	lastIdle, lastTotal = idle, total
	return usage, nil
}

func getMem() (mem, swap MemStat, err error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer f.Close()
	m := make(map[string]uint64)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(fields[1], 10, 64)
		m[strings.TrimSuffix(fields[0], ":")] = v * 1024
	}
	mem = MemStat{Total: m["MemTotal"], Used: m["MemTotal"] - m["MemAvailable"]}
	swap = MemStat{Total: m["SwapTotal"], Used: m["SwapTotal"] - m["SwapFree"]}
	return
}

func getDisk(path string) (DiskStat, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return DiskStat{}, err
	}
	total := st.Blocks * uint64(st.Bsize)
	free := st.Bfree * uint64(st.Bsize)
	return DiskStat{Total: total, Used: total - free}, nil
}
