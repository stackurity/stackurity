package diag

import (
	"bufio"
	"bytes"
	"fmt"
	"math"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
)

// MemoryInfo is the memory this process may use and its Go memory limit.
// doctor runs in the server's environment (its container, or its systemd
// unit), so they are the server's.
type MemoryInfo struct {
	// Limit is the container's memory limit (cgroup), or else the host's
	// memory; 0 when neither can be read. LimitFrom says which.
	Limit     int64
	LimitFrom string
	// GoLimit is GOMEMLIMIT in bytes, 0 when it is not set; GoLimitRaw is
	// the variable as written.
	GoLimit    int64
	GoLimitRaw string
}

// cgroup files holding a memory limit, v2 then v1; then the host's memory.
var (
	cgroupV2 = "/sys/fs/cgroup/memory.max"
	cgroupV1 = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
	meminfo  = "/proc/meminfo"
)

func readMemory() MemoryInfo {
	m := MemoryInfo{GoLimitRaw: os.Getenv("GOMEMLIMIT")}
	// The runtime has parsed GOMEMLIMIT already; MaxInt64 means unset.
	if l := debug.SetMemoryLimit(-1); l != math.MaxInt64 {
		m.GoLimit = l
	}
	m.Limit, m.LimitFrom = memoryLimit(os.ReadFile)
	return m
}

// memoryLimit reads the cgroup limit, or else MemTotal.
func memoryLimit(read func(string) ([]byte, error)) (int64, string) {
	for _, f := range []string{cgroupV2, cgroupV1} {
		b, err := read(f)
		if err != nil {
			continue
		}
		v := strings.TrimSpace(string(b))
		n, err := strconv.ParseInt(v, 10, 64)
		// "max", or v1's "no limit" (a page-rounded MaxInt64), mean none.
		if err == nil && n > 0 && n < 1<<60 {
			return n, "container limit (" + f + ")"
		}
	}
	if b, err := read(meminfo); err == nil {
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) >= 2 && f[0] == "MemTotal:" {
				if kb, err := strconv.ParseInt(f[1], 10, 64); err == nil {
					return kb << 10, "host memory (no container limit)"
				}
			}
		}
	}
	return 0, ""
}

// checkMemory compares GOMEMLIMIT with the memory the server may use. A
// feed sync that grows the heap past the container's limit gets the server
// killed by the kernel; GOMEMLIMIT makes the garbage collector work harder
// before that (docs/operations.md, Memory).
func checkMemory(m MemoryInfo) Result {
	r := Result{Check: "memory", Status: Pass, Docs: "docs/operations.md#memory"}
	suggest := func() string {
		return fmt.Sprintf("Set GOMEMLIMIT=%dMiB (about 70%% of %s) in the server's environment and restart it.", m.Limit*7/10>>20, bytesIEC(m.Limit))
	}
	switch {
	case m.Limit == 0 && m.GoLimit == 0:
		r.Status, r.Title = Skip, "Memory limit not detectable on this system, and GOMEMLIMIT is not set"
		r.Detail = "Run doctor in the server's container or on its Linux host to compare them."
	case m.Limit == 0:
		r.Status, r.Title = Skip, "GOMEMLIMIT="+m.GoLimitRaw+"; the memory limit is not detectable on this system"
	case m.GoLimit == 0:
		r.Status = Warn
		r.Title = fmt.Sprintf("GOMEMLIMIT is not set (%s: %s)", m.LimitFrom, bytesIEC(m.Limit))
		r.Detail = "Without it the garbage collector does not work harder as memory runs out: a memory peak (a large feed sync) gets the server killed by the kernel's OOM killer."
		r.Next = suggest()
	case m.GoLimit >= m.Limit:
		r.Status = Fail
		r.Title = fmt.Sprintf("GOMEMLIMIT=%s is at or above the %s (%s)", m.GoLimitRaw, m.LimitFrom, bytesIEC(m.Limit))
		r.Detail = "The kernel kills the server before the garbage collector reacts to the limit."
		r.Next = suggest()
	case m.GoLimit*100 > m.Limit*85:
		r.Status = Warn
		r.Title = fmt.Sprintf("GOMEMLIMIT=%s is %d%% of the %s (%s)", m.GoLimitRaw, m.GoLimit*100/m.Limit, m.LimitFrom, bytesIEC(m.Limit))
		r.Detail = "Goroutine stacks, the runtime, stack packs and buffers are outside the Go heap and need the rest."
		r.Next = suggest()
	default:
		r.Title = fmt.Sprintf("GOMEMLIMIT=%s is %d%% of the %s (%s)", m.GoLimitRaw, m.GoLimit*100/m.Limit, m.LimitFrom, bytesIEC(m.Limit))
	}
	return r
}
