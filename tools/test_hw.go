// 儲存為 test_hw.go
package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

func main() {
	cpus := runtime.NumCPU()
	ramGB := 32

	if f, err := os.Open("/proc/meminfo"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if kb, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
						ramGB = int(kb / 1024 / 1024)
					}
				}
				break
			}
		}
	}

	duckMemoryGB := int(float64(ramGB) * 0.68)
	duckThreads := cpus / 2
	if duckThreads > 16 {
		duckThreads = 16
	}

	fmt.Printf("CPU: %d vCPU, RAM: %d GB -> DuckDB 配額: %dGB / %d 執行緒\n", cpus, ramGB, duckMemoryGB, duckThreads)
}