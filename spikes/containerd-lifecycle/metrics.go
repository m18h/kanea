package main

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/containerd/containerd/v2/pkg/cio"

	"context"
)

// runMetrics answers spike question ③: does ONE scrape of containerd's
// /v1/metrics expose cpu+memory cgroup metrics for every alloc — including an
// alloc we placed under our own kanea-workloads.slice hierarchy (§5.2.11)?
func runMetrics(ctx context.Context) error {
	client, ctx, err := dial(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	img, err := ensureImage(ctx, client)
	if err != nil {
		return err
	}
	if err := writeCNINetConf(); err != nil {
		return err
	}
	if err := setupSlices(); err != nil { // one alloc lives under our hierarchy
		return err
	}

	ids := []string{"m-1", "m-2", "m-3"}
	cmd := []string{"sh", "-c", "tail -c 64M /dev/zero > /dev/null & exec yes > /dev/null"}
	allocs := map[string]alloc{
		"m-1": {ID: "m-1", Cmd: cmd},
		"m-2": {ID: "m-2", Cmd: cmd},
		"m-3": {ID: "m-3", Cmd: cmd, MemLimitMB: 256, CPUQuota: 100000, PidsLimit: 128,
			CgroupPath: "/kanea-workloads.slice/alloc-m-3"},
	}
	for _, id := range ids {
		a := allocs[id]
		if _, err := startAlloc(ctx, client, img, a); err != nil {
			return fmt.Errorf("start %s: %w", id, err)
		}
		defer removeAlloc(ctx, client, id)
	}
	time.Sleep(4 * time.Second) // let usage accumulate

	body, dur, err := scrape(metricsURL)
	if err != nil {
		return err
	}
	fmt.Printf("scraped %s: %d bytes in %v\n", metricsURL, len(body), dur.Round(time.Millisecond))

	// Which metric families carry our container IDs?
	fams := map[string]int{}
	for _, id := range ids {
		found := map[string]bool{}
		for _, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(line, "#") || !strings.Contains(line, id) {
				continue
			}
			name, _, _ := strings.Cut(line, "{")
			found[name] = true
			fams[name]++
		}
		cpu, mem := false, false
		for f := range found {
			if strings.Contains(f, "cpu") {
				cpu = true
			}
			if strings.Contains(f, "memory") {
				mem = true
			}
		}
		var list []string
		for f := range found {
			list = append(list, f)
		}
		sort.Strings(list)
		detail := fmt.Sprintf("cpu=%v memory=%v metrics=%v", cpu, mem, list)
		if id == "m-3" {
			check("single scrape covers "+id+" (custom cgroup path)", cpu && mem, detail)
		} else {
			check("single scrape covers "+id, cpu && mem, detail)
		}
	}

	// Sample lines verbatim for the report.
	fmt.Println("\nsample lines for m-1:")
	shown := 0
	for _, line := range strings.Split(string(body), "\n") {
		if !strings.HasPrefix(line, "#") && strings.Contains(line, "m-1") && shown < 6 {
			fmt.Println("  " + line)
			shown++
		}
	}

	// Scrape cost: 10 sequential scrapes.
	var tot time.Duration
	var size int
	for i := 0; i < 10; i++ {
		b, d, err := scrape(metricsURL)
		if err != nil {
			return err
		}
		tot += d
		size = len(b)
	}
	check("scrape latency (3 allocs)", true,
		fmt.Sprintf("mean %v, %d bytes/scrape over 10 scrapes", (tot/10).Round(time.Microsecond), size))

	return summary()
}

func scrape(url string) ([]byte, time.Duration, error) {
	t0 := time.Now()
	resp, err := http.Get(url) //nolint:bodyclose // closed below
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(resp.Body)
	return b, time.Since(t0), err
}

// nullIO keeps lifecycle.go readable; cio.NullIO is the task IO we want everywhere.
func nullIO() cio.Creator { return cio.NullIO }
