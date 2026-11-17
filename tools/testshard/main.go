// Command testshard splits a package's top-level tests into shards of about
// equal run time, using the times recorded in tools/ci/test-times.json, so CI
// waits for shards that finish together instead of for the one that happened
// to get the slow tests.
//
// Pick the tests for shard 2 of 3 (one name per line, from go test -list):
//
//	go test -list '^Test' ./internal/api | go run ./tools/testshard -shard 2 -of 3 -times tools/ci/test-times.json
//
// Refresh the recorded times from a go test -json run (see Makefile test-times):
//
//	go test -json -race ./internal/api | go run ./tools/testshard -record -times tools/ci/test-times.json
//
// Tests are placed longest first, each on the shard with the least time so far
// (ties go to the lowest shard), which keeps the shards within about one test's
// time of each other. A test with no recorded time (new since the last
// refresh) counts as the median recorded time. The split depends only on the
// test names and the times file, so every shard runner computes the same split
// and each test runs exactly once.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"
)

func main() {
	var (
		shard  = flag.Int("shard", 0, "shard to print, 1-based")
		of     = flag.Int("of", 0, "number of shards")
		times  = flag.String("times", "tools/ci/test-times.json", "recorded test times (JSON: package -> test -> seconds)")
		pkg    = flag.String("pkg", "github.com/stackurity/stackurity/internal/api", "package whose times to use or record")
		record = flag.Bool("record", false, "read go test -json from stdin and write its top-level test times for -pkg into -times")
	)
	flag.Parse()
	var err error
	if *record {
		err = recordTimes(os.Stdin, *times, *pkg)
	} else {
		err = printShard(os.Stdin, os.Stdout, *times, *pkg, *shard, *of)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "testshard:", err)
		os.Exit(1)
	}
}

type timesFile map[string]map[string]float64

func readTimes(path string) (timesFile, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return timesFile{}, nil
	}
	if err != nil {
		return nil, err
	}
	t := timesFile{}
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return t, nil
}

func printShard(in io.Reader, out io.Writer, timesPath, pkg string, shard, of int) error {
	if of < 1 || shard < 1 || shard > of {
		return fmt.Errorf("need 1 <= -shard <= -of, got %d of %d", shard, of)
	}
	var names []string
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); strings.HasPrefix(l, "Test") {
			names = append(names, l)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	t, err := readTimes(timesPath)
	if err != nil {
		return err
	}
	for _, n := range split(names, t[pkg], of)[shard-1] {
		fmt.Fprintln(out, n)
	}
	return nil
}

// split places names on of shards, longest recorded time first, each on the
// shard with the least total so far. Every name lands on exactly one shard.
func split(names []string, times map[string]float64, of int) [][]string {
	def := median(times)
	cost := func(n string) float64 {
		if s, ok := times[n]; ok {
			return s
		}
		return def
	}
	sorted := append([]string(nil), names...)
	sort.Slice(sorted, func(i, j int) bool {
		ci, cj := cost(sorted[i]), cost(sorted[j])
		if ci != cj {
			return ci > cj
		}
		return sorted[i] < sorted[j]
	})
	shards := make([][]string, of)
	load := make([]float64, of)
	for _, n := range sorted {
		best := 0
		for s := 1; s < of; s++ {
			if load[s] < load[best] {
				best = s
			}
		}
		shards[best] = append(shards[best], n)
		load[best] += cost(n)
	}
	for _, s := range shards {
		sort.Strings(s)
	}
	return shards
}

func median(times map[string]float64) float64 {
	if len(times) == 0 {
		return 1
	}
	v := make([]float64, 0, len(times))
	for _, s := range times {
		v = append(v, s)
	}
	sort.Float64s(v)
	if m := v[len(v)/2]; m > 0 {
		return m
	}
	return 0.01
}

// recordTimes replaces the times for pkg with the top-level test times from a
// go test -json stream. Other packages in the file are kept.
func recordTimes(in io.Reader, timesPath, pkg string) error {
	got := map[string]float64{}
	dec := json.NewDecoder(in)
	for {
		var ev struct {
			Action, Package, Test string
			Elapsed               float64
		}
		if err := dec.Decode(&ev); err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("reading go test -json: %w", err)
		}
		if ev.Package != pkg || ev.Test == "" || strings.Contains(ev.Test, "/") {
			continue
		}
		if ev.Action == "pass" || ev.Action == "fail" {
			got[ev.Test] = math.Round(ev.Elapsed*100) / 100
		}
	}
	if len(got) == 0 {
		return fmt.Errorf("no test results for %s in the input", pkg)
	}
	t, err := readTimes(timesPath)
	if err != nil {
		return err
	}
	t[pkg] = got
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(timesPath, append(b, '\n'), 0o644); err != nil {
		return err
	}
	var total float64
	for _, s := range got {
		total += s
	}
	fmt.Fprintf(os.Stderr, "recorded %d tests of %s, %.0fs in total\n", len(got), pkg, total)
	return nil
}
