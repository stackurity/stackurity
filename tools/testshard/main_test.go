package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSplitBalancesByTime(t *testing.T) {
	times := map[string]float64{"TestA": 100, "TestB": 60, "TestC": 50, "TestD": 10, "TestE": 1}
	got := split([]string{"TestE", "TestD", "TestC", "TestB", "TestA"}, times, 2)
	want := [][]string{{"TestA", "TestD", "TestE"}, {"TestB", "TestC"}} // 111s and 110s
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("split = %v, want %v", got, want)
	}
}

func TestSplitEveryTestOnce(t *testing.T) {
	var names []string
	times := map[string]float64{}
	for i := 0; i < 97; i++ {
		n := "Test" + strings.Repeat("x", i%7) + string(rune('A'+i%26)) + string(rune('a'+i/26))
		names = append(names, n)
		if i%3 != 0 { // a third have no recorded time
			times[n] = float64(i % 11)
		}
	}
	seen := map[string]int{}
	for _, s := range split(names, times, 3) {
		if len(s) == 0 {
			t.Fatal("empty shard")
		}
		for _, n := range s {
			seen[n]++
		}
	}
	for _, n := range names {
		if seen[n] != 1 {
			t.Fatalf("%s placed %d times", n, seen[n])
		}
	}
	// Same input in another order gives the same split (each runner computes it).
	rev := append([]string(nil), names...)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	if !reflect.DeepEqual(split(names, times, 3), split(rev, times, 3)) {
		t.Fatal("split depends on input order")
	}
}

func TestRecordAndShard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "times.json")
	os.WriteFile(path, []byte(`{"other/pkg": {"TestKeep": 3}}`), 0o644)
	stream := `{"Action":"run","Package":"p","Test":"TestSlow"}
{"Action":"pass","Package":"p","Test":"TestSlow/sub","Elapsed":9}
{"Action":"pass","Package":"p","Test":"TestSlow","Elapsed":9.004}
{"Action":"fail","Package":"p","Test":"TestFast","Elapsed":0.5}
{"Action":"pass","Package":"q","Test":"TestElsewhere","Elapsed":50}
{"Action":"pass","Package":"p","Elapsed":10}
`
	if err := recordTimes(strings.NewReader(stream), path, "p"); err != nil {
		t.Fatal(err)
	}
	tf, err := readTimes(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := (timesFile{"other/pkg": {"TestKeep": 3}, "p": {"TestSlow": 9, "TestFast": 0.5}}); !reflect.DeepEqual(tf, want) {
		t.Fatalf("times = %v, want %v", tf, want)
	}
	var out bytes.Buffer
	list := "TestSlow\nTestFast\nTestNew\nok  \tp\t0.1s\n"
	// TestNew has no time, so it counts as the median (9s) and sits
	// opposite TestSlow.
	if err := printShard(strings.NewReader(list), &out, path, "p", 2, 2); err != nil {
		t.Fatal(err)
	}
	if out.String() != "TestSlow\n" {
		t.Fatalf("shard 2 = %q", out.String())
	}
	if err := printShard(strings.NewReader(list), &out, path, "p", 3, 2); err == nil {
		t.Fatal("shard 3 of 2 accepted")
	}
}

func TestRecordNeedsResults(t *testing.T) {
	if err := recordTimes(strings.NewReader(""), filepath.Join(t.TempDir(), "t.json"), "p"); err == nil {
		t.Fatal("empty input accepted")
	}
}
