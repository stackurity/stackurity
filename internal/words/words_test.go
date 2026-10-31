package words

import "testing"

func TestCount(t *testing.T) {
	for _, c := range []struct {
		n         int
		one, many string
		want      string
	}{
		{0, "server", "servers", "0 servers"},
		{1, "server", "servers", "1 server"},
		{2, "server", "servers", "2 servers"},
		{1, "repository", "repositories", "1 repository"},
		{5, "repository", "repositories", "5 repositories"},
		{1, "release", "releases", "1 release"},
		{11, "release", "releases", "11 releases"},
		{19558, "finding", "findings", "19,558 findings"},
		{-1200, "day", "days", "-1,200 days"},
	} {
		if got := Count(c.n, c.one, c.many); got != c.want {
			t.Errorf("Count(%d, %q) = %q, want %q", c.n, c.one, got, c.want)
		}
	}
	for n, want := range map[int]string{0: "haven't", 1: "hasn't", 2: "haven't"} {
		if got := Pick(n, "hasn't", "haven't"); got != want {
			t.Errorf("Pick(%d) = %q", n, got)
		}
	}
}
