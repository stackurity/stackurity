package helpdocs

import "testing"

func TestArticlesLoad(t *testing.T) {
	all := All()
	if len(all) < 40 {
		t.Fatalf("only %d articles", len(all))
	}
	seen := map[string]bool{}
	for _, a := range all {
		if a.ID == "" || a.Title == "" || len(a.Text) < 20 || seen[a.ID] {
			t.Errorf("bad or repeated article %+v", a.ID)
		}
		seen[a.ID] = true
	}
	if a, ok := Get("add-server"); !ok || a.Title == "" {
		t.Error("add-server missing")
	}
	if _, ok := Get("no-such-article"); ok {
		t.Error("unknown id found")
	}
}

func TestSearchRanksTitlesFirst(t *testing.T) {
	got := Search("add server", 3)
	if len(got) == 0 || got[0].ID != "add-server" {
		t.Fatalf("add server -> %v", ids(got))
	}
	if got := Search("two factor", 2); len(got) == 0 || got[0].ID != "two-factor" {
		t.Errorf("two factor -> %v", ids(got))
	}
	if got := Search("zzqx", 3); len(got) != 0 {
		t.Errorf("nonsense matched %v", ids(got))
	}
	if got := Search("", 3); got != nil {
		t.Errorf("empty query matched %v", ids(got))
	}
}

func ids(as []Article) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.ID
	}
	return out
}
