// Package helpdocs holds the dashboard's Help articles as text, for tools
// that answer how-to questions from them (internal/mcp read_help, used by
// Ask Stackurity and connected AI assistants). articles.json is generated
// from web/src/help by `npm run help-json` in web/; a web test fails when
// it is out of date, so the server always reads what people read in Help.
package helpdocs

import (
	_ "embed"
	"encoding/json"
	"sort"
	"strings"
	"sync"
)

//go:embed articles.json
var raw []byte

// Article is one Help article.
type Article struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Section  string `json:"section"`
	Summary  string `json:"summary"`
	Where    string `json:"where"`
	Keywords string `json:"keywords"`
	// Text is the body as Markdown; links to other articles are /help/ID.
	Text string `json:"text"`
}

var (
	once sync.Once
	all  []Article
	byID map[string]Article
)

func load() {
	once.Do(func() {
		if err := json.Unmarshal(raw, &all); err != nil {
			panic("helpdocs: articles.json: " + err.Error())
		}
		byID = make(map[string]Article, len(all))
		for _, a := range all {
			byID[a.ID] = a
		}
	})
}

// All returns every article, in Help's order.
func All() []Article {
	load()
	return append([]Article(nil), all...)
}

// Get returns the article with this id.
func Get(id string) (Article, bool) {
	load()
	a, ok := byID[strings.TrimSpace(strings.ToLower(id))]
	return a, ok
}

func words(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
}

// Search returns up to limit articles matching q, best first: every word of
// q must start a word of the article (title words count most, then the
// summary, keywords and menu path, then the text).
func Search(q string, limit int) []Article {
	load()
	qw := words(q)
	if len(qw) == 0 || limit <= 0 {
		return nil
	}
	type hit struct {
		a     Article
		score int
		order int
	}
	var hits []hit
	for i, a := range all {
		title, meta, body := words(a.Title), words(a.Summary+" "+a.Keywords+" "+a.Where+" "+a.ID), words(a.Text)
		score := 0
		for _, w := range qw {
			switch {
			case hasPrefix(title, w):
				score += 4
			case hasPrefix(meta, w):
				score += 2
			case hasPrefix(body, w):
				score++
			default:
				score = -1
			}
			if score < 0 {
				break
			}
		}
		if score > 0 {
			hits = append(hits, hit{a, score, i})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].score > hits[j].score })
	out := make([]Article, 0, min(limit, len(hits)))
	for _, h := range hits[:min(limit, len(hits))] {
		out = append(out, h.a)
	}
	return out
}

func hasPrefix(ws []string, p string) bool {
	for _, w := range ws {
		if strings.HasPrefix(w, p) {
			return true
		}
	}
	return false
}
