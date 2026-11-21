package mcp

import (
	"context"
	"strings"

	"github.com/stackurity/stackurity/internal/helpdocs"
)

// read_help answers how-to questions from the dashboard's own Help articles
// (internal/helpdocs), so Ask Stackurity and connected assistants give the
// steps people read in Help, not steps from memory. It reads no
// organisation data and calls no API.

func init() {
	readTitles["read_help"] = "Read a Help article"
	tools["read_help"] = tool{
		description: "How to use and set up Stackurity, from its Help articles: adding servers, repositories, images and " +
			"clouds, connecting Slack, Teams, Jira, GitHub or GitLab, inviting people, roles, projects, notifications, " +
			"risk policy, automatic fixes, evidence reports, two-factor sign-in, API tokens and more. With id, returns that " +
			"article: title, where it is in the menu, page (its Help page, /help/ID) and text (Markdown, with steps and links " +
			"to Stackurity pages). With query, returns the best-matching articles (id, title, summary) to read next. With " +
			"neither, lists every article. Answer how-to questions from the article's steps, and link its page.",
		schema: obj(map[string]any{
			"id":    str("A Help article id, e.g. add-server, notifications, users-teams-roles"),
			"query": str("Words to find an article by, e.g. 'connect slack' or 'invite people'"),
		}),
		run: func(_ context.Context, _ API, a map[string]any) (any, error) {
			id, _ := a["id"].(string)
			if id = strings.TrimSpace(id); id != "" {
				art, ok := helpdocs.Get(id)
				if !ok {
					return map[string]any{"message": "No Help article has that id.", "articles": helpList(helpdocs.All())}, nil
				}
				return map[string]any{"id": art.ID, "title": art.Title, "where": art.Where, "page": "/help/" + art.ID,
					"summary": art.Summary, "text": art.Text}, nil
			}
			q, _ := a["query"].(string)
			if q = strings.TrimSpace(q); q != "" {
				hits := helpdocs.Search(q, 5)
				if len(hits) == 0 {
					return map[string]any{"message": "No Help article matches; these are all of them.", "articles": helpList(helpdocs.All())}, nil
				}
				return map[string]any{"articles": helpList(hits)}, nil
			}
			return map[string]any{"articles": helpList(helpdocs.All())}, nil
		},
	}
}

func helpList(as []helpdocs.Article) []map[string]any {
	out := make([]map[string]any, 0, len(as))
	for _, a := range as {
		out = append(out, map[string]any{"id": a.ID, "title": a.Title, "summary": a.Summary, "page": "/help/" + a.ID})
	}
	return out
}
