package notify

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/stackurity/stackurity/internal/store"
)

// Lists for setting up a Connect Jira channel: the site's projects, and a
// project's issue types, statuses and priorities, read with the
// connection's token so the administrator picks instead of typing.

// JiraProject is a project the connection can see.
type JiraProject struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

// JiraIssueType is an issue type of a project.
type JiraIssueType struct {
	Name    string `json:"name"`
	Subtask bool   `json:"subtask"`
}

// JiraStatus is a status of an issue type's workflow; Category is new,
// indeterminate or done.
type JiraStatus struct {
	Name     string `json:"name"`
	Category string `json:"category"`
}

// JiraProjectMeta is what a channel's settings are picked from.
type JiraProjectMeta struct {
	Key        string                  `json:"key"`
	Name       string                  `json:"name"`
	IssueTypes []JiraIssueType         `json:"issue_types"`
	Statuses   map[string][]JiraStatus `json:"statuses"` // by issue type name
	Priorities []string                `json:"priorities"`
}

// JiraSetup reads a connection's site for the setup lists.
type JiraSetup struct{ j *jiraClient }

// JiraSetup returns a reader of a connection's site (cloudID), or an error
// when the connection is not usable (store.ErrNotFound when it is not the
// context's workspace's).
func (d *Dispatcher) JiraSetup(ctx context.Context, connection int64, cloudID string) (*JiraSetup, error) {
	if !jiraCloudIDRe.MatchString(cloudID) {
		return nil, store.ErrNotFound
	}
	if _, err := d.Store.GetJiraConnection(ctx, connection); err != nil {
		return nil, err
	}
	j, err := d.jiraConnectionClient(ctx, ChannelConfig{Auth: JiraAuthOAuth, ConnectionID: connection, CloudID: cloudID})
	if err != nil {
		return nil, err
	}
	return &JiraSetup{j: j}, nil
}

// jiraListLimit bounds the projects listed.
const jiraListLimit = 500

// Projects lists the site's projects whose key or name contains query
// (all when empty), by name, at most jiraListLimit.
func (s *JiraSetup) Projects(ctx context.Context, query string) ([]JiraProject, error) {
	out := []JiraProject{}
	for start := 0; start < jiraListLimit; {
		q := url.Values{"startAt": {strconv.Itoa(start)}, "maxResults": {"50"}, "orderBy": {"name"}}
		if query = strings.TrimSpace(query); query != "" {
			q.Set("query", clip(query, 100))
		}
		var page struct {
			Values []struct {
				Key  string `json:"key"`
				Name string `json:"name"`
			} `json:"values"`
			IsLast bool `json:"isLast"`
		}
		if err := s.j.do(ctx, "GET", "/project/search?"+q.Encode(), nil, &page); err != nil {
			return nil, err
		}
		for _, p := range page.Values {
			if jiraProjectRe.MatchString(p.Key) {
				out = append(out, JiraProject{Key: p.Key, Name: clip(p.Name, 200)})
			}
		}
		if page.IsLast || len(page.Values) == 0 {
			break
		}
		start += len(page.Values)
	}
	return out, nil
}

// ProjectMeta reads a project's issue types, their statuses, and the
// site's priorities.
func (s *JiraSetup) ProjectMeta(ctx context.Context, key string) (*JiraProjectMeta, error) {
	if !jiraProjectRe.MatchString(key) {
		return nil, &PermanentError{errors.New("not a Jira project key")}
	}
	var proj struct {
		Key        string `json:"key"`
		Name       string `json:"name"`
		IssueTypes []struct {
			Name    string `json:"name"`
			Subtask bool   `json:"subtask"`
		} `json:"issueTypes"`
	}
	if err := s.j.do(ctx, "GET", "/project/"+url.PathEscape(key), nil, &proj); err != nil {
		return nil, fmt.Errorf("project %s: %w", key, err)
	}
	m := &JiraProjectMeta{Key: proj.Key, Name: clip(proj.Name, 200), IssueTypes: []JiraIssueType{}, Statuses: map[string][]JiraStatus{}, Priorities: []string{}}
	for _, t := range firstN(proj.IssueTypes, 100) {
		m.IssueTypes = append(m.IssueTypes, JiraIssueType{Name: clip(t.Name, 60), Subtask: t.Subtask})
	}
	var flows []struct {
		Name     string `json:"name"`
		Statuses []struct {
			Name           string `json:"name"`
			StatusCategory struct {
				Key string `json:"key"`
			} `json:"statusCategory"`
		} `json:"statuses"`
	}
	if err := s.j.do(ctx, "GET", "/project/"+url.PathEscape(key)+"/statuses", nil, &flows); err != nil {
		return nil, fmt.Errorf("project %s statuses: %w", key, err)
	}
	for _, f := range firstN(flows, 100) {
		var st []JiraStatus
		for _, x := range firstN(f.Statuses, 100) {
			st = append(st, JiraStatus{Name: clip(x.Name, 100), Category: x.StatusCategory.Key})
		}
		m.Statuses[clip(f.Name, 60)] = st
	}
	var prios []struct {
		Name string `json:"name"`
	}
	if err := s.j.do(ctx, "GET", "/priority", nil, &prios); err == nil {
		for _, p := range firstN(prios, 50) {
			m.Priorities = append(m.Priorities, clip(p.Name, 60))
		}
	}
	return m, nil
}
