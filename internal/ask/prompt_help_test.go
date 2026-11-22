package ask

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/helpdocs"
)

// Every Help article the prompt lets the model link, read_help can read: the
// list in SystemPrompt and the dashboard's Help (internal/helpdocs) agree.
func TestPromptHelpSlugsExist(t *testing.T) {
	m := regexp.MustCompile(`where SLUG is one of: ([a-z0-9, -]+)\.`).FindStringSubmatch(SystemPrompt)
	if m == nil {
		t.Fatal("no Help article list in SystemPrompt")
	}
	for _, s := range strings.Split(m[1], ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		if _, ok := helpdocs.Get(s); !ok {
			t.Errorf("SystemPrompt lists /help/%s, which is not a Help article", s)
		}
	}
	if !strings.Contains(SystemPrompt, "read_help") {
		t.Error("SystemPrompt does not say when to use read_help")
	}
}
