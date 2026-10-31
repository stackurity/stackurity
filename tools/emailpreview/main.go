// Command emailpreview renders bulk email campaigns to files, so their
// layout can be reviewed in a browser without sending anything:
//
//	go run ./tools/emailpreview -out /tmp/preview internal/notify/testdata/bulk/*.json
//
// Each argument is a campaign as JSON (notify.BulkCampaign: Key, Category
// and Message, as stored in email_campaigns.message), such as the samples
// of the release and vulnerability news emails in
// internal/notify/testdata/bulk. It writes <name>.html and <name>.txt to
// -out. The footer links are placeholders that work for nobody; it opens
// no database and no mail connection.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/stackurity/stackurity/internal/notify"
)

// noMail is the Mailer of a preview: it has a From address and sends
// nothing.
type noMail struct{ from string }

func (m noMail) From() string { return m.from }
func (m noMail) SendMail(context.Context, []string, notify.Message) error {
	return errors.New("emailpreview sends nothing")
}

func main() {
	out := flag.String("out", ".", "directory to write the previews to")
	base := flag.String("base-url", "https://app.stackurity.dev", "the dashboard address the links point to")
	from := flag.String("from", "Stackurity <news@stackurity.dev>", "the From address shown in the footer")
	postal := flag.String("postal-address", "", "the postal address shown in the footer (none: no address line)")
	flag.Parse()
	if flag.NArg() == 0 {
		fail(errors.New("name at least one campaign JSON file"))
	}
	b := &notify.Bulk{Mail: noMail{*from}, BaseURL: *base, PostalAddress: *postal}
	for _, path := range flag.Args() {
		raw, err := os.ReadFile(path)
		if err != nil {
			fail(err)
		}
		var c notify.BulkCampaign
		if err := json.Unmarshal(raw, &c); err != nil {
			fail(fmt.Errorf("%s: %w", path, err))
		}
		p, err := b.Preview(c)
		if err != nil {
			fail(fmt.Errorf("%s: %w", path, err))
		}
		name := filepath.Join(*out, strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)))
		for ext, body := range map[string]string{".html": p.HTML, ".txt": p.Text} {
			if err := os.WriteFile(name+ext, []byte(body), 0o644); err != nil {
				fail(err)
			}
		}
		fmt.Println(name + ".html")
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "emailpreview:", err)
	os.Exit(1)
}
