// Command emailpreview renders email to files, so its layout can be
// reviewed in a browser without sending anything.
//
// Every kind of email the server sends, from its sample
// (notify.EmailSamples), checked with notify.CheckEmail (make
// email-preview):
//
//	go run ./tools/emailpreview -samples -out /tmp/emails
//
// writes <name>.html and <name>.txt per email and an index.html linking
// them all; it fails if an email does not pass the checks.
//
// Bulk email campaigns as JSON (notify.BulkCampaign: Key, Category and
// Message, as stored in email_campaigns.message), such as the samples in
// internal/notify/testdata/bulk:
//
//	go run ./tools/emailpreview -out /tmp/preview internal/notify/testdata/bulk/*.json
//
// The links are placeholders that work for nobody; it opens no database
// and no mail connection.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
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
	from := flag.String("from", "", `the From address (default "Stackurity <no-reply@stackurity.dev>" with -samples, "Stackurity <news@stackurity.dev>" for campaigns)`)
	postal := flag.String("postal-address", "", "the postal address shown in the footer of campaigns (none: no address line)")
	samples := flag.Bool("samples", false, "render every kind of email the server sends, from its sample")
	privacy := flag.String("privacy-url", "", "with -samples: the privacy page the footer links to")
	support := flag.String("support-url", "", "with -samples: the support address the footer links to (https or mailto)")
	flag.Parse()
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fail(err)
	}
	if *samples {
		if *from == "" {
			*from = "Stackurity <no-reply@stackurity.dev>"
		}
		notify.SetEmailBrand(notify.EmailBrand{Home: *base, PrivacyURL: *privacy, SupportURL: *support})
		if err := renderSamples(*out, *base, *from); err != nil {
			fail(err)
		}
		return
	}
	if *from == "" {
		*from = "Stackurity <news@stackurity.dev>"
	}
	if flag.NArg() == 0 {
		fail(errors.New("name at least one campaign JSON file, or use -samples"))
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

// renderSamples writes every sample, checked, and an index.
func renderSamples(out, base, from string) error {
	addr, err := mail.ParseAddress(from)
	if err != nil {
		return fmt.Errorf("-from: %w", err)
	}
	var index strings.Builder
	index.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Stackurity emails</title>` +
		`<style>body{font:15px/1.5 system-ui,sans-serif;margin:32px;color:#0f1b33}td{padding:4px 12px 4px 0;vertical-align:top}.bad{color:#b4123a}</style>` +
		`</head><body><h1>Stackurity emails</h1><p>Rendered for ` + html.EscapeString(base) + `. Each passes notify.CheckEmail.</p><table>` + "\n")
	var failed []string
	for _, s := range notify.EmailSamples(base) {
		raw := notify.RenderEmail(from, []string{"dana@northwind-traders.com"}, s.Message)
		problems := notify.CheckEmail(raw, s.Message, notify.EmailCheck{Base: base, FromName: addr.Name, Notification: s.Notification, Secrets: s.Secrets})
		subject, text, page, err := parts(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", s.Name, err)
		}
		for ext, body := range map[string]string{".html": page, ".txt": "Subject: " + subject + "\n\n" + text, ".eml": string(raw)} {
			if err := os.WriteFile(filepath.Join(out, s.Name+ext), []byte(body), 0o644); err != nil {
				return err
			}
		}
		status := "ok"
		if len(problems) > 0 {
			status = `<span class="bad">` + html.EscapeString(strings.Join(problems, "; ")) + "</span>"
			failed = append(failed, s.Name+": "+strings.Join(problems, "; "))
		}
		fmt.Fprintf(&index, `<tr><td><a href="%s.html">%s</a></td><td>%s</td><td><a href="%s.txt">text</a></td><td>%s</td></tr>`+"\n",
			s.Name, s.Name, html.EscapeString(subject), s.Name, status)
		fmt.Println(filepath.Join(out, s.Name+".html"))
	}
	index.WriteString("</table></body></html>\n")
	if err := os.WriteFile(filepath.Join(out, "index.html"), []byte(index.String()), 0o644); err != nil {
		return err
	}
	if len(failed) > 0 {
		return errors.New("emails that fail the checks:\n  " + strings.Join(failed, "\n  "))
	}
	return nil
}

// parts decodes an email into its subject, text and HTML.
func parts(raw []byte) (subject, text, page string, err error) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return "", "", "", err
	}
	subject, _ = new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	_, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		return "", "", "", err
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", "", "", err
		}
		b, _ := io.ReadAll(p)
		if strings.HasPrefix(p.Header.Get("Content-Type"), "text/html") {
			page = string(b)
		} else {
			text = string(b)
		}
	}
	return subject, strings.ReplaceAll(text, "\r\n", "\n"), strings.ReplaceAll(page, "\r\n", "\n"), nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "emailpreview:", err)
	os.Exit(1)
}
