package webscan

import (
	"bytes"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// tagRef is an address a page loads, with the tag that loads it.
type tagRef struct {
	Tag       string // script, link, iframe, img, ...
	URL       *url.URL
	Integrity bool // has an integrity (SRI) attribute
}

// form is a form on a page.
type form struct {
	Action   *url.URL
	Password bool
}

// page is what one HTML page loads and says about itself.
type page struct {
	URL        *url.URL
	Title      string
	Generator  string
	Scripts    []tagRef // external scripts
	Styles     []tagRef // stylesheets
	Media      []tagRef // images, iframes, audio, video, objects
	Inline     [][]byte // inline script bodies
	Forms      []form
	Links      []*url.URL // a href
	DirListing bool
}

func parsePage(base *url.URL, body []byte) *page {
	p := &page{URL: base}
	z := html.NewTokenizer(bytes.NewReader(body))
	var inScript, inTitle bool
	var scriptBuf bytes.Buffer
	var cur *form
	resolve := func(s string) *url.URL {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "data:") || strings.HasPrefix(s, "javascript:") || strings.HasPrefix(s, "#") {
			return nil
		}
		u, err := base.Parse(s)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return nil
		}
		u.Fragment = ""
		return u
	}
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			if cur != nil {
				p.Forms = append(p.Forms, *cur)
			}
			p.DirListing = strings.HasPrefix(p.Title, "Index of /")
			return p
		case html.TextToken:
			if inScript {
				scriptBuf.Write(z.Text())
			} else if inTitle {
				p.Title += string(z.Text())
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			switch string(name) {
			case "script":
				if inScript && scriptBuf.Len() > 0 {
					p.Inline = append(p.Inline, bytes.Clone(scriptBuf.Bytes()))
				}
				inScript = false
				scriptBuf.Reset()
			case "title":
				inTitle = false
				p.Title = strings.TrimSpace(p.Title)
			case "form":
				if cur != nil {
					p.Forms = append(p.Forms, *cur)
					cur = nil
				}
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			attrs := map[string]string{}
			for hasAttr {
				var k, v []byte
				k, v, hasAttr = z.TagAttr()
				attrs[string(k)] = string(v)
			}
			if p.startTag(string(name), attrs, tt == html.StartTagToken, resolve, &cur) {
				inScript = true
			}
			if string(name) == "title" {
				inTitle = p.Title == ""
			}
		}
	}
}

// startTag records what one opening tag loads. It reports whether the tag
// starts an inline script whose text follows.
func (p *page) startTag(tag string, attrs map[string]string, opening bool, resolve func(string) *url.URL, cur **form) bool {
	_, integ := attrs["integrity"]
	switch tag {
	case "script":
		if u := resolve(attrs["src"]); u != nil {
			p.Scripts = append(p.Scripts, tagRef{Tag: tag, URL: u, Integrity: integ})
		} else if attrs["src"] == "" && opening {
			return true
		}
	case "link":
		rel := strings.ToLower(attrs["rel"])
		if u := resolve(attrs["href"]); u != nil {
			switch {
			case strings.Contains(rel, "stylesheet"):
				p.Styles = append(p.Styles, tagRef{Tag: tag, URL: u, Integrity: integ})
			case strings.Contains(rel, "modulepreload") || (strings.Contains(rel, "preload") && attrs["as"] == "script"):
				p.Scripts = append(p.Scripts, tagRef{Tag: tag, URL: u, Integrity: integ})
			}
		}
	case "img", "iframe", "audio", "video", "source", "embed":
		if u := resolve(attrs["src"]); u != nil {
			p.Media = append(p.Media, tagRef{Tag: tag, URL: u})
		}
	case "object":
		if u := resolve(attrs["data"]); u != nil {
			p.Media = append(p.Media, tagRef{Tag: tag, URL: u})
		}
	case "a":
		if u := resolve(attrs["href"]); u != nil {
			p.Links = append(p.Links, u)
		}
	case "meta":
		if strings.EqualFold(attrs["name"], "generator") && p.Generator == "" {
			p.Generator = attrs["content"]
		}
	case "form":
		if *cur != nil {
			p.Forms = append(p.Forms, **cur)
		}
		action := resolve(attrs["action"])
		if action == nil {
			action = p.URL
		}
		*cur = &form{Action: action}
	case "input":
		if *cur != nil && strings.EqualFold(attrs["type"], "password") {
			(*cur).Password = true
		}
	}
	return false
}
