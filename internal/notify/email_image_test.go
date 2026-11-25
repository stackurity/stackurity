package notify

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEmailImage(t *testing.T) {
	im := &EmailImage{Src: "https://stackurity.ai/img/x.png", Alt: "Grade C, 71 out of 100", Link: "https://app.example/website-check"}
	got := emailHTML(Message{Title: "Graded", Summary: []string{"Hello."}, Image: im}, EmailBrand{})
	for _, want := range []string{`src="https://stackurity.ai/img/x.png"`, `alt="Grade C, 71 out of 100"`, `width="520"`, `max-width:520px`, `href="https://app.example/website-check"`} {
		if !strings.Contains(got, want) {
			t.Errorf("html lacks %s", want)
		}
	}
	if i, h := strings.Index(got, "<img"), strings.Index(got, "</h1>"); i < h {
		t.Error("the picture comes after the heading")
	}
	for name, bad := range map[string]*EmailImage{
		"http":   {Src: "http://stackurity.ai/x.png", Alt: "x"},
		"no alt": {Src: "https://stackurity.ai/x.png", Alt: " "},
		"data":   {Src: "data:image/png;base64,AAAA", Alt: "x"},
	} {
		if strings.Contains(emailHTML(Message{Title: "T", Image: bad}, EmailBrand{}), "<img src=\"data") || emailImage(bad) != "" {
			t.Errorf("%s: picture shown", name)
		}
	}
	if !strings.Contains(emailImage(&EmailImage{Src: "https://a/x.png", Alt: "x", Width: 2000}), `width="520"`) {
		t.Error("a picture wider than the email is shown at 520")
	}
	b, _ := json.Marshal(Message{Title: "T", Image: im})
	if strings.Contains(string(b), "stackurity.ai/img") {
		t.Errorf("webhooks get the picture: %s", b)
	}
	if strings.Contains(emailText(Message{Title: "T", Summary: []string{"Hello."}, Image: im}, EmailBrand{}), "<img") {
		t.Error("plain text has HTML")
	}
}
