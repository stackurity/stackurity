package intel

import "testing"

func TestIssueTitle(t *testing.T) {
	for in, want := range map[string]string{
		"A security issue was fixed in nginx.":                                           "Security issue in nginx (fix available)",
		"Several security issues were fixed in OpenSSL.":                                 "Several security issues in OpenSSL (fix available)",
		"Security issues were fixed in libxml2":                                          "Security issues in libxml2 (fix available)",
		"Authorization Bypass in Next.js Middleware":                                     "Authorization Bypass in Next.js Middleware",
		"nginx could be made to crash if it received specially crafted network traffic.": "nginx could be made to crash if it received specially crafted network traffic.",
		"": "",
	} {
		if got := issueTitle(in); got != want {
			t.Errorf("issueTitle(%q) = %q, want %q", in, got, want)
		}
	}
}
