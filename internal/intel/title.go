package intel

import (
	"regexp"
	"strings"
)

// fixedInSummary matches distribution advisory summaries written from the
// vendor's side, such as Ubuntu's "A security issue was fixed in nginx." or
// "Several security issues were fixed in OpenSSL.".
var fixedInSummary = regexp.MustCompile(`(?i)^(a|one|several|multiple|some|two|three)?\s*security (issue|issues|vulnerability|vulnerabilities) (was|were|has been|have been) (fixed|addressed) in (.+?)\.?$`)

// issueTitle is a finding's title from its advisory summary. A summary that
// says an issue "was fixed" describes the vendor's update, but the finding
// is open on the customer's asset, so it is reworded to say what is wrong
// and that a fix exists: "Security issue in nginx (fix available)".
func issueTitle(summary string) string {
	s := strings.TrimSpace(summary)
	m := fixedInSummary.FindStringSubmatch(s)
	if m == nil {
		return s
	}
	what := "Security issue"
	if q := strings.ToLower(m[1]); strings.HasSuffix(strings.ToLower(m[2]), "s") || (q != "" && q != "a" && q != "one") {
		what = "Security issues"
		if q != "" && q != "a" && q != "one" {
			what = strings.ToUpper(q[:1]) + q[1:] + " security issues"
		}
	}
	return what + " in " + m[5] + " (fix available)"
}
