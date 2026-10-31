// Package words makes counted text agree in number: "1 server", "3
// servers", "0 servers"; "hasn't" or "haven't". Reporting titles,
// notification bodies, summaries and Platform health use it, so a single
// server never reads "1 servers" and a lone application never "its 1
// application".
package words

import (
	"strconv"
	"strings"
)

// Pick is one when n is 1, otherwise many (0 takes the plural, as English
// does: "0 servers").
func Pick(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// Count is n with the noun that agrees with it: "1 server", "3 servers",
// "19,558 findings".
func Count(n int, one, many string) string {
	return Thousands(n) + " " + Pick(n, one, many)
}

// Thousands formats 19558 as "19,558".
func Thousands(n int) string {
	s := strconv.Itoa(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}
