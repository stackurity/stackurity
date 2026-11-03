package darwin

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"howett.net/plist"
)

// maxPlistBytes bounds one property list. Info.plist files are a few KB;
// anything near this is not one, and a file another user can write (an app
// under ~/Applications) must not make the agent read gigabytes.
const maxPlistBytes = 1 << 20

var errPlistTooLarge = errors.New("property list larger than 1 MiB")

// readPlist reads an XML or binary property list whose top level is a
// dictionary. Decoding is guarded: the file may come from anyone who can
// write an application bundle, so a malformed one is an error for that
// file, never a crash of the agent.
func readPlist(path string) (out map[string]any, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		return nil, err
	} else if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxPlistBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPlistBytes {
		return nil, errPlistTooLarge
	}
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("malformed property list: %v", r)
		}
	}()
	var m map[string]any
	if _, err := plist.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("malformed property list: %w", err)
	}
	return m, nil
}

// str returns a top-level string value, trimmed; "" when absent or not a
// string.
func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return strings.TrimSpace(s)
}

// clean removes control and formatting characters (a WhatsApp bundle
// name starts with U+200E) and clips s to max bytes (at a rune
// boundary): values come from files anyone who can write a bundle chooses.
func clean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	s = strings.TrimSpace(s)
	for len(s) > max {
		_, n := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-n]
	}
	return s
}

// cleanVersion keeps the version itself from a bundle version string:
// some vendors append text ("3.13.3, (c) 2001-2024 Python Software
// Foundation.").
func cleanVersion(s string) string {
	s = clean(s, 256)
	if i := strings.IndexAny(s, " ,;("); i >= 0 {
		s = s[:i]
	}
	return s
}
