package auth

import (
	"bufio"
	"context"
	"crypto/sha1" //nolint:gosec // the Pwned Passwords range API is keyed by SHA-1; nothing is protected by it here
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Breached-password check (docs/network.md, "Breached-password check"):
// the Pwned Passwords range API with k-anonymity. Only the first five
// hexadecimal characters of the password's SHA-1 leave the server; the
// answer lists every suffix with that prefix (padded with fake entries,
// Add-Padding), and the match happens here.

// DefaultBreachURL is the Pwned Passwords range endpoint.
const DefaultBreachURL = "https://api.pwnedpasswords.com/range/"

// BreachChecker asks whether a password is in known data breaches.
type BreachChecker struct {
	// URL is the range endpoint; the prefix is appended. Empty is
	// DefaultBreachURL.
	URL string
	// HTTP makes the request; nil uses a client with a 3-second timeout
	// that follows no redirects.
	HTTP *http.Client
}

// ErrBreachedPassword wraps ErrBadPassword, so it answers 400 like a
// password that is too short.
type ErrBreachedPassword struct{ Count int }

func (e *ErrBreachedPassword) Error() string {
	return fmt.Sprintf("this password appears in known data breaches (%d times), so attackers try it first; choose another", e.Count)
}

func (e *ErrBreachedPassword) Unwrap() error { return ErrBadPassword }

var defaultBreachHTTP = &http.Client{
	Timeout:       3 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// Count reports how many times pw appears in breaches (0: not found).
func (c *BreachChecker) Count(ctx context.Context, pw string) (int, error) {
	sum := sha1.Sum([]byte(pw)) //nolint:gosec
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := h[:5], h[5:]
	url := c.URL
	if url == "" {
		url = DefaultBreachURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+prefix, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "stackurity")
	cl := c.HTTP
	if cl == nil {
		cl = defaultBreachHTTP
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("breached-password check: %s", resp.Status)
	}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 4<<20))
	for sc.Scan() {
		s, n, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if ok && strings.EqualFold(s, suffix) {
			count, _ := strconv.Atoi(n)
			return count, nil // padding entries have a count of 0
		}
	}
	return 0, sc.Err()
}

// CheckNewPassword applies the rules for a password someone chooses: 12 to
// 256 characters, and, with a checker, not in known breaches. When the
// check cannot be made, onUnavailable is called and the password is
// accepted (fail open): an unreachable service must not stop people from
// setting passwords.
func CheckNewPassword(ctx context.Context, c *BreachChecker, pw string, onUnavailable func(error)) error {
	if err := ValidPassword(pw); err != nil {
		return err
	}
	if c == nil {
		return nil
	}
	n, err := c.Count(ctx, pw)
	if err != nil {
		if onUnavailable != nil {
			onUnavailable(err)
		}
		return nil
	}
	if n > 0 {
		return &ErrBreachedPassword{Count: n}
	}
	return nil
}
