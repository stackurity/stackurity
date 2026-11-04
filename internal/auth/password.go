package auth

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The password rules (docs/install.md, "Passwords"). They apply when a
// password is set or changed; passwords set earlier keep working.
const (
	MinPasswordLength = 12
	MaxPasswordLength = 256
)

// ErrBadPassword is what every refused password unwraps to: one that
// breaks the rules (ErrWeakPassword) or is in known data breaches
// (ErrBreachedPassword).
var ErrBadPassword = errors.New("the password does not meet the rules")

// Rules a password can miss, as listed in ErrWeakPassword.Missing and in
// the details of a password_too_weak answer.
const (
	RuleLength    = "length"
	RuleLowercase = "lowercase"
	RuleUppercase = "uppercase"
	RuleDigit     = "digit"
	RuleSymbol    = "symbol"
)

// ErrWeakPassword is a password that breaks the rules. Missing lists them
// in a fixed order (RuleLength first); TooLong marks one over
// MaxPasswordLength.
type ErrWeakPassword struct {
	Missing []string
	TooLong bool
}

var ruleWords = map[string]string{
	RuleLowercase: "a lowercase letter",
	RuleUppercase: "an uppercase letter",
	RuleDigit:     "a digit",
	RuleSymbol:    "a symbol",
}

// Error says exactly what is missing, e.g. "Add an uppercase letter and a
// symbol." or "Use at least 12 characters, and add a digit."
func (e *ErrWeakPassword) Error() string {
	if e.TooLong {
		return "Use at most 256 characters."
	}
	var add []string
	short := false
	for _, m := range e.Missing {
		if m == RuleLength {
			short = true
		} else {
			add = append(add, ruleWords[m])
		}
	}
	switch {
	case short && len(add) == 0:
		return "Use at least 12 characters."
	case short:
		return "Use at least 12 characters, and add " + joinAnd(add) + "."
	}
	return "Add " + joinAnd(add) + "."
}

func (e *ErrWeakPassword) Unwrap() error { return ErrBadPassword }

func joinAnd(xs []string) string {
	if len(xs) <= 1 {
		return strings.Join(xs, "")
	}
	return strings.Join(xs[:len(xs)-1], ", ") + " and " + xs[len(xs)-1]
}

// ValidPassword applies the rules to a new password: 12 to 256 characters
// with at least one lowercase letter, one uppercase letter, one digit and
// one symbol. Letters of any script count by their case (é is lowercase, É
// uppercase); a letter without case (as in Chinese) is a letter, not a
// symbol. A symbol is any other character that is not a digit, a space, a
// combining mark or a control character. Spaces are allowed.
func ValidPassword(pw string) error {
	n := utf8.RuneCountInString(pw)
	if n > MaxPasswordLength {
		return &ErrWeakPassword{Missing: []string{RuleLength}, TooLong: true}
	}
	var lower, upper, digit, symbol bool
	for _, r := range pw {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLetter(r):
		case unicode.IsDigit(r):
			digit = true
		case unicode.IsSpace(r), unicode.IsMark(r), unicode.IsControl(r):
		default:
			symbol = true
		}
	}
	var missing []string
	for _, c := range []struct {
		ok   bool
		rule string
	}{{n >= MinPasswordLength, RuleLength}, {lower, RuleLowercase}, {upper, RuleUppercase}, {digit, RuleDigit}, {symbol, RuleSymbol}} {
		if !c.ok {
			missing = append(missing, c.rule)
		}
	}
	if len(missing) > 0 {
		return &ErrWeakPassword{Missing: missing}
	}
	return nil
}
