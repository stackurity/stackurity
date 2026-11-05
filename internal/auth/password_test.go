package auth

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestValidPassword(t *testing.T) {
	cases := []struct {
		pw      string
		missing []string // nil: accepted
		msg     string
	}{
		{"Abcdefgh1!xy", nil, ""}, // exactly 12
		{"Abcdefg1!xy", []string{RuleLength}, "Use at least 12 characters."}, // 11
		{"abcdefgh1!xy", []string{RuleUppercase}, "Add an uppercase letter."},
		{"ABCDEFGH1!XY", []string{RuleLowercase}, "Add a lowercase letter."},
		{"Abcdefghi!xy", []string{RuleDigit}, "Add a digit."},
		{"Abcdefghi1xy", []string{RuleSymbol}, "Add a symbol."},
		{"abcdefghijkl", []string{RuleUppercase, RuleDigit, RuleSymbol}, "Add an uppercase letter, a digit and a symbol."},
		{"abcdefghijk1", []string{RuleUppercase, RuleSymbol}, "Add an uppercase letter and a symbol."},
		{"short", []string{RuleLength, RuleUppercase, RuleDigit, RuleSymbol}, "Use at least 12 characters, and add an uppercase letter, a digit and a symbol."},
		{"", []string{RuleLength, RuleLowercase, RuleUppercase, RuleDigit, RuleSymbol}, "Use at least 12 characters, and add a lowercase letter, an uppercase letter, a digit and a symbol."},
		// Spaces are allowed and are not symbols.
		{"Correct horse battery 9", []string{RuleSymbol}, "Add a symbol."},
		{"Correct horse battery 9!", nil, ""},
		// Letters of other scripts count by their case; a symbol can be
		// any punctuation or sign.
		{"émile ÉCOLE 12€", nil, ""},
		{"ÄÖÜäöü123456", []string{RuleSymbol}, "Add a symbol."},
		{"Ab1密码密码密码密码密码", []string{RuleSymbol}, "Add a symbol."}, // caseless letters are not symbols
		{"Ab1~密码密码密码密码", nil, ""},
		{"Abcdefgh1 x😀", nil, ""}, // 12 characters, one an emoji
		// A combining accent is part of a letter, not a symbol.
		{"Abcdefghé1xy", []string{RuleSymbol}, "Add a symbol."},
		// Length counts characters, not bytes.
		{"Aé1!éééééé", []string{RuleLength}, "Use at least 12 characters."},
	}
	for _, c := range cases {
		err := ValidPassword(c.pw)
		if c.missing == nil {
			if err != nil {
				t.Errorf("%q refused: %v", c.pw, err)
			}
			continue
		}
		var w *ErrWeakPassword
		if !errors.As(err, &w) || !errors.Is(err, ErrBadPassword) {
			t.Errorf("%q: %v", c.pw, err)
			continue
		}
		if !reflect.DeepEqual(w.Missing, c.missing) || err.Error() != c.msg {
			t.Errorf("%q: missing %v %q, want %v %q", c.pw, w.Missing, err.Error(), c.missing, c.msg)
		}
	}
	max := "Aa1!" + strings.Repeat("x", 252)
	if err := ValidPassword(max); err != nil {
		t.Errorf("256 characters refused: %v", err)
	}
	var w *ErrWeakPassword
	if err := ValidPassword(max + "x"); !errors.As(err, &w) || !w.TooLong || err.Error() != "Use at most 256 characters." {
		t.Errorf("257 characters: %v", err)
	}
}
