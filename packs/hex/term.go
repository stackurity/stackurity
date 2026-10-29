package main

import (
	"fmt"
	"strings"
)

// term is an Elixir literal as mix.lock writes it: a map, tuple, list,
// string, atom, number or boolean. mix.lock is printed with inspect/2, so it
// holds no code, only these.
type term struct {
	kind  termKind
	s     string    // string, atom (without ':') and other scalar text
	items []term    // tuple and list elements; a keyword pair is a 2-tuple
	pairs []mapPair // map entries, in file order
}

type mapPair struct{ key, value term }

type termKind int

const (
	tString termKind = iota
	tAtom
	tNumber
	tTuple
	tList
	tMap
)

// maxDepth bounds nesting so a hostile file cannot exhaust the stack.
const maxDepth = 64

type termParser struct {
	src   string
	pos   int
	depth int
}

func parseTerm(src string) (term, error) {
	p := &termParser{src: src}
	t, err := p.value()
	if err != nil {
		return term{}, err
	}
	p.space()
	if p.pos != len(p.src) {
		return term{}, p.errf("unexpected text after the lock map")
	}
	return t, nil
}

func (p *termParser) errf(format string, args ...any) error {
	line := strings.Count(p.src[:min(p.pos, len(p.src))], "\n") + 1
	return fmt.Errorf("line %d: %s", line, fmt.Sprintf(format, args...))
}

func (p *termParser) space() {
	for p.pos < len(p.src) {
		switch c := p.src[p.pos]; {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			p.pos++
		case c == '#': // a comment, to the end of the line
			for p.pos < len(p.src) && p.src[p.pos] != '\n' {
				p.pos++
			}
		default:
			return
		}
	}
}

func (p *termParser) peek(s string) bool { return strings.HasPrefix(p.src[p.pos:], s) }

func (p *termParser) value() (term, error) {
	p.space()
	if p.pos >= len(p.src) {
		return term{}, p.errf("unexpected end of file")
	}
	switch c := p.src[p.pos]; {
	case p.peek("%{"):
		p.pos += 2
		return p.mapBody()
	case c == '{':
		p.pos++
		items, err := p.seq('}')
		return term{kind: tTuple, items: items}, err
	case c == '[':
		p.pos++
		items, err := p.seq(']')
		return term{kind: tList, items: items}, err
	case c == '"' || c == '\'':
		s, err := p.str()
		return term{kind: tString, s: s}, err
	case c == ':':
		p.pos++
		if p.pos < len(p.src) && p.src[p.pos] == '"' {
			s, err := p.str()
			return term{kind: tAtom, s: s}, err
		}
		id := p.ident()
		if id == "" {
			return term{}, p.errf("expected an atom")
		}
		return term{kind: tAtom, s: id}, nil
	case c == '-' || (c >= '0' && c <= '9'):
		start := p.pos
		p.pos++
		for p.pos < len(p.src) && strings.IndexByte("0123456789._eE+-", p.src[p.pos]) >= 0 {
			p.pos++
		}
		return term{kind: tNumber, s: p.src[start:p.pos]}, nil
	default:
		id := p.ident()
		switch id {
		case "true", "false", "nil":
			return term{kind: tAtom, s: id}, nil
		}
		return term{}, p.errf("unexpected %q", c)
	}
}

// ident reads an identifier or an atom's name (letters, digits, _, @, and a
// trailing ? or !).
func (p *termParser) ident() string {
	start := p.pos
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == '_' || c == '@' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			p.pos++
			continue
		}
		if (c == '?' || c == '!') && p.pos > start {
			p.pos++
		}
		break
	}
	return p.src[start:p.pos]
}

// str reads a double- or single-quoted literal with Elixir's escapes.
func (p *termParser) str() (string, error) {
	q := p.src[p.pos]
	p.pos++
	var b strings.Builder
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		switch {
		case c == q:
			p.pos++
			return b.String(), nil
		case c == '\\' && p.pos+1 < len(p.src):
			p.pos++
			e := p.src[p.pos]
			switch e {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			default:
				b.WriteByte(e)
			}
			p.pos++
		case c == '#' && p.peek("#{"):
			return "", p.errf("interpolation is not allowed in a lock file")
		default:
			b.WriteByte(c)
			p.pos++
		}
	}
	return "", p.errf("unterminated string")
}

// seq reads comma-separated items up to close. An item may be a keyword
// pair (repo: "hexpm"), kept as a 2-tuple of an atom and the value.
func (p *termParser) seq(close byte) ([]term, error) {
	if p.depth++; p.depth > maxDepth {
		return nil, p.errf("nested too deeply")
	}
	defer func() { p.depth-- }()
	var items []term
	for {
		p.space()
		if p.pos >= len(p.src) {
			return nil, p.errf("unexpected end of file")
		}
		if p.src[p.pos] == close {
			p.pos++
			return items, nil
		}
		if key, ok := p.keyword(); ok {
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			items = append(items, term{kind: tTuple, items: []term{{kind: tAtom, s: key}, v}})
		} else {
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			items = append(items, v)
		}
		p.space()
		if p.pos < len(p.src) && p.src[p.pos] == ',' {
			p.pos++
			continue
		}
		if p.pos < len(p.src) && p.src[p.pos] == close {
			continue
		}
		return nil, p.errf("expected , or %c", close)
	}
}

// keyword reads "name: " or "\"name\": " (a keyword key), restoring the
// position when there is none.
func (p *termParser) keyword() (string, bool) {
	start := p.pos
	var key string
	if p.pos < len(p.src) && p.src[p.pos] == '"' {
		s, err := p.str()
		if err != nil {
			p.pos = start
			return "", false
		}
		key = s
	} else {
		key = p.ident()
	}
	if key != "" && p.pos+1 < len(p.src) && p.src[p.pos] == ':' && (p.src[p.pos+1] == ' ' || p.src[p.pos+1] == '\n') {
		p.pos++
		return key, true
	}
	p.pos = start
	return "", false
}

// mapBody reads a map after "%{": "key": value or key => value entries.
func (p *termParser) mapBody() (term, error) {
	if p.depth++; p.depth > maxDepth {
		return term{}, p.errf("nested too deeply")
	}
	defer func() { p.depth-- }()
	t := term{kind: tMap}
	for {
		p.space()
		if p.pos >= len(p.src) {
			return term{}, p.errf("unexpected end of file")
		}
		if p.src[p.pos] == '}' {
			p.pos++
			return t, nil
		}
		var k term
		if key, ok := p.keyword(); ok {
			k = term{kind: tString, s: key}
		} else {
			var err error
			if k, err = p.value(); err != nil {
				return term{}, err
			}
			p.space()
			if !p.peek("=>") {
				return term{}, p.errf("expected => after a map key")
			}
			p.pos += 2
		}
		v, err := p.value()
		if err != nil {
			return term{}, err
		}
		t.pairs = append(t.pairs, mapPair{k, v})
		p.space()
		if p.pos < len(p.src) && p.src[p.pos] == ',' {
			p.pos++
			continue
		}
		if p.pos < len(p.src) && p.src[p.pos] == '}' {
			continue
		}
		return term{}, p.errf("expected , or }")
	}
}
