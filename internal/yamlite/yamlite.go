// Package yamlite parses the strict YAML subset used by handrail rule
// packs. It is deliberately not a general YAML implementation: no anchors,
// no aliases, no tags, no multi-document streams, no flow mappings. What
// remains is the part of YAML humans can review line by line — block
// mappings, block sequences, quoted and plain scalars, flow sequences of
// scalars, and literal block scalars — parsed deterministically with a
// line number attached to every node so validation errors point at the
// exact line of the pack file.
//
// The full grammar is documented in docs/rule-packs.md.
package yamlite

import (
	"fmt"
	"strconv"
	"strings"
)

// Kind discriminates the three node shapes.
type Kind int

const (
	// Scalar is a single value: plain, quoted, or a literal block.
	Scalar Kind = iota
	// Map is a block mapping with remembered key order.
	Map
	// Seq is a block or flow sequence.
	Seq
)

func (k Kind) String() string {
	switch k {
	case Scalar:
		return "scalar"
	case Map:
		return "mapping"
	case Seq:
		return "sequence"
	}
	return "unknown"
}

// Node is one parsed value. Line is 1-based and always set, so consumers
// can report schema errors against the source file.
type Node struct {
	Kind   Kind
	Line   int
	Value  string // scalar text (unescaped)
	Quoted bool   // scalar came from a quoted or block literal form
	Keys   []string
	Fields map[string]*Node
	Items  []*Node
}

// Get returns the value for key on a mapping node, or nil.
func (n *Node) Get(key string) *Node {
	if n == nil || n.Kind != Map {
		return nil
	}
	return n.Fields[key]
}

// Str returns the scalar text, or an error naming the actual kind.
func (n *Node) Str() (string, error) {
	if n.Kind != Scalar {
		return "", fmt.Errorf("expected a scalar, got a %s", n.Kind)
	}
	return n.Value, nil
}

// Bool decodes an unquoted true/false scalar.
func (n *Node) Bool() (bool, error) {
	s, err := n.Str()
	if err != nil {
		return false, err
	}
	switch s {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("expected true or false, got %q", s)
}

// Int decodes a base-10 integer scalar.
func (n *Node) Int() (int, error) {
	s, err := n.Str()
	if err != nil {
		return 0, err
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("expected an integer, got %q", s)
	}
	return v, nil
}

// Float decodes a decimal number scalar.
func (n *Node) Float() (float64, error) {
	s, err := n.Str()
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("expected a number, got %q", s)
	}
	return v, nil
}

// StringSeq decodes a sequence of scalars into a string slice.
func (n *Node) StringSeq() ([]string, error) {
	if n.Kind != Seq {
		return nil, fmt.Errorf("expected a sequence, got a %s", n.Kind)
	}
	out := make([]string, 0, len(n.Items))
	for _, it := range n.Items {
		s, err := it.Str()
		if err != nil {
			return nil, fmt.Errorf("sequence item on line %d: %w", it.Line, err)
		}
		out = append(out, s)
	}
	return out, nil
}

// ParseError carries the 1-based line where parsing failed.
type ParseError struct {
	Line int
	Msg  string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("line %d: %s", e.Line, e.Msg)
}

// line is one raw source line with its computed indentation.
type line struct {
	num    int // 1-based source line number
	indent int // leading spaces
	text   string
	blank  bool // blank or comment-only (structurally invisible)
}

type parser struct {
	lines []line
	pos   int // next structural line index (skips blanks)
}

// Parse decodes src into a node tree. The document root must be a mapping
// or a sequence.
func Parse(src []byte) (*Node, error) {
	p, err := newParser(string(src))
	if err != nil {
		return nil, err
	}
	first := p.peek()
	if first == nil {
		return nil, &ParseError{Line: 1, Msg: "empty document"}
	}
	if first.indent != 0 {
		return nil, &ParseError{Line: first.num, Msg: "top-level content must not be indented"}
	}
	root, err := p.parseBlock(0)
	if err != nil {
		return nil, err
	}
	if rest := p.peek(); rest != nil {
		return nil, &ParseError{Line: rest.num, Msg: "content after the end of the document"}
	}
	return root, nil
}

func newParser(src string) (*parser, error) {
	rawLines := strings.Split(src, "\n")
	p := &parser{lines: make([]line, 0, len(rawLines))}
	for i, raw := range rawLines {
		raw = strings.TrimSuffix(raw, "\r")
		num := i + 1
		indent := 0
		for indent < len(raw) && raw[indent] == ' ' {
			indent++
		}
		if indent < len(raw) && raw[indent] == '\t' {
			return nil, &ParseError{Line: num, Msg: "tab in indentation (use spaces)"}
		}
		text := raw[indent:]
		blank := text == "" || strings.HasPrefix(text, "#")
		if num == 1 && text == "---" {
			blank = true // tolerate a document-start marker
		}
		p.lines = append(p.lines, line{num: num, indent: indent, text: text, blank: blank})
	}
	p.skipBlanks()
	return p, nil
}

// peek returns the next structural line without consuming it.
func (p *parser) peek() *line {
	if p.pos >= len(p.lines) {
		return nil
	}
	return &p.lines[p.pos]
}

func (p *parser) advance() {
	p.pos++
	p.skipBlanks()
}

func (p *parser) skipBlanks() {
	for p.pos < len(p.lines) && p.lines[p.pos].blank {
		p.pos++
	}
}

// parseBlock parses either a mapping or a sequence starting at the current
// line, which must sit at exactly indent.
func (p *parser) parseBlock(indent int) (*Node, error) {
	ln := p.peek()
	if isDashLine(ln.text) {
		return p.parseSeq(indent)
	}
	return p.parseMap(indent)
}

func isDashLine(text string) bool {
	return text == "-" || strings.HasPrefix(text, "- ")
}

func (p *parser) parseMap(indent int) (*Node, error) {
	node := &Node{Kind: Map, Line: p.peek().num, Fields: map[string]*Node{}}
	for {
		ln := p.peek()
		if ln == nil || ln.indent < indent {
			return node, nil
		}
		if ln.indent > indent {
			return nil, &ParseError{Line: ln.num, Msg: fmt.Sprintf("unexpected indentation (expected %d spaces, got %d)", indent, ln.indent)}
		}
		if isDashLine(ln.text) {
			return node, nil // a sibling sequence belongs to the caller
		}
		key, rest, err := splitKey(ln)
		if err != nil {
			return nil, err
		}
		if _, dup := node.Fields[key]; dup {
			return nil, &ParseError{Line: ln.num, Msg: fmt.Sprintf("duplicate key %q", key)}
		}
		var value *Node
		if rest == "" {
			value, err = p.parseNested(ln)
		} else {
			value, err = p.parseValue(rest, ln)
		}
		if err != nil {
			return nil, err
		}
		node.Keys = append(node.Keys, key)
		node.Fields[key] = value
	}
}

// parseNested handles `key:` with the value on following lines: either a
// deeper-indented block, or a sequence at the same indent as the key
// (both are idiomatic YAML for lists under a mapping key).
func (p *parser) parseNested(keyLine *line) (*Node, error) {
	p.advance()
	next := p.peek()
	if next == nil || next.indent < keyLine.indent {
		return nil, &ParseError{Line: keyLine.num, Msg: "key has no value"}
	}
	if next.indent == keyLine.indent {
		if !isDashLine(next.text) {
			return nil, &ParseError{Line: keyLine.num, Msg: "key has no value"}
		}
		return p.parseSeq(next.indent)
	}
	return p.parseBlock(next.indent)
}

func (p *parser) parseSeq(indent int) (*Node, error) {
	node := &Node{Kind: Seq, Line: p.peek().num}
	for {
		ln := p.peek()
		if ln == nil || ln.indent != indent || !isDashLine(ln.text) {
			if ln != nil && ln.indent > indent {
				return nil, &ParseError{Line: ln.num, Msg: fmt.Sprintf("unexpected indentation (expected %d spaces, got %d)", indent, ln.indent)}
			}
			return node, nil
		}
		var item *Node
		var err error
		if ln.text == "-" {
			// The item body starts on the following, deeper-indented lines.
			p.advance()
			next := p.peek()
			if next == nil || next.indent <= indent {
				return nil, &ParseError{Line: ln.num, Msg: "sequence item has no value"}
			}
			item, err = p.parseBlock(next.indent)
		} else {
			rest := ln.text[2:]
			if strings.TrimSpace(rest) == "" {
				return nil, &ParseError{Line: ln.num, Msg: "sequence item has no value"}
			}
			if k, _, kerr := splitKey(&line{num: ln.num, text: rest}); kerr == nil && k != "" {
				// `- key: value` starts an inline mapping. Rewrite this line
				// to sit two columns deeper (past the dash) and parse a map.
				p.lines[p.pos] = line{num: ln.num, indent: indent + 2, text: rest}
				item, err = p.parseMap(indent + 2)
			} else {
				item, err = p.parseValue(rest, ln)
			}
		}
		if err != nil {
			return nil, err
		}
		node.Items = append(node.Items, item)
	}
}

// splitKey splits `key: rest` or `key:`. Keys are plain (unquoted) and may
// not contain a colon; this is enough for rule-pack schemas and keeps
// key parsing unambiguous.
func splitKey(ln *line) (key, rest string, err error) {
	text := ln.text
	i := strings.Index(text, ":")
	if i < 0 {
		return "", "", &ParseError{Line: ln.num, Msg: fmt.Sprintf("expected `key: value`, got %q", text)}
	}
	if i+1 < len(text) && text[i+1] != ' ' {
		return "", "", &ParseError{Line: ln.num, Msg: "missing space after `:` in mapping"}
	}
	key = strings.TrimSpace(text[:i])
	if key == "" {
		return "", "", &ParseError{Line: ln.num, Msg: "empty mapping key"}
	}
	if !plainKey(key) {
		return "", "", &ParseError{Line: ln.num, Msg: fmt.Sprintf("invalid mapping key %q (keys must be plain words)", key)}
	}
	rest = strings.TrimSpace(text[i+1:])
	return key, rest, nil
}

// plainKey reports whether s is a plain schema-style key: a word of
// letters, digits, `_` and `-`, starting with a letter or underscore.
// Anything else (spaces, quotes, URLs) is a scalar, not a key.
func plainKey(s string) bool {
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
		case i > 0 && (r >= '0' && r <= '9' || r == '-'):
		default:
			return false
		}
	}
	return true
}

// parseValue decodes the value part of a `key: value` or `- value` line.
func (p *parser) parseValue(rest string, ln *line) (*Node, error) {
	switch {
	case rest == "|" || rest == "|-":
		return p.parseBlockScalar(ln, rest == "|-")
	case strings.HasPrefix(rest, "["):
		p.advance()
		return parseFlowSeq(rest, ln.num)
	case strings.HasPrefix(rest, "'"):
		v, trailing, err := parseSingleQuoted(rest, ln.num)
		if err != nil {
			return nil, err
		}
		if err := checkTrailing(trailing, ln.num); err != nil {
			return nil, err
		}
		p.advance()
		return &Node{Kind: Scalar, Line: ln.num, Value: v, Quoted: true}, nil
	case strings.HasPrefix(rest, "\""):
		v, trailing, err := parseDoubleQuoted(rest, ln.num)
		if err != nil {
			return nil, err
		}
		if err := checkTrailing(trailing, ln.num); err != nil {
			return nil, err
		}
		p.advance()
		return &Node{Kind: Scalar, Line: ln.num, Value: v, Quoted: true}, nil
	default:
		p.advance()
		v := stripComment(rest)
		if v == "" {
			return nil, &ParseError{Line: ln.num, Msg: "value is only a comment"}
		}
		return &Node{Kind: Scalar, Line: ln.num, Value: v, Quoted: false}, nil
	}
}

// checkTrailing allows only a comment after a closing quote.
func checkTrailing(trailing string, num int) error {
	trailing = strings.TrimSpace(trailing)
	if trailing != "" && !strings.HasPrefix(trailing, "#") {
		return &ParseError{Line: num, Msg: fmt.Sprintf("unexpected content after quoted scalar: %q", trailing)}
	}
	return nil
}

// stripComment removes a ` #`-introduced trailing comment from a plain
// scalar, per YAML: `#` starts a comment only when preceded by whitespace.
func stripComment(s string) string {
	for i := 1; i < len(s); i++ {
		if s[i] == '#' && (s[i-1] == ' ' || s[i-1] == '\t') {
			return strings.TrimSpace(s[:i])
		}
	}
	return strings.TrimSpace(s)
}

// parseBlockScalar consumes a `|` literal block: every following raw line
// deeper than the key line (plus interior blanks), verbatim.
func (p *parser) parseBlockScalar(keyLine *line, strip bool) (*Node, error) {
	p.pos++ // move past the key line without skipping blanks: they belong to the block
	blockIndent := -1
	var body []string
	for p.pos < len(p.lines) {
		ln := p.lines[p.pos]
		if strings.TrimSpace(ln.text) == "" {
			body = append(body, "")
			p.pos++
			continue
		}
		if ln.indent <= keyLine.indent {
			break
		}
		if blockIndent == -1 {
			blockIndent = ln.indent
		}
		if ln.indent < blockIndent {
			return nil, &ParseError{Line: ln.num, Msg: "block scalar line indented less than its first line"}
		}
		body = append(body, strings.Repeat(" ", ln.indent-blockIndent)+ln.text)
		p.pos++
	}
	p.skipBlanks()
	if blockIndent == -1 {
		return nil, &ParseError{Line: keyLine.num, Msg: "block scalar has no content"}
	}
	// Drop trailing blank lines, then terminate with \n unless `|-`.
	for len(body) > 0 && body[len(body)-1] == "" {
		body = body[:len(body)-1]
	}
	value := strings.Join(body, "\n")
	if !strip {
		value += "\n"
	}
	return &Node{Kind: Scalar, Line: keyLine.num, Value: value, Quoted: true}, nil
}

// parseFlowSeq decodes `[a, 'b', "c"]` into a sequence of scalars.
func parseFlowSeq(s string, num int) (*Node, error) {
	close := flowClose(s)
	if close < 0 {
		return nil, &ParseError{Line: num, Msg: "flow sequence is not closed with `]`"}
	}
	if err := checkTrailing(s[close+1:], num); err != nil {
		return nil, err
	}
	inner := strings.TrimSpace(s[1:close])
	node := &Node{Kind: Seq, Line: num}
	rest := strings.TrimSpace(inner)
	for rest != "" {
		var item *Node
		var err error
		switch {
		case strings.HasPrefix(rest, "'"):
			var v string
			v, rest, err = parseSingleQuoted(rest, num)
			if err != nil {
				return nil, err
			}
			item = &Node{Kind: Scalar, Line: num, Value: v, Quoted: true}
			rest = strings.TrimSpace(rest)
			if rest != "" {
				if !strings.HasPrefix(rest, ",") {
					return nil, &ParseError{Line: num, Msg: "expected `,` between flow sequence items"}
				}
				rest = strings.TrimSpace(rest[1:])
			}
		case strings.HasPrefix(rest, "\""):
			var v string
			v, rest, err = parseDoubleQuoted(rest, num)
			if err != nil {
				return nil, err
			}
			item = &Node{Kind: Scalar, Line: num, Value: v, Quoted: true}
			rest = strings.TrimSpace(rest)
			if rest != "" {
				if !strings.HasPrefix(rest, ",") {
					return nil, &ParseError{Line: num, Msg: "expected `,` between flow sequence items"}
				}
				rest = strings.TrimSpace(rest[1:])
			}
		default:
			cut := strings.Index(rest, ",")
			var raw string
			if cut < 0 {
				raw, rest = rest, ""
			} else {
				raw, rest = rest[:cut], strings.TrimSpace(rest[cut+1:])
			}
			raw = strings.TrimSpace(raw)
			if raw == "" {
				return nil, &ParseError{Line: num, Msg: "empty item in flow sequence"}
			}
			item = &Node{Kind: Scalar, Line: num, Value: raw, Quoted: false}
		}
		node.Items = append(node.Items, item)
	}
	return node, nil
}

// flowClose returns the index of the `]` that closes a flow sequence
// starting at s[0] == '[', skipping quoted regions, or -1.
func flowClose(s string) int {
	inSingle, inDouble := false, false
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
			}
		case inDouble:
			if c == '\\' {
				i++
			} else if c == '"' {
				inDouble = false
			}
		case c == '\'':
			inSingle = true
		case c == '"':
			inDouble = true
		case c == ']':
			return i
		}
	}
	return -1
}

// parseSingleQuoted decodes a leading 'single quoted' scalar; ” escapes a
// quote. Returns the value and the unconsumed remainder of the line.
func parseSingleQuoted(s string, num int) (value, rest string, err error) {
	var b strings.Builder
	i := 1
	for i < len(s) {
		if s[i] == '\'' {
			if i+1 < len(s) && s[i+1] == '\'' {
				b.WriteByte('\'')
				i += 2
				continue
			}
			return b.String(), s[i+1:], nil
		}
		b.WriteByte(s[i])
		i++
	}
	return "", "", &ParseError{Line: num, Msg: "unterminated single-quoted scalar"}
}

// parseDoubleQuoted decodes a leading "double quoted" scalar with the
// escape set \\ \" \n \t \r \0 and \uXXXX.
func parseDoubleQuoted(s string, num int) (value, rest string, err error) {
	var b strings.Builder
	i := 1
	for i < len(s) {
		c := s[i]
		switch c {
		case '"':
			return b.String(), s[i+1:], nil
		case '\\':
			if i+1 >= len(s) {
				return "", "", &ParseError{Line: num, Msg: "dangling backslash in double-quoted scalar"}
			}
			i++
			switch s[i] {
			case '\\':
				b.WriteByte('\\')
			case '"':
				b.WriteByte('"')
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '0':
				b.WriteByte(0)
			case 'u':
				if i+4 >= len(s) {
					return "", "", &ParseError{Line: num, Msg: "truncated \\u escape"}
				}
				code, perr := strconv.ParseUint(s[i+1:i+5], 16, 32)
				if perr != nil {
					return "", "", &ParseError{Line: num, Msg: fmt.Sprintf("invalid \\u escape %q", s[i+1:i+5])}
				}
				b.WriteRune(rune(code))
				i += 4
			default:
				return "", "", &ParseError{Line: num, Msg: fmt.Sprintf("unsupported escape \\%c", s[i])}
			}
			i++
		default:
			b.WriteByte(c)
			i++
		}
	}
	return "", "", &ParseError{Line: num, Msg: "unterminated double-quoted scalar"}
}
