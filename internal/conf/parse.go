// Package conf parses Asterisk's configuration file format: sections,
// templates, repeated keys, "=" and "=>" assignments, ";" comments, ";-- --;"
// block comments and the "#include" / "#exec" directives.
package conf

import (
	"bufio"
	"io"
	"io/fs"
	"regexp"
	"strings"
)

// Option is one "key = value" line.
type Option struct {
	Key   string
	Value string
	Op    string // "=" or "=>"
	Line  int
}

// Section is one "[name]" block. Templates lists the sections it inherits
// from; IsTemplate is true for "[name](!)".
type Section struct {
	Name       string
	Templates  []string
	IsTemplate bool
	Line       int
	Options    []Option
}

// Directive is a "#include", "#tryinclude" or "#exec" line.
type Directive struct {
	Name string // include, tryinclude, exec
	Arg  string
	Line int
}

// BadLine is a line the parser could not make sense of.
type BadLine struct {
	Line int
	Text string
}

// Ignore is a "; lint-ignore: RULE ..." comment.
type Ignore struct {
	Line  int
	Rules []string // upper-case rule IDs, or "*"
	File  bool     // lint-ignore-file: applies to the whole file
}

// File is a parsed configuration file.
type File struct {
	Path       string
	Sections   []*Section
	Directives []Directive
	Bad        []BadLine
	Ignores    []Ignore
	// Preamble holds options that appear before the first section header.
	Preamble []Option
	// Mode is the file's permission bits when the file came from disk.
	Mode    fs.FileMode
	HasMode bool
}

var (
	sectionRe = regexp.MustCompile(`^\[([^\]]*)\]\s*(?:\(([^)]*)\))?\s*$`)
	ignoreRe  = regexp.MustCompile(`(?i)\blint-ignore(-file)?\s*:\s*([A-Za-z0-9_*,\s-]+)`)
)

// Parse reads a configuration file. It never fails on bad syntax: lines it
// cannot read are collected in File.Bad so one typo does not hide the rest.
func Parse(path string, r io.Reader) (*File, error) {
	f := &File{Path: path}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var cur *Section
	inBlock := false
	n := 0
	for sc.Scan() {
		n++
		raw := strings.TrimRight(sc.Text(), "\r")
		line := raw

		if inBlock {
			if i := strings.Index(line, "--;"); i >= 0 {
				inBlock = false
				line = line[i+3:]
			} else {
				continue
			}
		}
		line, comment, opened := splitComment(line)
		if opened {
			inBlock = true
		}
		if m := ignoreRe.FindStringSubmatch(comment); m != nil {
			f.Ignores = append(f.Ignores, Ignore{Line: n, Rules: splitRules(m[2]), File: m[1] != ""})
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "#") {
			if d, ok := parseDirective(line, n); ok {
				f.Directives = append(f.Directives, d)
			} else {
				f.Bad = append(f.Bad, BadLine{n, raw})
			}
			continue
		}
		if strings.HasPrefix(line, "[") {
			m := sectionRe.FindStringSubmatch(line)
			if m == nil {
				f.Bad = append(f.Bad, BadLine{n, raw})
				continue
			}
			cur = &Section{Name: strings.TrimSpace(m[1]), Line: n}
			for _, t := range strings.Split(m[2], ",") {
				t = strings.TrimSpace(t)
				switch t {
				case "":
				case "!":
					cur.IsTemplate = true
				default:
					cur.Templates = append(cur.Templates, t)
				}
			}
			f.Sections = append(f.Sections, cur)
			continue
		}
		key, op, val, ok := splitOption(line)
		if !ok {
			f.Bad = append(f.Bad, BadLine{n, raw})
			continue
		}
		o := Option{Key: key, Value: val, Op: op, Line: n}
		if cur == nil {
			f.Preamble = append(f.Preamble, o)
		} else {
			cur.Options = append(cur.Options, o)
		}
	}
	return f, sc.Err()
}

// splitComment cuts a trailing ";" comment (an escaped "\;" is kept) and
// reports whether a ";--" block comment starts on this line and does not end
// on it. A ";--" ... "--;" pair on one line is removed.
func splitComment(line string) (code, comment string, openBlock bool) {
	var sb strings.Builder
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\\' && i+1 < len(line) && line[i+1] == ';' {
			sb.WriteByte(';')
			i++
			continue
		}
		if c == ';' {
			rest := line[i:]
			if strings.HasPrefix(rest, ";--") {
				if j := strings.Index(rest[3:], "--;"); j >= 0 {
					// closed on the same line: drop it and keep scanning
					i += 3 + j + 2
					continue
				}
				return sb.String(), rest, true
			}
			return sb.String(), rest, false
		}
		sb.WriteByte(c)
	}
	return sb.String(), "", false
}

func splitRules(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		p = strings.ToUpper(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		// The first non-ID word ends the list: "AMI-003 test box" ignores AMI-003 only.
		if p != "*" && !ruleIDRe.MatchString(p) {
			break
		}
		out = append(out, p)
	}
	return out
}

var ruleIDRe = regexp.MustCompile(`^[A-Z]+-[0-9]+$`)

func parseDirective(line string, n int) (Directive, bool) {
	body := strings.TrimPrefix(line, "#")
	name, arg, _ := strings.Cut(body, " ")
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "include", "tryinclude", "exec":
		return Directive{Name: name, Arg: strings.Trim(strings.TrimSpace(arg), `"<>`), Line: n}, true
	}
	return Directive{}, false
}

// splitOption splits "key = value" or "key => value"; the value keeps
// everything after the operator.
func splitOption(line string) (key, op, val string, ok bool) {
	i := strings.IndexByte(line, '=')
	if i <= 0 {
		return "", "", "", false
	}
	// Asterisk splits at the first "=" and trims; keys may contain spaces
	// (cli_aliases.conf has "show channeltypes = core show channeltypes").
	key = strings.TrimSpace(line[:i])
	if key == "" {
		return "", "", "", false
	}
	rest := line[i+1:]
	op = "="
	if strings.HasPrefix(rest, ">") {
		op = "=>"
		rest = rest[1:]
	}
	return key, op, strings.TrimSpace(rest), true
}
