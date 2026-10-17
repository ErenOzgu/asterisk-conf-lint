// Package rules holds the checks. Each rule looks at parsed Asterisk
// configuration files and reports findings with a severity and a place.
package rules

import (
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ErenOzgu/asterisk-conf-lint/internal/conf"
)

// Severity orders findings from Info to Critical.
type Severity int

// Severities, lowest first.
const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string { return severityNames[s] }

// ParseSeverity turns "high" into High.
func ParseSeverity(s string) (Severity, bool) {
	for i, n := range severityNames {
		if strings.EqualFold(n, s) {
			return Severity(i), true
		}
	}
	return Info, false
}

// Finding is one problem in one place.
type Finding struct {
	RuleID   string
	Severity Severity
	File     string
	Line     int
	Message  string
}

// Rule describes a check. Severity is the highest level the rule reports;
// some rules lower it depending on the case.
type Rule struct {
	ID       string
	Title    string
	Severity Severity
	Applies  string // files the rule looks at, for the docs
	Why      string
	Fix      string
	check    func(*Context)
}

// Options are switches that change what is checked.
type Options struct {
	// CheckPerms enables CFG-003 (world-readable files that hold secrets).
	CheckPerms bool
}

// Context is what a rule sees, and how it reports.
type Context struct {
	Files []*conf.File
	Index *conf.Index
	Opts  Options

	rule     *Rule
	findings []Finding
}

// Add reports a finding for the rule being run.
func (c *Context) Add(sev Severity, f *conf.File, line int, format string, args ...any) {
	c.findings = append(c.findings, Finding{
		RuleID: c.rule.ID, Severity: sev, File: f.Path, Line: line,
		Message: fmt.Sprintf(format, args...),
	})
}

// Run executes every rule not listed in disabled.
func Run(files []*conf.File, opts Options, disabled map[string]bool) []Finding {
	c := &Context{Files: files, Index: conf.NewIndex(files), Opts: opts}
	for _, r := range All() {
		if disabled[r.ID] {
			continue
		}
		c.rule = r
		r.check(c)
	}
	sort.SliceStable(c.findings, func(i, j int) bool {
		a, b := c.findings[i], c.findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.RuleID < b.RuleID
	})
	return c.findings
}

var registry []*Rule

func register(r *Rule) { registry = append(registry, r) }

// All returns the rules sorted by ID.
func All() []*Rule {
	out := append([]*Rule(nil), registry...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Lookup returns the rule with the given ID.
func Lookup(id string) (*Rule, bool) {
	for _, r := range registry {
		if r.ID == id {
			return r, true
		}
	}
	return nil, false
}

// ---- helpers shared by the rules ----

func base(f *conf.File) string { return strings.ToLower(filepath.Base(f.Path)) }

func parentDir(f *conf.File) string {
	return strings.ToLower(filepath.Base(filepath.Dir(f.Path)))
}

func isManager(f *conf.File) bool { return base(f) == "manager.conf" || parentDir(f) == "manager.d" }

func isPJSIP(f *conf.File) bool {
	b := base(f)
	return strings.HasPrefix(b, "pjsip") && strings.HasSuffix(b, ".conf") || parentDir(f) == "pjsip.d"
}

func isSIP(f *conf.File) bool { return base(f) == "sip.conf" || parentDir(f) == "sip.d" }

func isDialplan(f *conf.File) bool {
	b := base(f)
	return strings.HasPrefix(b, "extensions") && strings.HasSuffix(b, ".conf")
}

// truthy and falsy follow Asterisk's ast_true / ast_false.
func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "true", "y", "t", "1", "on":
		return true
	}
	return false
}

func falsy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "no", "false", "n", "f", "0", "off":
		return true
	}
	return false
}

// isAnyNetwork reports whether an ACL entry covers every address.
func isAnyNetwork(v string) bool {
	v = strings.TrimSpace(v)
	switch v {
	case "0.0.0.0/0", "0.0.0.0/0.0.0.0", "::/0", "::/0.0.0.0", "0/0":
		return true
	}
	return false
}

func hostOnly(addr string) string {
	addr = strings.TrimSpace(addr)
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(addr, "[]")
}

func isLoopback(addr string) bool {
	h := hostOnly(addr)
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func isUnspecified(addr string) bool {
	h := hostOnly(addr)
	if h == "" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsUnspecified()
}

// splitList splits "a, b,c" into trimmed non-empty items.
func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// firstLine is a sensible place to point at for a finding about a file as a whole.
func firstLine(f *conf.File) int {
	if len(f.Sections) > 0 {
		return f.Sections[0].Line
	}
	return 1
}

// sectionsOf yields the non-template sections of f with their effective options.
func sectionsOf(c *Context, f *conf.File) []conf.Effective {
	var out []conf.Effective
	for _, s := range f.Sections {
		if s.IsTemplate {
			continue
		}
		out = append(out, c.Index.Resolve(s))
	}
	return out
}

// optLine returns the line of the option if present, else the section line.
func optLine(e conf.Effective, key string) int {
	if o, ok := e.Get(key); ok && o.Line > 0 {
		return o.Line
	}
	return e.Section.Line
}

type peer struct {
	f *conf.File
	e conf.Effective
}
