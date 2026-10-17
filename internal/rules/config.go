package rules

import (
	"fmt"
	"strings"

	"github.com/ErenOzgu/asterisk-conf-lint/internal/conf"
)

func init() {
	register(&Rule{
		ID: "CFG-000", Severity: Low, Applies: "all files",
		Title: "Line the parser does not understand",
		Why:   "Asterisk skips or rejects lines it cannot read, usually after logging a warning at startup. The option you meant to set is not set.",
		Fix:   "Fix the syntax: key = value, [section], or a #include / #exec line.",
		check: checkBadLines,
	})
	register(&Rule{
		ID: "CFG-001", Severity: High, Applies: "all files",
		Title: "#exec directive in a configuration file",
		Why:   "#exec runs a command every time the file is loaded. It is switched off unless asterisk.conf sets execincludes = yes, and then whoever can edit the file runs code as the Asterisk user.",
		Fix:   "Generate the file at deploy time instead, and keep execincludes off.",
		check: checkExec,
	})
	register(&Rule{
		ID: "CFG-002", Severity: Medium, Applies: "asterisk.conf",
		Title: "execincludes is enabled",
		Why:   "With execincludes = yes every configuration file may run commands through #exec.",
		Fix:   "Remove execincludes = yes unless a file really needs #exec.",
		check: checkExecIncludes,
	})
	register(&Rule{
		ID: "CFG-003", Severity: Medium, Applies: "all files (needs --check-perms)",
		Title: "Configuration file with secrets is readable by everyone",
		Why:   "Passwords sit in plain text in these files. World-readable means every local account can read them.",
		Fix:   "chown asterisk:asterisk and chmod 640 (or 600) the file.",
		check: checkPerms,
	})
}

// checkBadLines reports the first unreadable line of each file. Asterisk
// stops at the first one ("parse error: No category context for line N"), so
// the lines after it say little.
func checkBadLines(c *Context) {
	for _, f := range c.Files {
		if len(f.Bad) == 0 {
			continue
		}
		b := f.Bad[0]
		more := ""
		if n := len(f.Bad) - 1; n > 0 {
			more = fmt.Sprintf(" (and %d more unreadable lines)", n)
		}
		c.Add(Low, f, b.Line, "cannot parse: %s%s", strings.TrimSpace(b.Text), more)
	}
}

func execIncludesOn(c *Context) bool {
	for _, f := range filesNamed(c, "asterisk.conf") {
		for _, e := range sectionsOf(c, f) {
			if o, ok := e.Get("execincludes"); ok && truthy(o.Value) {
				return true
			}
		}
	}
	return false
}

func checkExec(c *Context) {
	on := execIncludesOn(c)
	for _, f := range c.Files {
		for _, d := range f.Directives {
			if d.Name != "exec" {
				continue
			}
			if on {
				c.Add(High, f, d.Line, "#exec %s, and asterisk.conf enables execincludes", d.Arg)
			} else {
				c.Add(Medium, f, d.Line, "#exec %s (only runs if execincludes = yes)", d.Arg)
			}
		}
	}
}

func checkExecIncludes(c *Context) {
	for _, f := range filesNamed(c, "asterisk.conf") {
		for _, e := range sectionsOf(c, f) {
			if o, ok := e.Get("execincludes"); ok && truthy(o.Value) {
				c.Add(Medium, f, o.Line, "execincludes = %s", o.Value)
			}
		}
	}
}

var secretKeys = map[string]bool{"secret": true, "md5secret": true, "password": true, "md5_cred": true}

func checkPerms(c *Context) {
	if !c.Opts.CheckPerms {
		return
	}
	for _, f := range c.Files {
		if !f.HasMode || f.Mode&0o004 == 0 {
			continue
		}
		line := 0
		visit := func(opts []conf.Option) {
			for _, o := range opts {
				if line == 0 && secretKeys[strings.ToLower(o.Key)] && strings.TrimSpace(o.Value) != "" {
					line = o.Line
				}
			}
		}
		visit(f.Preamble)
		for _, s := range f.Sections {
			visit(s.Options)
		}
		if line > 0 {
			c.Add(Medium, f, line, "file mode %04o: every local user can read the secrets in it", f.Mode.Perm())
		}
	}
}
