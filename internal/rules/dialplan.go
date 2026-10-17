package rules

import (
	"regexp"
	"strings"

	"github.com/ErenOzgu/asterisk-conf-lint/internal/conf"
)

func init() {
	register(&Rule{
		ID: "DIAL-001", Severity: Medium, Applies: "extensions*.conf",
		Title: "Catch-all pattern dials whatever it is given",
		Why:   "A pattern like _X. that runs Dial(PJSIP/${EXTEN}@trunk) lets any caller who reaches the context dial any number, premium-rate ones included: toll fraud.",
		Fix:   "Match only the number ranges you allow, and add Authenticate(), a blocklist check or GROUP() limits before the Dial.",
		check: checkTollFraud,
	})
	register(&Rule{
		ID: "DIAL-002", Severity: High, Applies: "extensions*.conf",
		Title: "System() or SHELL() built from channel variables",
		Why:   "A caller ID or dialled number reaches the shell: ${CALLERID(num)} can contain shell syntax, and the command runs as the Asterisk user.",
		Fix:   "Do the work with an AGI/ARI program, or validate the value first (REGEX() or FILTER()).",
		check: checkShell,
	})
}

var (
	broadPatternRe = regexp.MustCompile(`^_[+0-9XZN]{0,3}[.!]$`)
	dialTechRe     = regexp.MustCompile(`(?i)^dial\(\s*(pjsip|sip|iax2|dahdi)/`)
	guardRe        = regexp.MustCompile(`(?i)^(authenticate|gotoif|gosubif|execif|gotoiftime)\(|group\(`)
	shellRe        = regexp.MustCompile(`(?i)^(system|trysystem|shell)\(([^)]*)\)`)
)

// dialplanLines walks a file's extension lines in order and hands each one
// to fn with the exten pattern it belongs to ("same =>" lines inherit it).
func dialplanLines(f *conf.File, fn func(sec *conf.Section, pattern string, opt conf.Option, app string)) {
	for _, s := range f.Sections {
		pattern := ""
		for _, o := range s.Options {
			var rest string
			switch strings.ToLower(o.Key) {
			case "exten":
				parts := strings.SplitN(o.Value, ",", 3)
				if len(parts) < 3 {
					continue
				}
				pattern = strings.TrimSpace(parts[0])
				rest = parts[2]
			case "same":
				parts := strings.SplitN(o.Value, ",", 2)
				if len(parts) < 2 {
					continue
				}
				rest = parts[1]
			default:
				continue
			}
			fn(s, pattern, o, strings.TrimSpace(rest))
		}
	}
}

func checkTollFraud(c *Context) {
	for _, f := range c.Files {
		if !isDialplan(f) {
			continue
		}
		guarded := map[string]bool{}
		dialplanLines(f, func(s *conf.Section, pattern string, o conf.Option, app string) {
			key := s.Name + "\x00" + pattern
			if guardRe.MatchString(app) {
				guarded[key] = true
			}
			if !broadPatternRe.MatchString(pattern) || guarded[key] {
				return
			}
			if dialTechRe.MatchString(app) && strings.Contains(strings.ToUpper(app), "${EXTEN") {
				c.Add(Medium, f, o.Line, "context [%s]: pattern %s dials ${EXTEN} straight to a trunk with no check before it", s.Name, pattern)
			}
		})
	}
}

func checkShell(c *Context) {
	for _, f := range c.Files {
		if !isDialplan(f) {
			continue
		}
		dialplanLines(f, func(s *conf.Section, pattern string, o conf.Option, app string) {
			if m := shellRe.FindStringSubmatch(app); m != nil && strings.Contains(m[2], "${") {
				c.Add(High, f, o.Line, "context [%s]: %s() receives a channel variable", s.Name, strings.TrimSpace(strings.SplitN(app, "(", 2)[0]))
				return
			}
			if strings.Contains(strings.ToUpper(app), "${SHELL(") {
				inner := app[strings.Index(strings.ToUpper(app), "${SHELL(")+8:]
				if strings.Contains(inner, "${") {
					c.Add(High, f, o.Line, "context [%s]: SHELL() receives a channel variable", s.Name)
				}
			}
		})
	}
}
