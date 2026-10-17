package rules

import (
	"strings"

	"github.com/ErenOzgu/asterisk-conf-lint/internal/conf"
)

func init() {
	register(&Rule{
		ID: "AMI-001", Severity: High, Applies: "manager.conf",
		Title: "AMI listens on a non-loopback address",
		Why:   "The Manager Interface is plain text and can place calls and run commands. Reachable from the network, it invites password guessing.",
		Fix:   "Set bindaddr = 127.0.0.1, or a private address behind a firewall, and use TLS for anything that leaves the host.",
		check: checkAMIBind,
	})
	register(&Rule{
		ID: "AMI-002", Severity: High, Applies: "manager.conf",
		Title: "AMI user without a working ACL",
		Why:   "Asterisk's deny/permit lists allow everything that no rule mentions. A permit line without a catch-all deny restricts nothing.",
		Fix:   "Put deny = 0.0.0.0/0.0.0.0 first, then permit = 127.0.0.1/255.255.255.255 (or the addresses that really need access).",
		check: checkAMIACL,
	})
	register(&Rule{
		ID: "AMI-003", Severity: Critical, Applies: "manager.conf",
		Title: "AMI user with a weak secret",
		Why:   "AMI logins are tried by bots all day. Short, common or empty secrets fall within minutes.",
		Fix:   "Generate a random secret of at least 16 characters, for example with openssl rand -base64 24.",
		check: checkAMISecret,
	})
	register(&Rule{
		ID: "AMI-004", Severity: High, Applies: "manager.conf",
		Title: "AMI user with powerful write permissions",
		Why:   "The write classes decide which actions a login may run. all, command and originate allow shell-like commands and placing calls; system allows reload and shutdown.",
		Fix:   "Give each user only the classes its tools need, and note why a monitoring user needs system (CoreStatus, for one).",
		check: checkAMIWrite,
	})
}

func managerUsers(c *Context) []conf.Effective {
	var out []conf.Effective
	for _, f := range c.Files {
		if !isManager(f) {
			continue
		}
		for _, e := range sectionsOf(c, f) {
			if strings.EqualFold(e.Section.Name, "general") {
				continue
			}
			out = append(out, e)
		}
	}
	return out
}

func fileOf(c *Context, s *conf.Section) *conf.File {
	for _, f := range c.Files {
		for _, x := range f.Sections {
			if x == s {
				return f
			}
		}
	}
	return nil
}

func checkAMIBind(c *Context) {
	for _, f := range c.Files {
		if !isManager(f) {
			continue
		}
		for _, e := range sectionsOf(c, f) {
			if !strings.EqualFold(e.Section.Name, "general") {
				continue
			}
			if en, ok := e.Get("enabled"); !ok || !truthy(en.Value) {
				continue // disabled (the default): nothing listens
			}
			bind, ok := e.Get("bindaddr")
			switch {
			case !ok:
				c.Add(High, f, optLine(e, "enabled"), "AMI is enabled without bindaddr, so it listens on all interfaces (default 0.0.0.0)")
			case isUnspecified(bind.Value):
				c.Add(High, f, bind.Line, "AMI listens on all interfaces (bindaddr = %s)", bind.Value)
			case !isLoopback(bind.Value):
				c.Add(Medium, f, bind.Line, "AMI listens on %s, which is not a loopback address", bind.Value)
			}
		}
	}
}

func checkAMIACL(c *Context) {
	for _, e := range managerUsers(c) {
		f := fileOf(c, e.Section)
		if f == nil {
			continue
		}
		denies, permits := e.All("deny"), e.All("permit")
		denyAll := false
		for _, d := range denies {
			if isAnyNetwork(d.Value) {
				denyAll = true
			}
		}
		for _, p := range permits {
			if isAnyNetwork(p.Value) {
				c.Add(High, f, p.Line, "user %q permits every address (%s)", e.Section.Name, p.Value)
			}
		}
		switch {
		case len(denies) == 0 && len(permits) == 0:
			c.Add(High, f, e.Section.Line, "user %q has no deny/permit lines: any host that reaches the port may try to log in", e.Section.Name)
		case !denyAll:
			c.Add(High, f, optLine(e, "permit"), "user %q has permit lines but no deny = 0.0.0.0/0.0.0.0, so every other address is still allowed", e.Section.Name)
		}
	}
}

func checkAMISecret(c *Context) {
	for _, e := range managerUsers(c) {
		f := fileOf(c, e.Section)
		o, ok := e.Get("secret")
		if f == nil || !ok {
			continue
		}
		if reason, sev := weakSecret(o.Value, e.Section.Name); reason != "" {
			c.Add(sev, f, o.Line, "user %q: the secret %s", e.Section.Name, reason)
		}
	}
}

func checkAMIWrite(c *Context) {
	for _, e := range managerUsers(c) {
		f := fileOf(c, e.Section)
		o, ok := e.Get("write")
		if f == nil || !ok {
			continue
		}
		var all, strong, system []string
		for _, class := range splitList(o.Value) {
			switch strings.ToLower(class) {
			case "all":
				all = append(all, class)
			case "command", "originate":
				strong = append(strong, class)
			case "system":
				system = append(system, class)
			}
		}
		switch {
		case len(all) > 0:
			c.Add(High, f, o.Line, "user %q has write = all: every AMI action is allowed", e.Section.Name)
		case len(strong) > 0:
			c.Add(Medium, f, o.Line, "user %q may use the %s class (%s)", e.Section.Name, strings.Join(strong, ", "), "runs CLI commands or places calls")
		case len(system) > 0:
			c.Add(Low, f, o.Line, "user %q has the system class, which also allows reload and shutdown; check that the tool needs it", e.Section.Name)
		}
	}
}
