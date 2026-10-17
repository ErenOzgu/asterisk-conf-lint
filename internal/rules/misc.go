package rules

import (
	"path/filepath"
	"strings"

	"github.com/ErenOzgu/asterisk-conf-lint/internal/conf"
)

func init() {
	register(&Rule{
		ID: "RTP-001", Severity: Medium, Applies: "rtp.conf",
		Title: "strictrtp is switched off",
		Why:   "Strict RTP drops media from addresses a call has not negotiated. Without it, RTP injection and call hijacking get easier.",
		Fix:   "Remove strictrtp = no (the default is yes) or set strictrtp = yes.",
		check: checkStrictRTP,
	})
	register(&Rule{
		ID: "HTTP-001", Severity: Medium, Applies: "http.conf",
		Title: "Built-in HTTP server on a non-loopback address without TLS",
		Why:   "The HTTP server carries ARI and the AMI-over-HTTP interface. Plain HTTP on a reachable address sends passwords in the clear.",
		Fix:   "Bind to 127.0.0.1 behind a reverse proxy, or enable tlsenable with a certificate.",
		check: checkHTTP,
	})
	register(&Rule{
		ID: "ARI-001", Severity: Critical, Applies: "ari.conf",
		Title: "ARI user with a weak password",
		Why:   "ARI can place calls and control channels. The password is the only barrier.",
		Fix:   "Use a random password of at least 16 characters.",
		check: checkARIPassword,
	})
	register(&Rule{
		ID: "ARI-002", Severity: Low, Applies: "ari.conf",
		Title: "ARI passwords stored in plain text",
		Why:   "password_format defaults to plain: anyone who can read ari.conf learns every password.",
		Fix:   "Set password_format = crypt and store crypt(3) hashes (mkpasswd -m sha-512).",
		check: checkARIFormat,
	})
	register(&Rule{
		ID: "MOD-001", Severity: Low, Applies: "modules.conf",
		Title: "Legacy channel drivers are loaded but not configured",
		Why:   "Every loaded protocol is code that listens and parses network input. Unused drivers only add attack surface.",
		Fix:   "Add noload = chan_sip.so (and the others listed) to [modules].",
		check: checkLegacyModules,
	})
}

func filesNamed(c *Context, name string) []*conf.File {
	var out []*conf.File
	for _, f := range c.Files {
		if base(f) == name {
			out = append(out, f)
		}
	}
	return out
}

func checkStrictRTP(c *Context) {
	for _, f := range filesNamed(c, "rtp.conf") {
		for _, e := range sectionsOf(c, f) {
			if o, ok := e.Get("strictrtp"); ok && falsy(o.Value) {
				c.Add(Medium, f, o.Line, "strictrtp = %s", o.Value)
			}
		}
	}
}

func checkHTTP(c *Context) {
	for _, f := range filesNamed(c, "http.conf") {
		for _, e := range sectionsOf(c, f) {
			if en, ok := e.Get("enabled"); !ok || !truthy(en.Value) {
				continue
			}
			bind, ok := e.Get("bindaddr")
			if !ok || isLoopback(bind.Value) {
				continue
			}
			if tls, ok := e.Get("tlsenable"); ok && truthy(tls.Value) {
				continue
			}
			c.Add(Medium, f, bind.Line, "the HTTP server listens on %s without TLS", bind.Value)
		}
	}
}

func ariUsers(c *Context) []conf.Effective {
	var out []conf.Effective
	for _, f := range filesNamed(c, "ari.conf") {
		for _, e := range sectionsOf(c, f) {
			if !strings.EqualFold(e.Section.Name, "general") {
				out = append(out, e)
			}
		}
	}
	return out
}

func checkARIPassword(c *Context) {
	for _, e := range ariUsers(c) {
		o, ok := e.Get("password")
		f := fileOf(c, e.Section)
		if !ok || f == nil {
			continue
		}
		if reason, sev := weakSecret(o.Value, e.Section.Name); reason != "" {
			c.Add(sev, f, o.Line, "ARI user %q: the password %s", e.Section.Name, reason)
		}
	}
}

func checkARIFormat(c *Context) {
	for _, f := range filesNamed(c, "ari.conf") {
		var general *conf.Effective
		for _, e := range sectionsOf(c, f) {
			if strings.EqualFold(e.Section.Name, "general") {
				e := e
				general = &e
			}
		}
		format := "plain"
		line := firstLine(f)
		if general != nil {
			if o, ok := general.Get("password_format"); ok {
				format, line = strings.ToLower(o.Value), o.Line
			}
		}
		hasPassword := false
		for _, e := range ariUsers(c) {
			if fileOf(c, e.Section) == f {
				if _, ok := e.Get("password"); ok {
					hasPassword = true
				}
			}
		}
		if hasPassword && format == "plain" {
			c.Add(Low, f, line, "password_format is plain (the default)")
		}
	}
}

var legacyDrivers = []struct{ module, config string }{
	{"chan_sip.so", "sip.conf"},
	{"chan_iax2.so", "iax.conf"},
	{"chan_skinny.so", "skinny.conf"},
	{"chan_mgcp.so", "mgcp.conf"},
	{"chan_unistim.so", "unistim.conf"},
}

func checkLegacyModules(c *Context) {
	for _, f := range filesNamed(c, "modules.conf") {
		for _, e := range sectionsOf(c, f) {
			if !strings.EqualFold(e.Section.Name, "modules") {
				continue
			}
			auto, ok := e.Get("autoload")
			if !ok || !truthy(auto.Value) {
				continue
			}
			noload := map[string]bool{}
			for _, o := range e.All("noload") {
				noload[strings.TrimSuffix(strings.ToLower(filepath.Base(o.Value)), ".so")] = true
			}
			var loaded []string
			for _, d := range legacyDrivers {
				if noload[strings.TrimSuffix(d.module, ".so")] || len(filesNamed(c, d.config)) > 0 {
					continue
				}
				loaded = append(loaded, d.module)
			}
			if len(loaded) > 0 {
				c.Add(Low, f, auto.Line, "autoload = yes and no noload for %s", strings.Join(loaded, ", "))
			}
		}
	}
}
