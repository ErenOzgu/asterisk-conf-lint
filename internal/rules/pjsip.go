package rules

import (
	"strings"

	"github.com/ErenOzgu/asterisk-conf-lint/internal/conf"
)

func init() {
	register(&Rule{
		ID: "PJS-001", Severity: High, Applies: "pjsip.conf",
		Title: "An endpoint named anonymous accepts unidentified callers",
		Why:   "Asterisk routes calls from unknown senders to the endpoint called anonymous. Its context then decides what strangers can dial.",
		Fix:   "Remove the anonymous endpoint, or point it at a context that only offers harmless things (a rejection message).",
		check: checkPJSIPAnonymous,
	})
	register(&Rule{
		ID: "PJS-002", Severity: High, Applies: "pjsip.conf",
		Title: "Endpoint without authentication",
		Why:   "Without auth, an INVITE that names the endpoint's user is accepted without a password challenge, unless the endpoint is matched by IP only.",
		Fix:   "Add auth = <auth section>, or set identify_by = ip and add a type = identify section with the sender's address.",
		check: checkPJSIPNoAuth,
	})
	register(&Rule{
		ID: "PJS-003", Severity: Critical, Applies: "pjsip.conf",
		Title: "auth section with a weak password",
		Why:   "SIP passwords are guessed by bots that scan the internet for open ports. Short or common passwords are found quickly.",
		Fix:   "Use a random password of at least 16 characters. SIP phones store it once, so length costs nothing.",
		check: checkPJSIPPassword,
	})
	register(&Rule{
		ID: "PJS-004", Severity: High, Applies: "pjsip.conf",
		Title: "identify section that matches every address",
		Why:   "An identify section turns a source address into a trusted endpoint. Matching 0.0.0.0/0 trusts the whole internet.",
		Fix:   "List the provider's addresses or networks in match =, one entry each.",
		check: checkPJSIPIdentify,
	})
	register(&Rule{
		ID: "PJS-005", Severity: High, Applies: "pjsip.conf",
		Title: "Transport allows an outdated TLS or SSL version",
		Why:   "SSLv2, SSLv3, TLS 1.0 and TLS 1.1 have known weaknesses and are refused by current clients.",
		Fix:   "Set method = tlsv1_2 (or tlsv1_3), or leave method unset for the default.",
		check: checkPJSIPTLS,
	})
}

func pjsipSections(c *Context, typ string) []conf.Effective {
	var out []conf.Effective
	for _, f := range c.Files {
		if !isPJSIP(f) {
			continue
		}
		for _, e := range sectionsOf(c, f) {
			if strings.EqualFold(e.Value("type"), typ) {
				out = append(out, e)
			}
		}
	}
	return out
}

func checkPJSIPAnonymous(c *Context) {
	for _, e := range pjsipSections(c, "endpoint") {
		if strings.EqualFold(e.Section.Name, "anonymous") {
			if f := fileOf(c, e.Section); f != nil {
				c.Add(High, f, e.Section.Line, "endpoint \"anonymous\" exists: calls from unknown senders land in context %q", e.Value("context"))
			}
		}
	}
}

func checkPJSIPNoAuth(c *Context) {
	identified := map[string]bool{}
	for _, id := range pjsipSections(c, "identify") {
		if ep := id.Value("endpoint"); ep != "" {
			for _, name := range splitList(ep) {
				identified[name] = true
			}
		}
	}
	for _, e := range pjsipSections(c, "endpoint") {
		if strings.EqualFold(e.Section.Name, "anonymous") || e.Value("auth") != "" {
			continue
		}
		if by := strings.ToLower(e.Value("identify_by")); by != "" &&
			!strings.Contains(by, "username") && !strings.Contains(by, "auth_username") {
			continue // matched by IP or header only: PJS-004 judges the identify section
		}
		f := fileOf(c, e.Section)
		if f == nil {
			continue
		}
		extra := ""
		if identified[e.Section.Name] {
			extra = " (an identify section also matches it by address, but a caller can still use the username)"
		}
		c.Add(High, f, e.Section.Line, "endpoint %q has no auth: INVITEs for it are accepted without a password%s", e.Section.Name, extra)
	}
}

func checkPJSIPPassword(c *Context) {
	for _, e := range pjsipSections(c, "auth") {
		if t := strings.ToLower(e.Value("auth_type")); t != "" && t != "userpass" {
			continue // md5 credentials are checked elsewhere
		}
		o, ok := e.Get("password")
		f := fileOf(c, e.Section)
		if !ok || f == nil {
			continue
		}
		if reason, sev := weakSecret(o.Value, e.Section.Name, e.Value("username")); reason != "" {
			c.Add(sev, f, o.Line, "auth %q: the password %s", e.Section.Name, reason)
		}
	}
}

func checkPJSIPIdentify(c *Context) {
	for _, e := range pjsipSections(c, "identify") {
		f := fileOf(c, e.Section)
		if f == nil {
			continue
		}
		for _, o := range e.All("match") {
			for _, m := range splitList(o.Value) {
				if isAnyNetwork(m) {
					c.Add(High, f, o.Line, "identify %q matches %s, that is every address", e.Section.Name, m)
				}
			}
		}
	}
}

func checkPJSIPTLS(c *Context) {
	for _, e := range pjsipSections(c, "transport") {
		o, ok := e.Get("method")
		f := fileOf(c, e.Section)
		if !ok || f == nil {
			continue
		}
		switch strings.ToLower(o.Value) {
		case "sslv2", "sslv3":
			c.Add(High, f, o.Line, "transport %q allows %s", e.Section.Name, o.Value)
		case "tlsv1", "tlsv1_1":
			c.Add(Medium, f, o.Line, "transport %q allows %s", e.Section.Name, o.Value)
		}
	}
}
