package rules

import (
	"strings"
)

func init() {
	register(&Rule{
		ID: "SIP-001", Severity: High, Applies: "sip.conf",
		Title: "chan_sip accepts guest calls",
		Why:   "allowguest defaults to yes: callers without an account can reach the [default] context, a favourite entry point for toll fraud.",
		Fix:   "Set allowguest = no in [general].",
		check: checkSIPGuest,
	})
	register(&Rule{
		ID: "SIP-002", Severity: Medium, Applies: "sip.conf",
		Title: "chan_sip tells attackers which usernames exist",
		Why:   "Without alwaysauthreject = yes, a wrong user and a wrong password get different answers, so extensions can be enumerated.",
		Fix:   "Set alwaysauthreject = yes in [general].",
		check: checkSIPReject,
	})
	register(&Rule{
		ID: "SIP-003", Severity: High, Applies: "sip.conf",
		Title: "Peer skips authentication of INVITEs",
		Why:   "insecure = invite, very or yes lets matching callers start calls without a password.",
		Fix:   "Remove insecure = invite; for trunks matched by IP use insecure = port at most, and restrict the host with permit/deny.",
		check: checkSIPInsecure,
	})
	register(&Rule{
		ID: "SIP-004", Severity: Critical, Applies: "sip.conf",
		Title: "chan_sip peer with a weak secret",
		Why:   "Same as PJS-003: SIP secrets are brute-forced all day.",
		Fix:   "Use a random secret of at least 16 characters.",
		check: checkSIPSecret,
	})
	register(&Rule{
		ID: "SIP-005", Severity: Low, Applies: "sip.conf",
		Title: "chan_sip is deprecated",
		Why:   "chan_sip has been deprecated since Asterisk 17 and gets no new features; PJSIP is the supported SIP stack.",
		Fix:   "Plan the move to PJSIP; the wizard in pjsip_wizard.conf keeps the config short.",
		check: checkSIPDeprecated,
	})
}

func checkSIPGuest(c *Context) {
	for _, f := range c.Files {
		if !isSIP(f) {
			continue
		}
		for _, e := range sectionsOf(c, f) {
			if !strings.EqualFold(e.Section.Name, "general") {
				continue
			}
			o, ok := e.Get("allowguest")
			switch {
			case !ok:
				c.Add(High, f, e.Section.Line, "allowguest is not set and defaults to yes")
			case truthy(o.Value):
				c.Add(High, f, o.Line, "allowguest = %s", o.Value)
			}
		}
	}
}

func checkSIPReject(c *Context) {
	for _, f := range c.Files {
		if !isSIP(f) {
			continue
		}
		for _, e := range sectionsOf(c, f) {
			if !strings.EqualFold(e.Section.Name, "general") {
				continue
			}
			if o, ok := e.Get("alwaysauthreject"); !ok || !truthy(o.Value) {
				c.Add(Medium, f, optLine(e, "alwaysauthreject"), "alwaysauthreject is not enabled")
			}
		}
	}
}

func sipPeers(c *Context) []peer {
	var out []peer
	for _, f := range c.Files {
		if !isSIP(f) {
			continue
		}
		for _, e := range sectionsOf(c, f) {
			if strings.EqualFold(e.Section.Name, "general") || strings.EqualFold(e.Section.Name, "authentication") {
				continue
			}
			out = append(out, peer{f, e})
		}
	}
	return out
}

func checkSIPInsecure(c *Context) {
	for _, p := range sipPeers(c) {
		o, ok := p.e.Get("insecure")
		if !ok {
			continue
		}
		for _, v := range splitList(o.Value) {
			if l := strings.ToLower(v); l == "invite" || l == "very" || l == "yes" {
				c.Add(High, p.f, o.Line, "peer %q has insecure = %s", p.e.Section.Name, o.Value)
				break
			}
		}
	}
}

func checkSIPSecret(c *Context) {
	for _, p := range sipPeers(c) {
		o, ok := p.e.Get("secret")
		if !ok {
			continue
		}
		if reason, sev := weakSecret(o.Value, p.e.Section.Name, p.e.Value("username")); reason != "" {
			c.Add(sev, p.f, o.Line, "peer %q: the secret %s", p.e.Section.Name, reason)
		}
	}
}

func checkSIPDeprecated(c *Context) {
	for _, f := range c.Files {
		if base(f) == "sip.conf" && len(f.Sections) > 0 {
			c.Add(Low, f, firstLine(f), "this file configures chan_sip")
		}
	}
}
