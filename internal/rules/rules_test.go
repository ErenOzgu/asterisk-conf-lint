package rules

import (
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"testing"

	"github.com/ErenOzgu/asterisk-conf-lint/internal/conf"
)

// run lints in-memory files (name -> content) and returns "RULE@line" strings.
func run(t *testing.T, opts Options, files map[string]string) []string {
	t.Helper()
	var parsed []*conf.File
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f, err := conf.Parse(n, strings.NewReader(files[n]))
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, f)
	}
	var out []string
	for _, f := range Run(parsed, opts, nil) {
		out = append(out, fmt.Sprintf("%s@%d", f.RuleID, f.Line))
	}
	return out
}

func check(t *testing.T, name string, got []string, want ...string) {
	t.Helper()
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("%s:\n got  %v\n want %v", name, got, want)
	}
}

const goodACL = "deny = 0.0.0.0/0.0.0.0\npermit = 127.0.0.1/255.255.255.255\n"
const strong = "Zq7xR2mV9pLw4TnC8dYe3Ka"

func TestAMIBind(t *testing.T) {
	cases := []struct {
		name, conf string
		want       []string
	}{
		{"disabled by default", "[general]\nbindaddr = 0.0.0.0\n", nil},
		{"explicitly disabled", "[general]\nenabled = no\nbindaddr = 0.0.0.0\n", nil},
		{"enabled, no bindaddr", "[general]\nenabled = yes\n", []string{"AMI-001@2"}},
		{"all interfaces", "[general]\nenabled = yes\nbindaddr = 0.0.0.0\n", []string{"AMI-001@3"}},
		{"ipv6 any", "[general]\nenabled = yes\nbindaddr = ::\n", []string{"AMI-001@3"}},
		{"empty bindaddr", "[general]\nenabled = yes\nbindaddr =\n", []string{"AMI-001@3"}},
		{"loopback", "[general]\nenabled = yes\nbindaddr = 127.0.0.1\n", nil},
		{"ipv6 loopback", "[general]\nenabled = yes\nbindaddr = ::1\n", nil},
		{"localhost with port", "[general]\nenabled = true\nbindaddr = localhost:5038\n", nil},
		{"private address", "[general]\nenabled = on\nbindaddr = 10.1.2.3\n", []string{"AMI-001@3"}},
	}
	for _, c := range cases {
		check(t, c.name, run(t, Options{}, map[string]string{"manager.conf": c.conf}), c.want...)
	}
}

func TestAMIACL(t *testing.T) {
	cases := []struct {
		name, conf string
		want       []string
	}{
		{"no acl", "[u]\nsecret = " + strong + "\n", []string{"AMI-002@1"}},
		{"deny and permit loopback", "[u]\nsecret = " + strong + "\n" + goodACL, nil},
		{"permit without deny", "[u]\nsecret = " + strong + "\npermit = 127.0.0.1/255.255.255.255\n", []string{"AMI-002@3"}},
		{"deny of a single network is not a catch-all", "[u]\nsecret = " + strong + "\ndeny = 10.0.0.0/8\npermit = 127.0.0.1/32\n", []string{"AMI-002@4"}},
		{"permit all", "[u]\nsecret = " + strong + "\ndeny = 0.0.0.0/0.0.0.0\npermit = 0.0.0.0/0.0.0.0\n", []string{"AMI-002@4"}},
		{"short notation for any", "[u]\nsecret = " + strong + "\ndeny = 0.0.0.0/0\npermit = 0.0.0.0/0\n", []string{"AMI-002@4"}},
		{"general is not a user", "[general]\nenabled = no\n", nil},
		{"template is not a user", "[tmpl](!)\nsecret = x\n", nil},
		{"acl inherited from a template", "[tmpl](!)\n" + goodACL + "[u](tmpl)\nsecret = " + strong + "\n", nil},
		{"file in manager.d", "", nil},
	}
	for _, c := range cases {
		check(t, c.name, run(t, Options{}, map[string]string{"manager.conf": c.conf}), c.want...)
	}
	// manager.d/*.conf is treated like manager.conf (asterisk-gcp-iac uses it).
	check(t, "manager.d", run(t, Options{}, map[string]string{"etc/manager.d/exporter.conf": "[exporter]\nsecret = " + strong + "\n"}), "AMI-002@1")
}

func TestAMISecret(t *testing.T) {
	cases := []struct {
		name, secret string
		want         []string
	}{
		{"strong", strong, nil},
		{"empty", "", []string{"AMI-003@2"}},
		{"default", "asterisk", []string{"AMI-003@2"}},
		{"same as user", "ops", []string{"AMI-003@2"}},
		{"too short", "Ab1!", []string{"AMI-003@2"}},
		{"eleven chars", "Ab1!Ab1!Ab1", []string{"AMI-003@2"}},
		{"twelve mixed chars", "Ab1!Ab1!Ab1!", nil},
		{"digits only, 14 long", "48201937562810", []string{"AMI-003@2"}},
		{"digits only, 16 long", "4820193756281047", nil},
		{"sequence", "123456789012345678", []string{"AMI-003@2"}},
		{"repeated", "aaaaaaaaaaaaaaaa", []string{"AMI-003@2"}},
		{"placeholder is not judged", "${AMI_SECRET}", nil},
		{"template placeholder", "{{ vault_ami }}", nil},
	}
	for _, c := range cases {
		text := "[ops]\nsecret = " + c.secret + "\n" + goodACL
		got := run(t, Options{}, map[string]string{"manager.conf": text})
		check(t, c.name, got, c.want...)
	}
	// md5secret only: nothing to judge.
	check(t, "md5secret", run(t, Options{}, map[string]string{"manager.conf": "[ops]\nmd5secret = 5d41402abc4b2a76b9719d911017c592\n" + goodACL}))
}

func TestAMIWrite(t *testing.T) {
	cases := []struct {
		write string
		want  []string
	}{
		{"reporting", nil},
		{"system,reporting", []string{"AMI-004@3"}},
		{"command", []string{"AMI-004@3"}},
		{"call, originate", []string{"AMI-004@3"}},
		{"all", []string{"AMI-004@3"}},
		{"ALL", []string{"AMI-004@3"}},
		{"", nil},
	}
	for _, c := range cases {
		text := "[ops]\nsecret = " + strong + "\nwrite = " + c.write + "\n" + goodACL
		check(t, "write="+c.write, run(t, Options{}, map[string]string{"manager.conf": text}), c.want...)
	}
}

func TestAMIWriteSeverities(t *testing.T) {
	sev := func(write string) Severity {
		text := "[ops]\nsecret = " + strong + "\nwrite = " + write + "\n" + goodACL
		f, _ := conf2file("manager.conf", text)
		for _, fd := range Run([]*conf.File{f}, Options{}, nil) {
			if fd.RuleID == "AMI-004" {
				return fd.Severity
			}
		}
		return -1
	}
	for write, want := range map[string]Severity{"all": High, "command": Medium, "originate,reporting": Medium, "system": Low} {
		if got := sev(write); got != want {
			t.Errorf("write=%s severity %v, want %v", write, got, want)
		}
	}
}

func conf2file(name, text string) (*conf.File, error) {
	return conf.Parse(name, strings.NewReader(text))
}

func TestPJSIP(t *testing.T) {
	const pj = "pjsip.conf"
	cases := []struct {
		name, conf string
		want       []string
	}{
		{"anonymous endpoint", "[anonymous]\ntype = endpoint\ncontext = default\n", []string{"PJS-001@1"}},
		{"endpoint without auth", "[200]\ntype = endpoint\ncontext = x\n", []string{"PJS-002@1"}},
		{"endpoint with auth", "[200]\ntype = endpoint\nauth = a200\n", nil},
		{"auth inherited from template", "[t](!)\ntype = endpoint\nauth = shared\n[200](t)\n", nil},
		{"ip-only endpoint needs no auth", "[trunk]\ntype = endpoint\nidentify_by = ip\n", nil},
		{"username matching without auth", "[trunk]\ntype = endpoint\nidentify_by = username,ip\n", []string{"PJS-002@1"}},
		{"identify does not excuse a missing auth", "[trunk]\ntype = endpoint\n[trunk]\ntype = identify\nendpoint = trunk\nmatch = 203.0.113.9\n", []string{"PJS-002@1"}},
		{"weak auth password", "[a]\ntype = auth\nusername = u\npassword = secret\n", []string{"PJS-003@4"}},
		{"password equal to username", "[a]\ntype = auth\nusername = Sup3rSecretUser!\npassword = Sup3rSecretUser!\n", []string{"PJS-003@4"}},
		{"strong auth password", "[a]\ntype = auth\nusername = u\npassword = " + strong + "\n", nil},
		{"md5 auth is not judged", "[a]\ntype = auth\nauth_type = md5\nmd5_cred = abc\n", nil},
		{"identify any", "[i]\ntype = identify\nendpoint = e\nmatch = 0.0.0.0/0\n", []string{"PJS-004@4"}},
		{"identify list with any", "[i]\ntype = identify\nendpoint = e\nmatch = 203.0.113.9, ::/0\n", []string{"PJS-004@4"}},
		{"identify narrow", "[i]\ntype = identify\nendpoint = e\nmatch = 203.0.113.0/24\n", nil},
		{"sslv3", "[t]\ntype = transport\nprotocol = tls\nmethod = sslv3\n", []string{"PJS-005@4"}},
		{"tlsv1", "[t]\ntype = transport\nprotocol = tls\nmethod = tlsv1\n", []string{"PJS-005@4"}},
		{"tlsv1_2", "[t]\ntype = transport\nprotocol = tls\nmethod = tlsv1_2\n", nil},
		{"unrelated type in pjsip.conf", "[x]\ntype = aor\nmax_contacts = 1\n", nil},
	}
	for _, c := range cases {
		check(t, c.name, run(t, Options{}, map[string]string{pj: c.conf}), c.want...)
	}
	// PJSIP files are recognised by name, so a "type = endpoint" in an
	// unrelated file is ignored.
	check(t, "other file", run(t, Options{}, map[string]string{"queues.conf": "[anonymous]\ntype = endpoint\n"}))
	check(t, "pjsip.d", run(t, Options{}, map[string]string{"etc/pjsip.d/ext.conf": "[anonymous]\ntype = endpoint\n"}), "PJS-001@1")
}

func TestChanSIP(t *testing.T) {
	cases := []struct {
		name, conf string
		want       []string
	}{
		{"defaults", "[general]\nbindport = 5060\n", []string{"SIP-001@1", "SIP-002@1", "SIP-005@1"}},
		{"hardened", "[general]\nallowguest = no\nalwaysauthreject = yes\n", []string{"SIP-005@1"}},
		{"guest on", "[general]\nallowguest = yes\nalwaysauthreject = yes\n", []string{"SIP-001@2", "SIP-005@1"}},
		{"authreject off", "[general]\nallowguest = no\nalwaysauthreject = no\n", []string{"SIP-002@3", "SIP-005@1"}},
		{"insecure invite", "[general]\nallowguest = no\nalwaysauthreject = yes\n[p]\ntype = peer\ninsecure = port,invite\nsecret = " + strong + "\n",
			[]string{"SIP-003@6", "SIP-005@1"}},
		{"insecure very", "[general]\nallowguest = no\nalwaysauthreject = yes\n[p]\ninsecure = very\n", []string{"SIP-003@5", "SIP-005@1"}},
		{"insecure port is fine", "[general]\nallowguest = no\nalwaysauthreject = yes\n[p]\ninsecure = port\n", []string{"SIP-005@1"}},
		{"weak peer secret", "[general]\nallowguest = no\nalwaysauthreject = yes\n[p]\nsecret = 1234\n", []string{"SIP-004@5", "SIP-005@1"}},
	}
	for _, c := range cases {
		check(t, c.name, run(t, Options{}, map[string]string{"sip.conf": c.conf}), c.want...)
	}
	check(t, "sip_notify.conf is not sip.conf", run(t, Options{}, map[string]string{"sip_notify.conf": "[general]\nx = 1\n"}))
}

func TestRTPHTTPARIModules(t *testing.T) {
	check(t, "strictrtp no", run(t, Options{}, map[string]string{"rtp.conf": "[general]\nstrictrtp = no\n"}), "RTP-001@2")
	check(t, "strictrtp yes", run(t, Options{}, map[string]string{"rtp.conf": "[general]\nstrictrtp = yes\n"}))
	check(t, "strictrtp default", run(t, Options{}, map[string]string{"rtp.conf": "[general]\nrtpstart = 10000\n"}))

	check(t, "http public no tls", run(t, Options{}, map[string]string{"http.conf": "[general]\nenabled = yes\nbindaddr = 0.0.0.0\n"}), "HTTP-001@3")
	check(t, "http public tls", run(t, Options{}, map[string]string{"http.conf": "[general]\nenabled = yes\nbindaddr = 0.0.0.0\ntlsenable = yes\n"}))
	check(t, "http loopback", run(t, Options{}, map[string]string{"http.conf": "[general]\nenabled = yes\nbindaddr = 127.0.0.1\n"}))
	check(t, "http disabled", run(t, Options{}, map[string]string{"http.conf": "[general]\nenabled = no\nbindaddr = 0.0.0.0\n"}))
	check(t, "http no bindaddr", run(t, Options{}, map[string]string{"http.conf": "[general]\nenabled = yes\n"}))

	check(t, "ari weak plain", run(t, Options{}, map[string]string{"ari.conf": "[general]\nenabled = yes\n[app]\ntype = user\npassword = asterisk\n"}), "ARI-001@5", "ARI-002@1")
	check(t, "ari crypt", run(t, Options{}, map[string]string{"ari.conf": "[general]\npassword_format = crypt\n[app]\npassword = $6$salt$" + strong + "\n"}))
	check(t, "ari plain explicit", run(t, Options{}, map[string]string{"ari.conf": "[general]\npassword_format = plain\n[app]\npassword = " + strong + "\n"}), "ARI-002@2")
	check(t, "ari no users", run(t, Options{}, map[string]string{"ari.conf": "[general]\nenabled = no\n"}))

}

func TestModulesRule(t *testing.T) {
	got := run(t, Options{}, map[string]string{"modules.conf": "[modules]\nautoload = yes\nnoload = chan_sip.so\nnoload = chan_iax2\nnoload = chan_skinny.so\nnoload = chan_mgcp.so\n"})
	check(t, "one driver left", got, "MOD-001@2")
	check(t, "all noloaded", run(t, Options{}, map[string]string{"modules.conf": "[modules]\nautoload = yes\nnoload = chan_sip.so\nnoload = chan_iax2.so\nnoload = chan_skinny.so\nnoload = chan_mgcp.so\nnoload = chan_unistim.so\n"}))
	check(t, "autoload off", run(t, Options{}, map[string]string{"modules.conf": "[modules]\nautoload = no\n"}))
	// A driver whose config file is part of the run is considered in use.
	got = run(t, Options{}, map[string]string{
		"modules.conf": "[modules]\nautoload = yes\nnoload = chan_iax2.so\nnoload = chan_skinny.so\nnoload = chan_mgcp.so\nnoload = chan_unistim.so\n",
		"sip.conf":     "[general]\nallowguest = no\nalwaysauthreject = yes\n",
	})
	check(t, "chan_sip in use", got, "SIP-005@1")
}

func TestDialplan(t *testing.T) {
	const ex = "extensions.conf"
	cases := []struct {
		name, conf string
		want       []string
	}{
		{"unguarded catch-all", "[out]\nexten => _X.,1,Dial(PJSIP/${EXTEN}@trunk)\n", []string{"DIAL-001@2"}},
		{"catch-all via same", "[out]\nexten => _0.,1,NoOp()\n same => n,Dial(PJSIP/${EXTEN}@trunk)\n", []string{"DIAL-001@3"}},
		{"guarded by Authenticate", "[out]\nexten => _X.,1,Authenticate(1234)\n same => n,Dial(PJSIP/${EXTEN}@trunk)\n", nil},
		{"guarded by GotoIf", "[out]\nexten => _00X.,1,GotoIf($[\"${X}\" = \"y\"]?ok:no)\n same => n(ok),Dial(PJSIP/${EXTEN}@trunk)\n", nil},
		{"narrow pattern", "[in]\nexten => _10X,1,Dial(PJSIP/${EXTEN})\n", nil},
		{"local channel is not a trunk", "[out]\nexten => _X.,1,Dial(Local/${EXTEN}@internal)\n", nil},
		{"dial of a fixed trunk number", "[out]\nexten => _X.,1,Dial(PJSIP/provider)\n", nil},
		{"system with variable", "[a]\nexten => s,1,System(/bin/notify ${CALLERID(num)})\n", []string{"DIAL-002@2"}},
		{"trysystem with variable", "[a]\nexten => s,1,TrySystem(echo ${EXTEN})\n", []string{"DIAL-002@2"}},
		{"system with fixed command", "[a]\nexten => s,1,System(/bin/notify now)\n", nil},
		{"SHELL function with variable", "[a]\nexten => s,1,Set(R=${SHELL(echo ${EXTEN})})\n", []string{"DIAL-002@2"}},
		{"SHELL function with fixed command", "[a]\nexten => s,1,Set(R=${SHELL(date)})\n", nil},
		{"extensions_custom.conf counts", "", nil},
	}
	for _, c := range cases {
		check(t, c.name, run(t, Options{}, map[string]string{ex: c.conf}), c.want...)
	}
	check(t, "extensions_custom.conf", run(t, Options{}, map[string]string{"extensions_custom.conf": "[o]\nexten => _X.,1,Dial(SIP/${EXTEN})\n"}), "DIAL-001@2")
}

func TestConfigRules(t *testing.T) {
	check(t, "bad line, first only", run(t, Options{}, map[string]string{"x.conf": "[a]\nk = v\nnonsense one\nnonsense two\nnonsense three\n"}), "CFG-000@3")
	check(t, "exec without execincludes", run(t, Options{}, map[string]string{"extensions.conf": "#exec \"/bin/gen\"\n[a]\nk=v\n"}), "CFG-001@1")
	check(t, "execincludes alone", run(t, Options{}, map[string]string{"asterisk.conf": "[options]\nexecincludes = yes\n"}), "CFG-002@2")
	check(t, "exec with execincludes", run(t, Options{}, map[string]string{
		"asterisk.conf":   "[options]\nexecincludes = yes\n",
		"extensions.conf": "#exec \"/bin/gen\"\n",
	}), "CFG-001@1", "CFG-002@2")
	check(t, "include is fine", run(t, Options{}, map[string]string{"extensions.conf": "#include \"extra.conf\"\n"}))
}

func TestSeverityOfExecDirective(t *testing.T) {
	sev := func(files map[string]string) Severity {
		var parsed []*conf.File
		for n, c := range files {
			f, _ := conf2file(n, c)
			parsed = append(parsed, f)
		}
		for _, fd := range Run(parsed, Options{}, nil) {
			if fd.RuleID == "CFG-001" {
				return fd.Severity
			}
		}
		return -1
	}
	if got := sev(map[string]string{"extensions.conf": "#exec \"/bin/x\"\n"}); got != Medium {
		t.Errorf("without execincludes: %v", got)
	}
	if got := sev(map[string]string{"extensions.conf": "#exec \"/bin/x\"\n", "asterisk.conf": "[options]\nexecincludes=yes\n"}); got != High {
		t.Errorf("with execincludes: %v", got)
	}
}

func TestPermsRule(t *testing.T) {
	mk := func(mode fs.FileMode, body string) *conf.File {
		f, _ := conf2file("manager.conf", body)
		f.Mode, f.HasMode = mode, true
		return f
	}
	secretConf := "[ops]\nsecret = " + strong + "\n" + goodACL
	for _, c := range []struct {
		name string
		file *conf.File
		opts Options
		want int
	}{
		{"world readable", mk(0o644, secretConf), Options{CheckPerms: true}, 1},
		{"private", mk(0o640, secretConf), Options{CheckPerms: true}, 0},
		{"disabled by default", mk(0o644, secretConf), Options{}, 0},
		{"no secrets inside", mk(0o644, "[general]\nenabled = no\n"), Options{CheckPerms: true}, 0},
		{"in-memory file has no mode", func() *conf.File { f, _ := conf2file("manager.conf", secretConf); return f }(), Options{CheckPerms: true}, 0},
	} {
		n := 0
		for _, fd := range Run([]*conf.File{c.file}, c.opts, nil) {
			if fd.RuleID == "CFG-003" {
				n++
			}
		}
		if n != c.want {
			t.Errorf("%s: %d CFG-003 findings, want %d", c.name, n, c.want)
		}
	}
}

func TestEveryRuleIsDocumentedAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range All() {
		if seen[r.ID] {
			t.Errorf("duplicate rule %s", r.ID)
		}
		seen[r.ID] = true
		if r.Title == "" || r.Why == "" || r.Fix == "" || r.Applies == "" || r.check == nil {
			t.Errorf("rule %s is missing a title, explanation, fix, file or check", r.ID)
		}
	}
	if len(seen) < 20 {
		t.Errorf("only %d rules registered", len(seen))
	}
}

func TestDisabledRulesDoNotRun(t *testing.T) {
	f, _ := conf2file("sip.conf", "[general]\nbindport = 5060\n")
	got := Run([]*conf.File{f}, Options{}, map[string]bool{"SIP-001": true, "SIP-005": true})
	if len(got) != 1 || got[0].RuleID != "SIP-002" {
		t.Errorf("got %+v", got)
	}
}
