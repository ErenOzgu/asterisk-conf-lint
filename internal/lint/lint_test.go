package lint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ErenOzgu/asterisk-conf-lint/internal/rules"
)

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func ids(res *Result) string {
	var out []string
	for _, f := range res.Findings {
		out = append(out, f.RuleID)
	}
	return strings.Join(out, ",")
}

const badSIP = "[general]\nbindport = 5060\n"

func TestRunWalksDirectoriesRecursively(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "sip.conf", badSIP)
	write(t, dir, "nested/deeper/rtp.conf", "[general]\nstrictrtp = no\n")
	write(t, dir, "notes.txt", "[general]\nstrictrtp = no\n")
	write(t, dir, "ast_debug_tools.conf", "# bash\nCOREDUMPS=\"x\"\n")
	res, err := Run([]string{dir}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 2 {
		t.Errorf("files = %d, want 2 (txt and the bash file are skipped)", res.Files)
	}
	if got := ids(res); got != "RTP-001,SIP-001,SIP-002,SIP-005" && got != "SIP-001,SIP-002,SIP-005,RTP-001" {
		t.Errorf("findings = %s", got)
	}
}

func TestRunErrors(t *testing.T) {
	if _, err := Run([]string{filepath.Join(t.TempDir(), "missing")}, Options{}); err == nil {
		t.Error("a missing path must be an error")
	}
	if _, err := Run([]string{t.TempDir()}, Options{}); err == nil || !strings.Contains(err.Error(), "no .conf files") {
		t.Errorf("an empty directory must be an error, got %v", err)
	}
}

func TestSuppression(t *testing.T) {
	dir := t.TempDir()
	body := strings.Join([]string{
		"; lint-ignore: SIP-001 lab box, no trunk",
		"[general]",
		"bindport = 5060 ; lint-ignore: SIP-005",
	}, "\n")
	// SIP-001 and SIP-002 and SIP-005 are all reported on line 2 ("[general]").
	write(t, dir, "sip.conf", body)
	res, err := Run([]string{dir}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(res); got != "SIP-002,SIP-005" {
		t.Errorf("the line-above ignore must hide SIP-001 only, got %s", got)
	}
	if res.Suppressed != 1 {
		t.Errorf("suppressed = %d", res.Suppressed)
	}
}

func TestSuppressionSameLineWildcardAndFile(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "sip.conf", "[general] ; lint-ignore: *\nbindport = 5060\n")
	res, _ := Run([]string{dir}, Options{})
	if len(res.Findings) != 0 || res.Suppressed != 3 {
		t.Errorf("wildcard on the same line: findings=%v suppressed=%d", res.Findings, res.Suppressed)
	}

	dir = t.TempDir()
	write(t, dir, "sip.conf", "[general]\nbindport = 5060\n\n; lint-ignore-file: SIP-001,SIP-002\n")
	res, _ = Run([]string{dir}, Options{})
	if got := ids(res); got != "SIP-005" || res.Suppressed != 2 {
		t.Errorf("file-wide ignore: %s suppressed=%d", got, res.Suppressed)
	}

	dir = t.TempDir()
	write(t, dir, "sip.conf", "; lint-ignore: SIP-001\n\n[general]\nbindport = 5060\n")
	res, _ = Run([]string{dir}, Options{})
	if res.Suppressed != 0 {
		t.Error("an ignore two lines above must not apply")
	}
}

func TestMinSeverityAndDisabled(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "sip.conf", badSIP)
	res, _ := Run([]string{dir}, Options{MinSeverty: rules.High})
	if got := ids(res); got != "SIP-001" {
		t.Errorf("min severity high: %s", got)
	}
	res, _ = Run([]string{dir}, Options{Disabled: map[string]bool{"SIP-001": true, "SIP-005": true}})
	if got := ids(res); got != "SIP-002" {
		t.Errorf("disabled: %s", got)
	}
}

func TestSingleFileAndModeRecorded(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "manager.conf", "[ops]\nsecret = Zq7xR2mV9pLw4TnC8dYe3Ka\ndeny = 0.0.0.0/0.0.0.0\npermit = 127.0.0.1/32\nwrite = reporting\n")
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Run([]string{p}, Options{Rules: rules.Options{CheckPerms: true}})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(res); got != "CFG-003" {
		t.Errorf("findings = %s", got)
	}
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	res, _ = Run([]string{p}, Options{Rules: rules.Options{CheckPerms: true}})
	if len(res.Findings) != 0 {
		t.Errorf("0640 must pass: %v", res.Findings)
	}
}

func TestCrossFileTemplates(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "pjsip_templates.conf", "[tmpl](!)\ntype = endpoint\nauth = shared-auth\n")
	write(t, dir, "pjsip.conf", "[300](tmpl)\ncontext = x\n")
	res, err := Run([]string{dir}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("auth comes from a template in another file, got %v", res.Findings)
	}
}
