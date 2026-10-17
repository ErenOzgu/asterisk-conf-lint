package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func exec(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

const good = "../../testdata/good"
const bad = "../../testdata/bad"

func TestExitCodes(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"clean config", []string{good}, 0},
		{"findings at medium and above", []string{bad}, 1},
		{"fail-on none", []string{"-fail-on", "none", bad}, 0},
		{"fail-on critical, none that bad", []string{"-fail-on", "critical", bad}, 0},
		{"fail-on high", []string{"-fail-on", "high", bad}, 1},
		{"only low findings pass the default", []string{"-disable", "AMI-001,AMI-002,AMI-003,AMI-004,PJS-001,PJS-002,PJS-003,PJS-004,PJS-005,RTP-001,HTTP-001,ARI-001,SIP-001,SIP-002,SIP-003,SIP-004,CFG-001,CFG-002,DIAL-001,DIAL-002", bad}, 0},
		{"fail-on low catches them", []string{"-fail-on", "low", "-disable", "AMI-001,AMI-002,AMI-003,AMI-004,PJS-001,PJS-002,PJS-003,PJS-004,PJS-005,RTP-001,HTTP-001,ARI-001,SIP-001,SIP-002,SIP-003,SIP-004,CFG-001,CFG-002,DIAL-001,DIAL-002", bad}, 1},
		{"min-severity hides low findings, fail-on low then passes", []string{"-min-severity", "high", "-fail-on", "low", good}, 0},
		{"no arguments", nil, 2},
		{"missing path", []string{"/nonexistent/dir"}, 2},
		{"unknown flag", []string{"-nope", good}, 2},
		{"unknown format", []string{"-format", "xml", good}, 2},
		{"unknown fail-on", []string{"-fail-on", "severe", good}, 2},
		{"unknown min-severity", []string{"-min-severity", "x", good}, 2},
		{"unknown rule in disable", []string{"-disable", "NOPE-1", good}, 2},
		{"help", []string{"-h"}, 0},
	}
	for _, c := range cases {
		if got, _, errOut := exec(t, c.args...); got != c.want {
			t.Errorf("%s: exit %d, want %d (stderr: %s)", c.name, got, c.want, errOut)
		}
	}
}

func TestTextOutput(t *testing.T) {
	code, out, _ := exec(t, bad)
	if code != 1 || !strings.Contains(out, "AMI-002") || !strings.Contains(out, "fix:") {
		t.Errorf("exit %d\n%s", code, out)
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("output to a buffer must not be coloured")
	}
	_, out, _ = exec(t, good)
	if strings.TrimSpace(out) != "no findings in 8 files" {
		t.Errorf("clean output = %q", out)
	}
}

func TestJSONAndSARIFOutput(t *testing.T) {
	_, out, _ := exec(t, "-format", "json", bad)
	var j struct{ Findings []map[string]any }
	if err := json.Unmarshal([]byte(out), &j); err != nil || len(j.Findings) != 28 {
		t.Errorf("json: err=%v findings=%d", err, len(j.Findings))
	}
	_, out, _ = exec(t, "-format", "sarif", bad)
	var s struct{ Version string }
	if err := json.Unmarshal([]byte(out), &s); err != nil || s.Version != "2.1.0" {
		t.Errorf("sarif: err=%v version=%s", err, s.Version)
	}
}

func TestMinSeverityFilter(t *testing.T) {
	_, out, _ := exec(t, "-min-severity", "high", "-fail-on", "none", bad)
	if strings.Contains(out, "  low  ") || strings.Contains(out, "medium ") {
		t.Errorf("low and medium findings must be hidden:\n%s", out)
	}
	if !strings.Contains(out, "17 high") && !strings.Contains(out, "17 findings (17 high)") {
		t.Errorf("summary = %s", out)
	}
}

func TestListRulesAndVersion(t *testing.T) {
	code, out, _ := exec(t, "-list-rules")
	if code != 0 || !strings.Contains(out, "AMI-001") || !strings.Contains(out, "why:") || !strings.Contains(out, "fix:") {
		t.Errorf("exit %d\n%s", code, out)
	}
	code, out, _ = exec(t, "-list-rules", "-format", "markdown")
	if code != 0 || !strings.HasPrefix(out, "| Rule | Severity |") {
		t.Errorf("markdown: exit %d\n%s", code, out)
	}
	if code, _, _ = exec(t, "-list-rules", "-format", "json"); code != 2 {
		t.Errorf("-list-rules -format json should be refused, got %d", code)
	}
	_, out, _ = exec(t, "-version")
	if strings.TrimSpace(out) != "asterisk-conf-lint dev" {
		t.Errorf("version = %q", out)
	}
}

func TestCheckPermsFlag(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "manager.conf")
	body := "[ops]\nsecret = Zq7xR2mV9pLw4TnC8dYe3Ka\ndeny = 0.0.0.0/0.0.0.0\npermit = 127.0.0.1/32\nwrite = reporting\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := exec(t, dir); code != 0 {
		t.Errorf("without -check-perms: exit %d", code)
	}
	if code, out, _ := exec(t, "-check-perms", dir); code != 1 || !strings.Contains(out, "CFG-003") {
		t.Errorf("with -check-perms: exit %d\n%s", code, out)
	}
}

func TestDisableFlag(t *testing.T) {
	_, out, _ := exec(t, "-disable", "ami-001, AMI-002", "-fail-on", "none", bad)
	if strings.Contains(out, "AMI-001") || strings.Contains(out, "AMI-002") {
		t.Errorf("disabled rules still reported:\n%s", out)
	}
	if !strings.Contains(out, "AMI-003") {
		t.Error("other rules must still run")
	}
}
