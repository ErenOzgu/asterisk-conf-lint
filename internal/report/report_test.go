package report

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ErenOzgu/asterisk-conf-lint/internal/lint"
	"github.com/ErenOzgu/asterisk-conf-lint/internal/rules"
)

const badDir = "../../testdata/bad"

func badResult(t *testing.T) *lint.Result {
	t.Helper()
	res, err := lint.Run([]string{badDir}, lint.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestTextHasFixAndSummary(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, badResult(t), false)
	out := buf.String()
	for _, want := range []string{
		"testdata/bad/manager.conf:3  high      AMI-001  AMI listens on all interfaces",
		"    fix: Set bindaddr = 127.0.0.1",
		"28 findings (17 high, 7 medium, 4 low) in 9 files",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output lacks %q", want)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("colour escapes without colour")
	}
	buf.Reset()
	Text(&buf, badResult(t), true)
	if !strings.Contains(buf.String(), "\x1b[31m") {
		t.Error("colour requested but missing")
	}
}

func TestTextGolden(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, badResult(t), false)
	const golden = "../../testdata/bad.golden.txt"
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(golden, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if buf.String() != string(want) {
		t.Errorf("output differs from %s (run with UPDATE_GOLDEN=1 to refresh):\n%s", golden, buf.String())
	}
}

func TestSummaryWording(t *testing.T) {
	if got := Summary(&lint.Result{Files: 3}); got != "no findings in 3 files" {
		t.Errorf("clean = %q", got)
	}
	got := Summary(&lint.Result{Files: 1, Suppressed: 2, Findings: []rules.Finding{{Severity: rules.Critical}}})
	if got != "1 findings (1 critical) in 1 files, 2 suppressed" {
		t.Errorf("= %q", got)
	}
}

func TestJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, badResult(t)); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Files    int
		Findings []struct {
			Rule, Severity, File, Message string
			Line                          int
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if out.Files != 9 || len(out.Findings) != 28 {
		t.Errorf("files=%d findings=%d", out.Files, len(out.Findings))
	}
	f := out.Findings[0]
	if f.Rule == "" || f.Severity == "" || f.File == "" || f.Line == 0 || f.Message == "" {
		t.Errorf("incomplete finding %+v", f)
	}

	buf.Reset()
	if err := JSON(&buf, &lint.Result{Files: 1}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"findings": []`) {
		t.Errorf("no findings must be an empty array, not null: %s", buf.String())
	}
}

func TestSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, badResult(t), "1.2.3"); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name, Version string
					Rules         []struct {
						ID                   string `json:"id"`
						DefaultConfiguration struct{ Level string }
						Properties           map[string]any
					}
				}
			}
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string
				Message   struct{ Text string }
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						}
						Region struct{ StartLine int }
					}
				}
			}
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("version=%s runs=%d", log.Version, len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "asterisk-conf-lint" || run.Tool.Driver.Version != "1.2.3" {
		t.Errorf("driver = %+v", run.Tool.Driver)
	}
	if len(run.Tool.Driver.Rules) != len(rules.All()) {
		t.Errorf("rules = %d, want %d", len(run.Tool.Driver.Rules), len(rules.All()))
	}
	for _, r := range run.Tool.Driver.Rules {
		if _, ok := r.Properties["security-severity"]; !ok {
			t.Errorf("rule %s has no security-severity", r.ID)
		}
	}
	if len(run.Results) != 28 {
		t.Fatalf("results = %d", len(run.Results))
	}
	levels := map[string]int{}
	for _, r := range run.Results {
		if run.Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
			t.Errorf("ruleIndex %d does not point at %s", r.RuleIndex, r.RuleID)
		}
		loc := r.Locations[0].PhysicalLocation
		if loc.Region.StartLine < 1 || !strings.HasSuffix(loc.ArtifactLocation.URI, ".conf") || strings.Contains(loc.ArtifactLocation.URI, "\\") {
			t.Errorf("bad location %+v", loc)
		}
		levels[r.Level]++
	}
	if levels["error"] != 17 || levels["warning"] != 7 || levels["note"] != 4 {
		t.Errorf("levels = %v", levels)
	}
}

func TestRulesMarkdownCoversEveryRule(t *testing.T) {
	md := RulesMarkdown()
	for _, r := range rules.All() {
		if !strings.Contains(md, "| `"+r.ID+"` |") {
			t.Errorf("table lacks %s", r.ID)
		}
	}
	if !strings.HasPrefix(md, "| Rule | Severity | File | What it catches |") {
		t.Error("table header changed")
	}
}

// The README embeds the rule table. Keeping the check here means a new or
// renamed rule fails the build until the docs are regenerated:
//
//	asterisk-conf-lint -list-rules -format markdown
func TestReadmeRuleTableIsCurrent(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Skip("README.md not present")
	}
	if !strings.Contains(string(readme), RulesMarkdown()) {
		t.Error("README.md does not contain the current rule table; run: asterisk-conf-lint -list-rules -format markdown")
	}
}
