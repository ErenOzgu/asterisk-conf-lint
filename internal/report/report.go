// Package report writes findings as text, JSON, SARIF or a Markdown rule table.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ErenOzgu/asterisk-conf-lint/internal/lint"
	"github.com/ErenOzgu/asterisk-conf-lint/internal/rules"
)

const informationURI = "https://github.com/ErenOzgu/asterisk-conf-lint"

// Text prints one block per finding and a summary line.
func Text(w io.Writer, res *lint.Result, color bool) {
	paint := func(sev rules.Severity, s string) string {
		if !color {
			return s
		}
		code := map[rules.Severity]string{
			rules.Critical: "1;31", rules.High: "31", rules.Medium: "33", rules.Low: "36", rules.Info: "2",
		}[sev]
		return "\x1b[" + code + "m" + s + "\x1b[0m"
	}
	for _, f := range res.Findings {
		fmt.Fprintf(w, "%s:%d  %s  %s  %s\n", f.File, f.Line, paint(f.Severity, fmt.Sprintf("%-8s", f.Severity)), f.RuleID, f.Message)
		if r, ok := rules.Lookup(f.RuleID); ok {
			fmt.Fprintf(w, "    fix: %s\n", r.Fix)
		}
	}
	fmt.Fprintln(w, Summary(res))
}

// Summary is the closing line: counts by severity, files and suppressions.
func Summary(res *lint.Result) string {
	counts := map[rules.Severity]int{}
	for _, f := range res.Findings {
		counts[f.Severity]++
	}
	var parts []string
	for s := rules.Critical; s >= rules.Info; s-- {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	found := "no findings"
	if len(parts) > 0 {
		found = fmt.Sprintf("%d findings (%s)", len(res.Findings), strings.Join(parts, ", "))
	}
	tail := ""
	if res.Suppressed > 0 {
		tail = fmt.Sprintf(", %d suppressed", res.Suppressed)
	}
	return fmt.Sprintf("%s in %d files%s", found, res.Files, tail)
}

type jsonFinding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Message  string `json:"message"`
}

// JSON writes {"files":N,"suppressed":N,"findings":[...]}.
func JSON(w io.Writer, res *lint.Result) error {
	out := struct {
		Files      int           `json:"files"`
		Suppressed int           `json:"suppressed"`
		Findings   []jsonFinding `json:"findings"`
	}{Files: res.Files, Suppressed: res.Suppressed, Findings: []jsonFinding{}}
	for _, f := range res.Findings {
		out.Findings = append(out.Findings, jsonFinding{f.RuleID, f.Severity.String(), f.File, f.Line, f.Message})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// securitySeverity maps a severity to the CVSS-like score GitHub code
// scanning uses to sort alerts.
func securitySeverity(s rules.Severity) string {
	return map[rules.Severity]string{
		rules.Critical: "9.5", rules.High: "8.0", rules.Medium: "5.5", rules.Low: "3.0", rules.Info: "1.0",
	}[s]
}

func sarifLevel(s rules.Severity) string {
	switch {
	case s >= rules.High:
		return "error"
	case s == rules.Medium:
		return "warning"
	}
	return "note"
}

// SARIF writes a SARIF 2.1.0 log that GitHub code scanning accepts.
func SARIF(w io.Writer, res *lint.Result, version string) error {
	type obj = map[string]any
	var ruleDefs []obj
	index := map[string]int{}
	for _, r := range rules.All() {
		index[r.ID] = len(ruleDefs)
		ruleDefs = append(ruleDefs, obj{
			"id":               r.ID,
			"name":             r.ID,
			"shortDescription": obj{"text": r.Title},
			"fullDescription":  obj{"text": r.Why},
			"help":             obj{"text": r.Fix},
			"defaultConfiguration": obj{
				"level": sarifLevel(r.Severity),
			},
			"properties": obj{
				"tags":              []string{"security", "asterisk"},
				"security-severity": securitySeverity(r.Severity),
			},
		})
	}
	results := []obj{}
	for _, f := range res.Findings {
		results = append(results, obj{
			"ruleId":    f.RuleID,
			"ruleIndex": index[f.RuleID],
			"level":     sarifLevel(f.Severity),
			"message":   obj{"text": f.Message},
			"locations": []obj{{
				"physicalLocation": obj{
					"artifactLocation": obj{"uri": strings.TrimPrefix(strings.ReplaceAll(f.File, "\\", "/"), "./")},
					"region":           obj{"startLine": f.Line},
				},
			}},
		})
	}
	log := obj{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []obj{{
			"tool": obj{"driver": obj{
				"name":           "asterisk-conf-lint",
				"version":        version,
				"informationUri": informationURI,
				"rules":          ruleDefs,
			}},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// RulesMarkdown renders the rule table used in the README. The README test
// compares it with the file, so the docs cannot drift from the code.
func RulesMarkdown() string {
	var sb strings.Builder
	sb.WriteString("| Rule | Severity | File | What it catches |\n|---|---|---|---|\n")
	rs := rules.All()
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
	for _, r := range rs {
		fmt.Fprintf(&sb, "| `%s` | %s | `%s` | %s |\n", r.ID, r.Severity, r.Applies, r.Title)
	}
	return sb.String()
}

// RulesText is the --list-rules output.
func RulesText() string {
	var sb strings.Builder
	for _, r := range rules.All() {
		fmt.Fprintf(&sb, "%s  %-8s  %s\n    why: %s\n    fix: %s\n", r.ID, r.Severity, r.Title, r.Why, r.Fix)
	}
	return sb.String()
}
