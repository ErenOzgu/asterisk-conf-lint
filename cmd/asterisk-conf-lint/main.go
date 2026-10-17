// Command asterisk-conf-lint checks Asterisk configuration files for common
// security mistakes.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ErenOzgu/asterisk-conf-lint/internal/lint"
	"github.com/ErenOzgu/asterisk-conf-lint/internal/report"
	"github.com/ErenOzgu/asterisk-conf-lint/internal/rules"
)

// version is set at build time: -ldflags "-X main.version=1.2.3".
var version = "dev"

const usage = `usage: asterisk-conf-lint [flags] <file-or-directory>...

Checks Asterisk configuration files (manager.conf, pjsip.conf, sip.conf,
rtp.conf, http.conf, ari.conf, modules.conf, extensions.conf, ...) for
common security mistakes. A directory is searched recursively for *.conf.

Exit status: 0 nothing at or above --fail-on, 1 findings, 2 usage or I/O error.

flags:
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("asterisk-conf-lint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
	}
	var (
		format     = fs.String("format", "text", "Output format: text, json, sarif (with -list-rules: text, markdown).")
		failOn     = fs.String("fail-on", "medium", "Exit 1 when a finding is at least this severe: info, low, medium, high, critical, or none.")
		minSev     = fs.String("min-severity", "info", "Do not show findings below this severity.")
		disable    = fs.String("disable", "", "Comma-separated rule IDs to switch off, e.g. AMI-004,SIP-005.")
		checkPerms = fs.Bool("check-perms", false, "Also report world-readable files that contain secrets (CFG-003).")
		noColor    = fs.Bool("no-color", false, "Never use colour in text output (NO_COLOR is honoured too).")
		listRules  = fs.Bool("list-rules", false, "Print the rules and exit.")
		showVer    = fs.Bool("version", false, "Print the version and exit.")
	)
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *showVer {
		fmt.Fprintln(stdout, "asterisk-conf-lint", version)
		return 0
	}
	if *listRules {
		switch *format {
		case "text":
			fmt.Fprint(stdout, report.RulesText())
		case "markdown":
			fmt.Fprint(stdout, report.RulesMarkdown())
		default:
			fmt.Fprintf(stderr, "-list-rules supports -format text or markdown, not %q\n", *format)
			return 2
		}
		return 0
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return 2
	}

	failSev, failEnabled := rules.Info, true
	if strings.EqualFold(*failOn, "none") {
		failEnabled = false
	} else if s, ok := rules.ParseSeverity(*failOn); ok {
		failSev = s
	} else {
		fmt.Fprintf(stderr, "unknown -fail-on value %q\n", *failOn)
		return 2
	}
	min, ok := rules.ParseSeverity(*minSev)
	if !ok {
		fmt.Fprintf(stderr, "unknown -min-severity value %q\n", *minSev)
		return 2
	}
	disabled := map[string]bool{}
	for _, id := range strings.Split(*disable, ",") {
		if id = strings.ToUpper(strings.TrimSpace(id)); id != "" {
			if _, ok := rules.Lookup(id); !ok {
				fmt.Fprintf(stderr, "unknown rule %q in -disable (see -list-rules)\n", id)
				return 2
			}
			disabled[id] = true
		}
	}

	res, err := lint.Run(fs.Args(), lint.Options{
		Rules:      rules.Options{CheckPerms: *checkPerms},
		Disabled:   disabled,
		MinSeverty: min,
	})
	if err != nil {
		fmt.Fprintln(stderr, "asterisk-conf-lint:", err)
		return 2
	}

	switch *format {
	case "text":
		color := !*noColor && os.Getenv("NO_COLOR") == "" && isTerminal(stdout)
		report.Text(stdout, res, color)
	case "json":
		err = report.JSON(stdout, res)
	case "sarif":
		err = report.SARIF(stdout, res, version)
	default:
		fmt.Fprintf(stderr, "unknown -format value %q\n", *format)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "asterisk-conf-lint:", err)
		return 2
	}

	if failEnabled {
		for _, f := range res.Findings {
			if f.Severity >= failSev {
				return 1
			}
		}
	}
	return 0
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
