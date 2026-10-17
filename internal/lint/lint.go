// Package lint finds configuration files, runs the rules over them and
// applies "; lint-ignore:" comments.
package lint

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ErenOzgu/asterisk-conf-lint/internal/conf"
	"github.com/ErenOzgu/asterisk-conf-lint/internal/rules"
)

// Options controls a run.
type Options struct {
	Rules      rules.Options
	Disabled   map[string]bool
	MinSeverty rules.Severity // findings below this level are dropped
}

// Result is the outcome of a run.
type Result struct {
	Files      int
	Findings   []rules.Finding
	Suppressed int
}

// Run lints the given files and directories. A directory is searched
// recursively for *.conf files.
func Run(paths []string, opts Options) (*Result, error) {
	var files []*conf.File
	for _, p := range paths {
		found, err := collect(p)
		if err != nil {
			return nil, err
		}
		files = append(files, found...)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no .conf files found in %s", strings.Join(paths, ", "))
	}

	res := &Result{Files: len(files)}
	all := rules.Run(files, opts.Rules, opts.Disabled)
	ignores := map[string][]conf.Ignore{}
	for _, f := range files {
		ignores[f.Path] = f.Ignores
	}
	for _, fd := range all {
		if fd.Severity < opts.MinSeverty {
			continue
		}
		if suppressed(fd, ignores[fd.File]) {
			res.Suppressed++
			continue
		}
		res.Findings = append(res.Findings, fd)
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	return res, nil
}

// suppressed reports whether an ignore comment covers the finding: on the
// same line, on the line right above it, or file-wide.
func suppressed(fd rules.Finding, ignores []conf.Ignore) bool {
	for _, ig := range ignores {
		if !ig.File && ig.Line != fd.Line && ig.Line != fd.Line-1 {
			continue
		}
		for _, r := range ig.Rules {
			if r == "*" || r == fd.RuleID {
				return true
			}
		}
	}
	return false
}

// notAsteriskFormat lists files in /etc/asterisk that end in .conf but are
// not in Asterisk's configuration format.
var notAsteriskFormat = map[string]bool{
	"ast_debug_tools.conf": true, // sourced by bash
	"dbsep.conf":           true, // read by a Perl CGI script, "#" comments
}

func collect(path string) ([]*conf.File, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		f, err := load(path)
		if err != nil {
			return nil, err
		}
		return []*conf.File{f}, nil
	}
	var out []*conf.File
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".conf") || notAsteriskFormat[strings.ToLower(d.Name())] {
			return nil
		}
		f, err := load(p)
		if err != nil {
			return err
		}
		out = append(out, f)
		return nil
	})
	return out, err
}

func load(path string) (*conf.File, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	f, err := conf.Parse(path, fh)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if st, err := fh.Stat(); err == nil {
		f.Mode, f.HasMode = st.Mode(), true
	}
	return f, nil
}
