package conf

import "strings"

// Effective is a section's options after template inheritance. Options of a
// template come first, the section's own options last, so for single-valued
// keys the last value is the one Asterisk uses.
type Effective struct {
	Section *Section
	Options []Option
}

// Get returns the last value of key (case-insensitive).
func (e Effective) Get(key string) (Option, bool) {
	for i := len(e.Options) - 1; i >= 0; i-- {
		if strings.EqualFold(e.Options[i].Key, key) {
			return e.Options[i], true
		}
	}
	return Option{}, false
}

// Value is Get without the option: "" when the key is absent.
func (e Effective) Value(key string) string {
	o, _ := e.Get(key)
	return o.Value
}

// All returns every occurrence of key, in order.
func (e Effective) All(key string) []Option {
	var out []Option
	for _, o := range e.Options {
		if strings.EqualFold(o.Key, key) {
			out = append(out, o)
		}
	}
	return out
}

// Index finds sections by name across all files of a lint run, so a section
// can inherit from a template defined in another file.
type Index struct {
	byName map[string][]*Section
}

// NewIndex builds an Index over the given files.
func NewIndex(files []*File) *Index {
	ix := &Index{byName: map[string][]*Section{}}
	for _, f := range files {
		for _, s := range f.Sections {
			ix.byName[s.Name] = append(ix.byName[s.Name], s)
		}
	}
	return ix
}

// Resolve returns the effective options of s, following templates. A cycle
// or a missing template is ignored, not an error: Asterisk would complain
// itself and the linter's job is the rest of the file.
func (ix *Index) Resolve(s *Section) Effective {
	var opts []Option
	seen := map[*Section]bool{}
	var walk func(*Section)
	walk = func(sec *Section) {
		if seen[sec] {
			return
		}
		seen[sec] = true
		for _, t := range sec.Templates {
			for _, ts := range ix.byName[t] {
				if ts.IsTemplate {
					walk(ts)
				}
			}
		}
		opts = append(opts, sec.Options...)
	}
	walk(s)
	return Effective{Section: s, Options: opts}
}
