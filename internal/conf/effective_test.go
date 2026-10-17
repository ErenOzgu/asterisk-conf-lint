package conf

import "testing"

func TestEffectiveInheritance(t *testing.T) {
	f := parse(t, `
[base](!)
type = endpoint
allow = ulaw
context = default

[mid](!,base)
allow = alaw

[ep](mid)
context = internal
`)
	ix := NewIndex([]*File{f})
	e := ix.Resolve(f.Sections[2])
	if got := e.Value("context"); got != "internal" {
		t.Errorf("own option must win, got %q", got)
	}
	if got := e.Value("TYPE"); got != "endpoint" {
		t.Errorf("inherited option (case-insensitive key) = %q", got)
	}
	if got := e.All("allow"); len(got) != 2 || got[0].Value != "ulaw" || got[1].Value != "alaw" {
		t.Errorf("repeated keys keep template order: %+v", got)
	}
	if _, ok := e.Get("missing"); ok {
		t.Error("Get on a missing key must report false")
	}
}

func TestEffectiveAcrossFilesAndCycles(t *testing.T) {
	a := parse(t, "[loop1](!,loop2)\nx = 1\n[user](shared)\ny = 2\n")
	b, err := Parse("b.conf", stringsReader("[shared](!)\nsecret = abc\n[loop2](!,loop1)\nz = 3\n"))
	if err != nil {
		t.Fatal(err)
	}
	ix := NewIndex([]*File{a, b})
	if got := ix.Resolve(a.Sections[1]).Value("secret"); got != "abc" {
		t.Errorf("template from another file: secret = %q", got)
	}
	// A cycle must terminate and still return the own options.
	if got := ix.Resolve(a.Sections[0]).Value("x"); got != "1" {
		t.Errorf("cycle: x = %q", got)
	}
}

func TestMissingAndNonTemplateParents(t *testing.T) {
	f := parse(t, "[real]\nk = from-real\n[child](real, nothere)\nown = 1\n")
	e := NewIndex([]*File{f}).Resolve(f.Sections[1])
	if _, ok := e.Get("k"); ok {
		t.Error("a section that is not a template must not be inherited from")
	}
	if e.Value("own") != "1" {
		t.Error("own option lost")
	}
}
