package conf

import (
	"strings"
	"testing"
)

func parse(t *testing.T, text string) *File {
	t.Helper()
	f, err := Parse("test.conf", strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestSectionsAndOptions(t *testing.T) {
	f := parse(t, "[general]\nenabled = yes\nbindaddr=127.0.0.1\n\n[user]\nsecret => s3cret\npermit = 10.0.0.0/8\npermit = 127.0.0.1/32\n")
	if len(f.Sections) != 2 {
		t.Fatalf("sections = %d", len(f.Sections))
	}
	g := f.Sections[0]
	if g.Name != "general" || g.Line != 1 || len(g.Options) != 2 {
		t.Fatalf("general = %+v", g)
	}
	if o := g.Options[1]; o.Key != "bindaddr" || o.Value != "127.0.0.1" || o.Line != 3 || o.Op != "=" {
		t.Errorf("bindaddr option = %+v", o)
	}
	u := f.Sections[1]
	if o := u.Options[0]; o.Key != "secret" || o.Value != "s3cret" || o.Op != "=>" {
		t.Errorf("=> option = %+v", o)
	}
	if len(u.Options) != 3 {
		t.Errorf("repeated keys must all be kept, got %d options", len(u.Options))
	}
}

func TestCommentsAndEscapes(t *testing.T) {
	f := parse(t, strings.Join([]string{
		"; whole line comment",
		"[a] ; trailing comment on a header",
		"k1 = v1 ; trailing comment",
		`k2 = a\;b`,
		"k3 = x ;-- inline block --; y",
		";-- block starts",
		"hidden = yes",
		"still hidden = yes",
		"--; k4 = v4",
		"k5 = v5",
	}, "\n"))
	s := f.Sections[0]
	got := map[string]string{}
	for _, o := range s.Options {
		got[o.Key] = o.Value
	}
	want := map[string]string{"k1": "v1", "k2": "a;b", "k3": "x  y", "k4": "v4", "k5": "v5"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["hidden"]; ok {
		t.Error("an option inside a block comment was parsed")
	}
	if len(f.Bad) != 0 {
		t.Errorf("unexpected bad lines: %+v", f.Bad)
	}
}

func TestTemplates(t *testing.T) {
	f := parse(t, "[base](!)\nx = 1\n[mid](!,base)\ny = 2\n[leaf](mid, other)\nz = 3\n[plain]\n")
	base, mid, leaf, plain := f.Sections[0], f.Sections[1], f.Sections[2], f.Sections[3]
	if !base.IsTemplate || len(base.Templates) != 0 {
		t.Errorf("base = %+v", base)
	}
	if !mid.IsTemplate || len(mid.Templates) != 1 || mid.Templates[0] != "base" {
		t.Errorf("mid = %+v", mid)
	}
	if leaf.IsTemplate || len(leaf.Templates) != 2 || leaf.Templates[1] != "other" {
		t.Errorf("leaf = %+v", leaf)
	}
	if plain.IsTemplate || len(plain.Templates) != 0 {
		t.Errorf("plain = %+v", plain)
	}
}

func TestDirectives(t *testing.T) {
	f := parse(t, "#include \"manager.d/*.conf\"\n#tryinclude <extra.conf>\n#exec \"/bin/true\"\n[a]\nk=v\n")
	if len(f.Directives) != 3 {
		t.Fatalf("directives = %+v", f.Directives)
	}
	want := []Directive{{"include", "manager.d/*.conf", 1}, {"tryinclude", "extra.conf", 2}, {"exec", "/bin/true", 3}}
	for i, d := range want {
		if f.Directives[i] != d {
			t.Errorf("directive %d = %+v, want %+v", i, f.Directives[i], d)
		}
	}
}

func TestKeysMayContainSpaces(t *testing.T) {
	// cli_aliases.conf in a stock Asterisk install does this.
	f := parse(t, "[general]\nshow channeltypes=core show channeltypes\n")
	if len(f.Bad) != 0 || f.Sections[0].Options[0].Key != "show channeltypes" {
		t.Errorf("got %+v bad=%+v", f.Sections[0].Options, f.Bad)
	}
}

func TestBadLinesAreCollected(t *testing.T) {
	f := parse(t, "[a]\nok = 1\nthis is nonsense\n[broken\n#bogus directive\nafter = still parsed\n")
	if len(f.Bad) != 3 {
		t.Fatalf("bad = %+v", f.Bad)
	}
	if f.Bad[0].Line != 3 || f.Bad[1].Line != 4 || f.Bad[2].Line != 5 {
		t.Errorf("bad lines = %+v", f.Bad)
	}
	if o := f.Sections[0].Options; len(o) != 2 || o[1].Key != "after" {
		t.Errorf("parsing must go on after a bad line, got %+v", o)
	}
}

func TestPreambleBeforeFirstSection(t *testing.T) {
	f := parse(t, "orphan = 1\n[a]\nk = v\n")
	if len(f.Preamble) != 1 || f.Preamble[0].Key != "orphan" {
		t.Errorf("preamble = %+v", f.Preamble)
	}
}

func TestCRLFAndLongLines(t *testing.T) {
	long := strings.Repeat("x", 200_000)
	f := parse(t, "[a]\r\nk = v\r\nbig = "+long+"\r\n")
	if f.Sections[0].Options[0].Value != "v" {
		t.Errorf("CRLF value = %q", f.Sections[0].Options[0].Value)
	}
	if len(f.Sections[0].Options[1].Value) != len(long) {
		t.Error("long line truncated")
	}
}

func TestIgnoreComments(t *testing.T) {
	f := parse(t, "; lint-ignore: ami-003, AMI-002 lab machine\n[a]\nk = v ; lint-ignore: *\n; lint-ignore-file: SIP-005\n; lint-ignore: not a rule id\n")
	if len(f.Ignores) != 4 {
		t.Fatalf("ignores = %+v", f.Ignores)
	}
	if ig := f.Ignores[0]; ig.Line != 1 || ig.File || len(ig.Rules) != 2 || ig.Rules[0] != "AMI-003" || ig.Rules[1] != "AMI-002" {
		t.Errorf("first ignore = %+v", ig)
	}
	if ig := f.Ignores[1]; ig.Line != 3 || len(ig.Rules) != 1 || ig.Rules[0] != "*" {
		t.Errorf("second ignore = %+v", ig)
	}
	if ig := f.Ignores[2]; !ig.File || ig.Rules[0] != "SIP-005" {
		t.Errorf("third ignore = %+v", ig)
	}
	if ig := f.Ignores[3]; len(ig.Rules) != 0 {
		t.Errorf("free text must not become a rule: %+v", ig)
	}
}

func stringsReader(s string) *strings.Reader { return strings.NewReader(s) }
