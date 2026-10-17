package rules

import "testing"

func TestWeakSecretReasons(t *testing.T) {
	cases := []struct {
		secret string
		names  []string
		sev    Severity
		bad    bool
	}{
		{"", nil, Critical, true},
		{"Password", nil, High, true},
		{"AMP111", nil, High, true},
		{"MyUser", []string{"myuser"}, High, true},
		{"abcdefgh", nil, High, true}, // ascending run
		{"zzzzzzzzzzzz", nil, High, true},
		{"short1", nil, High, true},
		{"Summer2024", nil, Medium, true},
		{"abcdefghijklmnop", nil, High, true},  // letters in order
		{"9876543210987", nil, High, true},     // digits wrap around
		{"abcdefghijklmnoq", nil, Info, false}, // one step out of line
		{"Zq7xR2mV9pLw4TnC8dYe3Ka", nil, Info, false},
		{"${SECRET}", nil, Info, false},
	}
	for _, c := range cases {
		reason, sev := weakSecret(c.secret, c.names...)
		if (reason != "") != c.bad {
			t.Errorf("%q: reason=%q, bad=%v expected", c.secret, reason, c.bad)
			continue
		}
		if c.bad && sev != c.sev {
			t.Errorf("%q: severity %v, want %v (%s)", c.secret, sev, c.sev, reason)
		}
	}
}
