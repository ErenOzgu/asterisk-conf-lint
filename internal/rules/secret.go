package rules

import (
	"fmt"
	"strings"
	"unicode"
)

var commonSecrets = map[string]bool{
	"secret": true, "password": true, "passw0rd": true, "pass": true, "admin": true,
	"asterisk": true, "changeme": true, "change-me": true, "test": true, "default": true,
	"letmein": true, "qwerty": true, "welcome": true, "demo": true, "manager": true,
	"abc123": true, "1q2w3e4r": true, "password1": true, "mysecret": true, "asteriskpass": true,
	"amp111": true, "12345": true, "1234": true, "123456": true, "1234567": true,
	"12345678": true, "123456789": true, "1234567890": true, "root": true, "user": true,
}

// weakSecret judges a password or shared secret. names are the account names
// it must not equal. It returns "" when the secret looks fine, and a
// placeholder such as "${SECRET}" is never judged.
func weakSecret(secret string, names ...string) (string, Severity) {
	if secret == "" {
		return "is empty", Critical
	}
	if strings.Contains(secret, "${") || strings.Contains(secret, "{{") {
		return "", Info
	}
	lower := strings.ToLower(secret)
	if commonSecrets[lower] {
		return "is a well-known default or guess", High
	}
	for _, n := range names {
		if n != "" && lower == strings.ToLower(n) {
			return "is the same as the account name", High
		}
	}
	if repeated(secret) {
		return "is a repeated or sequential pattern", High
	}
	n := len([]rune(secret))
	switch {
	case n < 8:
		return fmt.Sprintf("has only %d characters (use at least 12)", n), High
	case n < 12:
		return fmt.Sprintf("has only %d characters (use at least 12)", n), Medium
	}
	if classes(secret) == 1 && n < 16 {
		return "uses a single kind of character (digits only, letters only)", Medium
	}
	return "", Info
}

func classes(s string) int {
	var lower, upper, digit, other bool
	for _, r := range s {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	n := 0
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			n++
		}
	}
	return n
}

// repeated is true for "aaaaaaaa" and for ascending or descending runs such
// as "abcdefgh" or "1234567890123" (digits wrap around from 9 to 0).
func repeated(s string) bool {
	r := []rune(s)
	if len(r) < 4 {
		return false
	}
	step := func(a, b rune) bool { // b follows a, going up
		if unicode.IsDigit(a) && unicode.IsDigit(b) {
			return (a-'0'+1)%10 == b-'0'
		}
		return b == a+1
	}
	same, up, down := true, true, true
	for i := 1; i < len(r); i++ {
		if r[i] != r[0] {
			same = false
		}
		if !step(r[i-1], r[i]) {
			up = false
		}
		if !step(r[i], r[i-1]) {
			down = false
		}
	}
	return same || up || down
}
