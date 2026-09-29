// Package redact keeps secret-shaped values out of anything signet prints.
//
// It is its own leaf package because more than one place needs it: input
// validation in internal/link echoes a mistyped value back, and signing in
// internal/keys passes `stellar`'s stderr through. Both end up in a terminal,
// a CI log, and a pasted bug report.
package redact

import "regexp"

// secretPattern matches a Stellar StrKey secret seed.
var secretPattern = regexp.MustCompile(`\bS[A-Z2-7]{55}\b`)

// Placeholder is what a secret-shaped value is replaced with.
const Placeholder = "[redacted: secret-shaped value]"

// Secrets replaces anything shaped like a Stellar secret seed in value.
//
// Echoing a value back is genuinely useful — it is how someone spots a typo,
// and `stellar`'s own stderr is usually the actionable part of a signing
// failure — so the rest of the text is kept, unless showing it would disclose
// a key.
func Secrets(value string) string {
	return secretPattern.ReplaceAllString(value, Placeholder)
}
