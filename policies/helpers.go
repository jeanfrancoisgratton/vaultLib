// vaultlib
// Written by J.F.Gratton <jean-francois@famillegratton.net>
// Original filename: policies/helpers.go
// Original timestamp: 2026/06/21 17:10:49

package policies

import "strings"

// RuleLines splits Rules into individual lines for display purposes — e.g.
// table cells, log output, or anywhere a single embedded-newline string
// renders poorly.
//
// This is a display convenience only. It does no HCL/JSON parsing and has
// no notion of path blocks, capabilities, or Vault's policy grammar; it
// does not tell you what a policy grants, only how to lay its raw text out
// one line at a time. Rules remains the canonical, wire-faithful
// representation (and the one CreatePolicy expects back). Callers needing
// real structural or access-decision information should treat Rules as the
// source of truth and consult Vault itself rather than this method.
//
// RuleLines returns nil if Rules is empty. A single trailing newline (or
// CRLF) is trimmed so callers don't get a spurious empty final line; any
// CR left at the end of interior lines (CRLF-authored documents) is also
// stripped.
func (p *Policy) RuleLines() []string {
	if p == nil || p.Rules == "" {
		return nil
	}

	trimmed := strings.TrimRight(p.Rules, "\r\n")
	lines := strings.Split(trimmed, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSuffix(line, "\r")
	}
	return lines
}
