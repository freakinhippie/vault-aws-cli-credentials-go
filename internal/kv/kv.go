// Package kv parses the shared, line-oriented key = value configuration syntax.
package kv

import (
	"strings"
	"unicode"
)

// SplitKeyValue normalizes keys and removes enclosing quotes and comments.
// A comment starts at an unquoted # preceded by whitespace; embedded hashes
// in tokens and URLs remain part of the value.
func SplitKeyValue(line string) (key, value string, ok bool) {
	key, value, ok = strings.Cut(line, "=")
	if !ok {
		return "", "", false
	}
	key = strings.ReplaceAll(strings.ToLower(unquote(strings.TrimSpace(key))), "-", "_")
	if key == "" {
		return "", "", false
	}
	var quote rune
	escaped := false
	previousSpace := true
	for i, r := range value {
		if escaped {
			escaped = false
		} else if quote == '"' && r == '\\' {
			escaped = true
		} else if quote != 0 {
			if r == quote {
				quote = 0
			}
		} else if r == '\'' || r == '"' {
			quote = r
		} else if r == '#' && previousSpace {
			value = value[:i]
			break
		}
		previousSpace = unicode.IsSpace(r)
	}
	if quote != 0 {
		return "", "", false
	}
	return key, unquote(strings.TrimSpace(value)), true
}

func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}
