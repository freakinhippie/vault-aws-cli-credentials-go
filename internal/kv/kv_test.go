package kv

import "testing"

func TestSplitKeyValue(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		line, key, value string
		ok               bool
	}{
		{`vault-capath = "/etc/ssl/certs" # note`, "vault_capath", "/etc/ssl/certs", true},
		{`"TTL" = '90s'`, "ttl", "90s", true},
		{`vault_token = secret#suffix`, "vault_token", "secret#suffix", true},
		{`vault_token = "secret # suffix"`, "vault_token", "secret # suffix", true},
		{`token_helper = "C:\Users\name\helper.exe"`, "token_helper", `C:\Users\name\helper.exe`, true},
		{`token_helper = "helper --name=app"`, "token_helper", "helper --name=app", true},
		{`role = ""`, "role", "", true},
		{`role = # empty`, "role", "", true},
		{`role = "unterminated`, "", "", false},
		{`role`, "", "", false},
		{` = value`, "", "", false},
	} {
		t.Run(tc.line, func(t *testing.T) {
			key, value, ok := SplitKeyValue(tc.line)
			if key != tc.key || value != tc.value || ok != tc.ok {
				t.Fatalf("got (%q,%q,%v), want (%q,%q,%v)", key, value, ok, tc.key, tc.value, tc.ok)
			}
		})
	}
}
