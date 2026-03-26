package awscred

import "encoding/json"

type ProcessOutput struct {
	Version         int     `json:"Version"`
	AccessKeyID     string  `json:"AccessKeyId"`
	SecretAccessKey string  `json:"SecretAccessKey"`
	SessionToken    string  `json:"SessionToken,omitempty"`
	Expiration      *string `json:"Expiration,omitempty"`
}

func (p ProcessOutput) JSON() ([]byte, error) {
	if p.Version == 0 {
		p.Version = 1
	}
	// #nosec G117 -- Emitting credential_process JSON to stdout is the CLI's primary contract with AWS tooling.
	return json.Marshal(p)
}
