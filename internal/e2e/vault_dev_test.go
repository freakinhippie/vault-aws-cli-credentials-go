//go:build integration

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestVaultCredsWithVaultDevSTS(t *testing.T) {
	if _, err := exec.LookPath("vault"); err != nil {
		t.Skip("vault binary not found")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go binary not found")
	}

	aws := newAWSMockServer()
	defer aws.Close()

	port, err := freePort()
	if err != nil {
		t.Fatalf("allocate port: %v", err)
	}
	addr := fmt.Sprintf("http://127.0.0.1:%d", port)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	vaultCmd := exec.CommandContext(ctx, "vault", "server", "-dev", "-dev-root-token-id=root", "-dev-listen-address=127.0.0.1:"+fmt.Sprint(port))
	vaultCmd.Env = append(os.Environ(), "VAULT_ADDR="+addr)
	vaultOut, err := os.CreateTemp(t.TempDir(), "vault-dev-*.log")
	if err != nil {
		t.Fatalf("create vault log: %v", err)
	}
	defer vaultOut.Close()
	vaultCmd.Stdout = vaultOut
	vaultCmd.Stderr = vaultOut
	if err := vaultCmd.Start(); err != nil {
		t.Fatalf("start vault dev server: %v", err)
	}
	defer func() {
		cancel()
		_ = vaultCmd.Wait()
	}()

	waitForVault(t, addr)

	runVault(t, addr, "secrets", "enable", "-path=aws", "aws")
	configureAWSRoot(t, addr, aws.URL(), aws.URL())
	runVault(t, addr,
		"write", "aws/roles/dev-role",
		"credential_type=federation_token",
		"policy_document={\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}",
	)

	repoRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	repoRoot = filepath.Clean(filepath.Join(repoRoot, "..", ".."))

	cmd := exec.Command("go", "run", "./cmd/vaultcreds", "--mount=aws", "--role=dev-role", "--type=sts")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"VAULT_ADDR="+addr,
		"VAULT_TOKEN=root",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run vaultcreds: %v\noutput: %s", err, string(out))
	}

	var payload map[string]any
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("parse vaultcreds output: %v\noutput: %s", err, string(out))
	}
	if payload["AccessKeyId"] == "" || payload["SecretAccessKey"] == "" || payload["SessionToken"] == "" {
		t.Fatalf("missing credentials in output: %#v", payload)
	}

	if aws.ActionCount("GetFederationToken") == 0 && aws.ActionCount("AssumeRole") == 0 {
		t.Fatalf("mock STS never received credential issuance action; counts=%v", aws.Counts())
	}
}

func TestVaultCredsWithVaultDevCreds(t *testing.T) {
	if _, err := exec.LookPath("vault"); err != nil {
		t.Skip("vault binary not found")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go binary not found")
	}

	aws := newAWSMockServer()
	defer aws.Close()

	port, err := freePort()
	if err != nil {
		t.Fatalf("allocate port: %v", err)
	}
	addr := fmt.Sprintf("http://127.0.0.1:%d", port)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	vaultCmd := exec.CommandContext(ctx, "vault", "server", "-dev", "-dev-root-token-id=root", "-dev-listen-address=127.0.0.1:"+fmt.Sprint(port))
	vaultCmd.Env = append(os.Environ(), "VAULT_ADDR="+addr)
	vaultOut, err := os.CreateTemp(t.TempDir(), "vault-dev-*.log")
	if err != nil {
		t.Fatalf("create vault log: %v", err)
	}
	defer vaultOut.Close()
	vaultCmd.Stdout = vaultOut
	vaultCmd.Stderr = vaultOut
	if err := vaultCmd.Start(); err != nil {
		t.Fatalf("start vault dev server: %v", err)
	}
	defer func() {
		cancel()
		_ = vaultCmd.Wait()
	}()

	waitForVault(t, addr)

	runVault(t, addr, "secrets", "enable", "-path=aws", "aws")
	configureAWSRoot(t, addr, aws.URL(), aws.URL())
	runVault(t, addr,
		"write", "aws/roles/dev-creds-role",
		"credential_type=iam_user",
		"policy_document={\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}",
	)

	repoRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	repoRoot = filepath.Clean(filepath.Join(repoRoot, "..", ".."))

	cmd := exec.Command("go", "run", "./cmd/vaultcreds", "--mount=aws", "--role=dev-creds-role", "--type=creds")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"VAULT_ADDR="+addr,
		"VAULT_TOKEN=root",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run vaultcreds: %v\noutput: %s", err, string(out))
	}

	var payload map[string]any
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("parse vaultcreds output: %v\noutput: %s", err, string(out))
	}
	if payload["AccessKeyId"] == "" || payload["SecretAccessKey"] == "" {
		t.Fatalf("missing credentials in output: %#v", payload)
	}
	if sessionToken, ok := payload["SessionToken"]; ok && sessionToken != "" {
		t.Fatalf("expected creds type to omit session token, got: %#v", payload)
	}

	if aws.ActionCount("CreateAccessKey") == 0 {
		t.Fatalf("mock IAM never received CreateAccessKey; counts=%v", aws.Counts())
	}
}

func TestVaultCredsWithVaultConfigTLSSTS(t *testing.T) {
	if _, err := exec.LookPath("vault"); err != nil {
		t.Skip("vault binary not found")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go binary not found")
	}

	aws := newAWSMockServer()
	defer aws.Close()

	addr, cacert, stop := startVaultDev(t, true)
	defer stop()

	runVault(t, addr, "secrets", "enable", "-path=aws", "aws")
	configureAWSRoot(t, addr, aws.URL(), aws.URL())
	runVault(t, addr,
		"write", "aws/roles/tls-sts-role",
		"credential_type=federation_token",
		"policy_document={\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}",
	)

	repoRoot := repoRoot(t)
	cfgPath := writeVaultCredsConfig(t, t.TempDir(), strings.Join([]string{
		"vault_addr = \"" + addr + "\"",
		"vault_cacert = \"" + cacert + "\"",
		"vault_token = \"root\"",
		"mount = \"aws\"",
		"role = \"tls-sts-role\"",
		"credential_type = \"sts\"",
		"ttl = \"1h\"",
	}, "\n")+"\n")

	cmd := exec.Command("go", "run", "./cmd/vaultcreds", "--config", cfgPath)
	cmd.Dir = repoRoot
	cmd.Env = cleanVaultCredsEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run vaultcreds tls sts: %v\noutput: %s", err, string(out))
	}

	var payload map[string]any
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("parse vaultcreds output: %v\noutput: %s", err, string(out))
	}
	if payload["AccessKeyId"] == "" || payload["SecretAccessKey"] == "" || payload["SessionToken"] == "" {
		t.Fatalf("missing credentials in output: %#v", payload)
	}
	if aws.ActionCount("GetFederationToken") == 0 && aws.ActionCount("AssumeRole") == 0 {
		t.Fatalf("mock STS never received credential issuance action; counts=%v", aws.Counts())
	}
}

func TestVaultCredsWithVaultConfigTLSCreds(t *testing.T) {
	if _, err := exec.LookPath("vault"); err != nil {
		t.Skip("vault binary not found")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go binary not found")
	}

	aws := newAWSMockServer()
	defer aws.Close()

	addr, cacert, stop := startVaultDev(t, true)
	defer stop()

	runVault(t, addr, "secrets", "enable", "-path=aws", "aws")
	configureAWSRoot(t, addr, aws.URL(), aws.URL())
	runVault(t, addr,
		"write", "aws/roles/tls-creds-role",
		"credential_type=iam_user",
		"policy_document={\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}",
	)

	repoRoot := repoRoot(t)
	cfgPath := writeVaultCredsConfig(t, t.TempDir(), strings.Join([]string{
		"vault_addr = \"" + addr + "\"",
		"vault_cacert = \"" + cacert + "\"",
		"vault_token = \"root\"",
		"mount = \"aws\"",
		"role = \"tls-creds-role\"",
		"credential_type = \"creds\"",
	}, "\n")+"\n")

	cmd := exec.Command("go", "run", "./cmd/vaultcreds", "--config", cfgPath)
	cmd.Dir = repoRoot
	cmd.Env = cleanVaultCredsEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run vaultcreds tls creds: %v\noutput: %s", err, string(out))
	}

	var payload map[string]any
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("parse vaultcreds output: %v\noutput: %s", err, string(out))
	}
	if payload["AccessKeyId"] == "" || payload["SecretAccessKey"] == "" {
		t.Fatalf("missing credentials in output: %#v", payload)
	}
	if sessionToken, ok := payload["SessionToken"]; ok && sessionToken != "" {
		t.Fatalf("expected creds type to omit session token, got: %#v", payload)
	}
	if aws.ActionCount("CreateAccessKey") == 0 {
		t.Fatalf("mock IAM never received CreateAccessKey; counts=%v", aws.Counts())
	}
}

func configureAWSRoot(t *testing.T, vaultAddr, stsEndpoint, iamEndpoint string) {
	t.Helper()

	attempts := [][]string{
		{
			"write", "aws/config/root",
			"access_key=test",
			"secret_key=test",
			"region=us-east-1",
			"sts_endpoint=" + stsEndpoint,
			"iam_endpoint=" + iamEndpoint,
			"skip_creds_validation=true",
			"skip_requesting_account_id=true",
		},
		{
			"write", "aws/config/root",
			"access_key=test",
			"secret_key=test",
			"region=us-east-1",
			"sts_endpoint=" + stsEndpoint,
			"iam_endpoint=" + iamEndpoint,
			"skip_creds_validation=true",
		},
		{
			"write", "aws/config/root",
			"access_key=test",
			"secret_key=test",
			"region=us-east-1",
			"sts_endpoint=" + stsEndpoint,
			"iam_endpoint=" + iamEndpoint,
		},
	}

	var lastErr error
	for _, args := range attempts {
		if _, err := runVaultWithOutput(vaultAddr, args...); err == nil {
			return
		} else {
			lastErr = err
		}
	}
	if lastErr != nil {
		t.Fatalf("configure aws root failed: %v", lastErr)
	}
}

func runVault(t *testing.T, addr string, args ...string) {
	t.Helper()
	out, err := runVaultWithOutput(addr, args...)
	if err != nil {
		t.Fatalf("vault %s failed: %v\noutput: %s", strings.Join(args, " "), err, out)
	}
}

func runVaultWithOutput(addr string, args ...string) (string, error) {
	cmd := exec.Command("vault", args...)
	cmd.Env = append(os.Environ(), "VAULT_ADDR="+addr, "VAULT_TOKEN=root", "VAULT_SKIP_VERIFY=true")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func waitForVault(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		cmd := exec.Command("vault", "status", "-address="+addr)
		cmd.Env = append(os.Environ(), "VAULT_ADDR="+addr, "VAULT_SKIP_VERIFY=true")
		if err := cmd.Run(); err == nil {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("vault did not become ready at %s", addr)
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func startVaultDev(t *testing.T, withTLS bool) (string, string, func()) {
	t.Helper()

	port, err := freePort()
	if err != nil {
		t.Fatalf("allocate port: %v", err)
	}

	scheme := "http"
	args := []string{
		"server",
		"-dev",
		"-dev-root-token-id=root",
		"-dev-listen-address=127.0.0.1:" + fmt.Sprint(port),
	}
	var cacert string
	if withTLS {
		scheme = "https"
		certDir := t.TempDir()
		args = append(args, "-dev-tls", "-dev-tls-cert-dir="+certDir)
		cacert = filepath.Join(certDir, "vault-ca.pem")
	}

	addr := fmt.Sprintf("%s://127.0.0.1:%d", scheme, port)
	ctx, cancel := context.WithCancel(t.Context())
	vaultCmd := exec.CommandContext(ctx, "vault", args...)
	vaultCmd.Env = append(os.Environ(), "VAULT_ADDR="+addr)
	vaultOut, err := os.CreateTemp(t.TempDir(), "vault-dev-*.log")
	if err != nil {
		t.Fatalf("create vault log: %v", err)
	}
	vaultCmd.Stdout = vaultOut
	vaultCmd.Stderr = vaultOut
	if err := vaultCmd.Start(); err != nil {
		t.Fatalf("start vault dev server: %v", err)
	}

	waitForVault(t, addr)
	return addr, cacert, func() {
		cancel()
		_ = vaultCmd.Wait()
		_ = vaultOut.Close()
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	return filepath.Clean(filepath.Join(root, "..", ".."))
}

func writeVaultCredsConfig(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "vaultcreds.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	return path
}

func cleanVaultCredsEnv() []string {
	env := os.Environ()
	out := make([]string, 0, len(env))
	for _, kv := range env {
		switch {
		case strings.HasPrefix(kv, "VAULT_"):
		case strings.HasPrefix(kv, "VAULTCREDS_"):
		default:
			out = append(out, kv)
		}
	}
	return out
}

type awsMock struct {
	server *httptest.Server
	mu     sync.Mutex
	counts map[string]int
}

func newAWSMockServer() *awsMock {
	m := &awsMock{counts: map[string]int{}}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		action := r.FormValue("Action")
		if action == "" {
			action = r.URL.Query().Get("Action")
		}
		m.mu.Lock()
		m.counts[action]++
		m.mu.Unlock()

		w.Header().Set("Content-Type", "text/xml")
		switch action {
		case "GetCallerIdentity":
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::111122223333:user/test</Arn>
    <UserId>FAKEUSERID</UserId>
    <Account>111122223333</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata><RequestId>mock-request</RequestId></ResponseMetadata>
</GetCallerIdentityResponse>`))
		case "GetFederationToken":
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<GetFederationTokenResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetFederationTokenResult>
    <Credentials>
      <AccessKeyId>ASIAFAKEACCESSKEY</AccessKeyId>
      <SecretAccessKey>fakeSecretAccessKeyForTestsOnly</SecretAccessKey>
      <SessionToken>fakeSessionTokenForTestsOnly</SessionToken>
      <Expiration>2030-01-01T00:00:00Z</Expiration>
    </Credentials>
    <FederatedUser>
      <FederatedUserId>123:dev-role</FederatedUserId>
      <Arn>arn:aws:sts::111122223333:federated-user/dev-role</Arn>
    </FederatedUser>
    <PackedPolicySize>1</PackedPolicySize>
  </GetFederationTokenResult>
  <ResponseMetadata><RequestId>mock-request</RequestId></ResponseMetadata>
</GetFederationTokenResponse>`))
		case "AssumeRole":
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIAFAKEACCESSKEY</AccessKeyId>
      <SecretAccessKey>fakeSecretAccessKeyForTestsOnly</SecretAccessKey>
      <SessionToken>fakeSessionTokenForTestsOnly</SessionToken>
      <Expiration>2030-01-01T00:00:00Z</Expiration>
    </Credentials>
    <AssumedRoleUser>
      <AssumedRoleId>AROATEST:dev-role</AssumedRoleId>
      <Arn>arn:aws:sts::111122223333:assumed-role/dev-role/test</Arn>
    </AssumedRoleUser>
  </AssumeRoleResult>
  <ResponseMetadata><RequestId>mock-request</RequestId></ResponseMetadata>
</AssumeRoleResponse>`))
		case "CreateUser":
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<CreateUserResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <CreateUserResult>
    <User>
      <Path>/</Path>
      <UserName>vault-test-user</UserName>
      <UserId>AIDATESTUSER</UserId>
      <Arn>arn:aws:iam::111122223333:user/vault-test-user</Arn>
      <CreateDate>2026-01-01T00:00:00Z</CreateDate>
    </User>
  </CreateUserResult>
  <ResponseMetadata><RequestId>mock-request</RequestId></ResponseMetadata>
</CreateUserResponse>`))
		case "PutUserPolicy", "DeleteUserPolicy", "DeleteAccessKey", "DeleteUser":
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><ResponseMetadata><RequestId>mock-request</RequestId></ResponseMetadata>`))
		case "CreateAccessKey":
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<CreateAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <CreateAccessKeyResult>
    <AccessKey>
      <UserName>vault-test-user</UserName>
      <AccessKeyId>AKIAFAKEACCESSKEY</AccessKeyId>
      <Status>Active</Status>
      <SecretAccessKey>fakeSecretAccessKeyForCredsTypeTestsOnly</SecretAccessKey>
      <CreateDate>2026-01-01T00:00:00Z</CreateDate>
    </AccessKey>
  </CreateAccessKeyResult>
  <ResponseMetadata><RequestId>mock-request</RequestId></ResponseMetadata>
</CreateAccessKeyResponse>`))
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><ErrorResponse><Error><Code>InvalidAction</Code><Message>unsupported action</Message></Error></ErrorResponse>`))
		}
	}))
	return m
}

func (m *awsMock) URL() string {
	return m.server.URL
}

func (m *awsMock) Close() {
	m.server.Close()
}

func (m *awsMock) ActionCount(action string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counts[action]
}

func (m *awsMock) Counts() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]int, len(m.counts))
	for k, v := range m.counts {
		out[k] = v
	}
	return out
}
