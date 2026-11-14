package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/freakinhippie/vault-aws-cli-credentials-go/internal/subprocess"
)

// WorkerArgument is private to the parent/child protocol. Credentials travel
// over anonymous pipes, never command arguments, environment variables or files.
const WorkerArgument = "--internal-cache-worker"

const cacheOperationTimeout = 5 * time.Second

type workerRequest struct {
	Scope       string
	Operation   string
	Key         string
	Keys        []string
	Credentials CachedCredentials
}

type workerResponse struct {
	Credentials CachedCredentials
	Found       bool
	Entries     []Entry
	Removed     int
	Error       string
}

// ProcessStore isolates keyring implementations that do not support context
// cancellation. Each operation has a short deadline independent of the Vault
// request budget, so an unavailable cache cannot prevent a live credential fetch.
type ProcessStore struct {
	ctx        context.Context
	scope      string
	executable string
	args       []string
}

func NewProcessStore(ctx context.Context, scope string) (*ProcessStore, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("find cache worker executable: %w", err)
	}
	return &ProcessStore{ctx: ctx, scope: scope, executable: executable, args: []string{WorkerArgument}}, nil
}

func (s *ProcessStore) call(request workerRequest) (workerResponse, error) {
	request.Scope = s.scope
	// #nosec G117 -- Secrets are encoded only for the anonymous worker pipe.
	input, err := json.Marshal(request)
	if err != nil {
		return workerResponse{}, err
	}
	ctx, cancel := context.WithTimeout(s.ctx, cacheOperationTimeout)
	defer cancel()
	cmd := subprocess.Command(ctx, s.executable, s.args...)
	cmd.Stdin = bytes.NewReader(input)
	cmd.Env = nonInteractiveEnv(os.Environ())
	output, err := subprocess.Run(ctx, cmd, 4<<20, 1024)
	if err != nil {
		return workerResponse{}, fmt.Errorf("credential cache worker: %w", err)
	}
	var response workerResponse
	if err := json.Unmarshal(output, &response); err != nil {
		return workerResponse{}, errors.New("invalid credential cache worker response")
	}
	if response.Error != "" {
		return response, errors.New(response.Error)
	}
	return response, nil
}

func (s *ProcessStore) Load(key string) (CachedCredentials, bool, error) {
	r, err := s.call(workerRequest{Operation: "load", Key: key})
	return r.Credentials, r.Found, err
}

func (s *ProcessStore) Save(key string, credentials CachedCredentials) error {
	_, err := s.call(workerRequest{Operation: "save", Key: key, Credentials: credentials})
	return err
}

func (s *ProcessStore) ListEntries() ([]Entry, error) {
	r, err := s.call(workerRequest{Operation: "list"})
	return r.Entries, err
}

func (s *ProcessStore) PurgeKeys(keys []string) (int, error) {
	r, err := s.call(workerRequest{Operation: "purge", Keys: keys})
	return r.Removed, err
}

func (s *ProcessStore) PurgeExpired() (int, error) {
	r, err := s.call(workerRequest{Operation: "purge-expired"})
	return r.Removed, err
}

func (s *ProcessStore) PurgeAll() (int, error) {
	r, err := s.call(workerRequest{Operation: "purge-all"})
	return r.Removed, err
}

// RunWorker performs one operation in the disposable child process.
func RunWorker(input io.Reader, output io.Writer) int {
	return runWorker(input, output, newStoreWithScope)
}

func runWorker(input io.Reader, output io.Writer, open func(string) (*Store, error)) int {
	var request workerRequest
	if err := json.NewDecoder(io.LimitReader(input, 4<<20)).Decode(&request); err != nil {
		return 2
	}
	var response workerResponse
	store, err := open(request.Scope)
	if err == nil {
		switch request.Operation {
		case "load":
			response.Credentials, response.Found, err = store.Load(request.Key)
		case "save":
			err = store.Save(request.Key, request.Credentials)
		case "list":
			response.Entries, err = store.ListEntries()
		case "purge":
			response.Removed, err = store.PurgeKeys(request.Keys)
		case "purge-expired":
			response.Removed, err = store.PurgeExpired()
		case "purge-all":
			response.Removed, err = store.PurgeAll()
		default:
			err = errors.New("unknown credential cache operation")
		}
	}
	if err != nil {
		response.Error = err.Error()
	}
	// #nosec G117 -- The response is sent to the parent over an anonymous pipe.
	if err := json.NewEncoder(output).Encode(response); err != nil {
		return 2
	}
	return 0
}

func nonInteractiveEnv(env []string) []string {
	// Appending prevents GPG from opening a pinentry prompt. An already
	// unlocked agent continues to work. pass also supports user extensions;
	// disable those for these fixed cache operations.
	values := map[string]string{}
	for _, entry := range env {
		for i := 0; i < len(entry); i++ {
			if entry[i] == '=' {
				values[entry[:i]] = entry[i+1:]
				break
			}
		}
	}
	values["PASSWORD_STORE_GPG_OPTS"] += " --batch --no-tty --pinentry-mode error"
	values["PASSWORD_STORE_ENABLE_EXTENSIONS"] = "false"
	result := make([]string, 0, len(values))
	for key, value := range values {
		result = append(result, key+"="+value)
	}
	return result
}
