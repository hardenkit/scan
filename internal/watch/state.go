package watch

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// stateVersion is the version of the state file format.
const stateVersion = 1

// State is the last result of every watched target.
type State struct {
	Version int                `json:"version"`
	Targets map[string]*Target `json:"targets"`
}

// Target is the last successful scan of one target. All findings are kept,
// not only the ones that alert, so a finding that becomes more urgent later
// can be told apart from a new one.
type Target struct {
	Checked  time.Time `json:"checked"`
	Findings []Finding `json:"findings"`
}

// DefaultStatePath is $XDG_STATE_HOME/hardenkit/watch.json, or
// ~/.local/state/hardenkit/watch.json when XDG_STATE_HOME is not set.
func DefaultStatePath() (string, error) {
	dir := os.Getenv("XDG_STATE_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(dir, "hardenkit", "watch.json"), nil
}

// Load reads the state file. A missing file is an empty state.
func Load(path string) (*State, error) {
	s := &State{Version: stateVersion, Targets: map[string]*Target{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	if s.Version != stateVersion {
		return nil, fmt.Errorf("%s: unsupported state version %d", path, s.Version)
	}
	if s.Targets == nil {
		s.Targets = map[string]*Target{}
	}
	return s, nil
}

// Save writes the state file atomically: a temporary file in the same
// directory, then a rename. The file is 0600 and a directory it has to
// create 0700.
func (s *State) Save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".watch-*.tmp") // created 0600
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after the rename
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
