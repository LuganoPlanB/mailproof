package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func PublishAnalysis(root, runID string, evidence []Evidence, verdict Verdict) error {
	dir := filepath.Join(root, "runs", runID, "analysis")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create analysis directory: %w", err)
	}
	eb, err := json.Marshal(evidence)
	if err != nil {
		return fmt.Errorf("marshal evidence: %w", err)
	}
	vb, err := json.Marshal(verdict)
	if err != nil {
		return fmt.Errorf("marshal verdict: %w", err)
	}
	if err := publish(dir, "evidence.json", eb); err != nil {
		return err
	}
	return publish(dir, "verdict.json", vb)
}
func publish(dir, name string, b []byte) error {
	target := filepath.Join(dir, name)
	if _, err := os.Stat(target); err == nil {
		return fmt.Errorf("refuse overwrite %s", name)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	f, err := os.CreateTemp(dir, "."+name+"-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o440); err != nil {
		_ = f.Close()
		return fmt.Errorf("set permissions for %s: %w", name, err)
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := os.Link(tmp, target); err != nil {
		return fmt.Errorf("publish %s: %w", name, err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open analysis directory: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync analysis directory: %w", err)
	}
	return nil
}
func Digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
