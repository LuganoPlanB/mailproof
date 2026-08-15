package analyzers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luganoplanb/mailproof/internal/evidence"
)

type RevocationState string

const (
	RevocationChecked       RevocationState = "checked"
	RevocationNotChecked    RevocationState = "not_checked"
	RevocationIndeterminate RevocationState = "indeterminate"
)

// CryptoConfig names only digest-pinned, operator-mounted verification tools
// and read-only trust material. Mailproof never imports keys or contacts a
// keyserver.
type CryptoConfig struct {
	OpenSSLPath string
	GPGVPath    string
	TrustRoot   string
	WorkRoot    string
	Timeout     time.Duration
	OutputLimit int64
}

func (c CryptoConfig) Validate() error {
	if c.WorkRoot == "" || c.Timeout <= 0 || c.OutputLimit <= 0 {
		return errors.New("crypto work root, timeout, and output bound are required")
	}
	if c.TrustRoot != "" {
		info, err := os.Stat(c.TrustRoot)
		if err != nil {
			return fmt.Errorf("inspect trust root: %w", err)
		}
		if !info.IsDir() {
			return errors.New("trust root must be a directory")
		}
	}
	return nil
}

type CryptoResult struct {
	Format                 string                    `json:"format"`
	Status                 evidence.CapabilityStatus `json:"status"`
	CryptographicallyValid bool                      `json:"cryptographically_valid"`
	ConfiguredTrust        string                    `json:"configured_trust"`
	Signer                 string                    `json:"signer,omitempty"`
	Fingerprint            string                    `json:"fingerprint,omitempty"`
	Revocation             RevocationState           `json:"revocation"`
	ToolVersion            string                    `json:"tool_version"`
	ExitCode               int                       `json:"exit_code"`
	OutputDigest           string                    `json:"output_digest"`
	Limitations            []string                  `json:"limitations"`
}

func unavailableCrypto(format string) CryptoResult {
	return CryptoResult{Format: format, Status: evidence.Unavailable, ConfiguredTrust: "unavailable", Revocation: RevocationIndeterminate, Limitations: []string{"operator trust material is not mounted"}}
}

// VerifySMIME delegates CMS parsing and verification to OpenSSL. The message
// remains stdin and all generated outputs stay inside a fresh run directory.
func VerifySMIME(ctx context.Context, config CryptoConfig, message []byte) (CryptoResult, error) {
	if err := config.Validate(); err != nil {
		return CryptoResult{}, err
	}
	if config.TrustRoot == "" || config.OpenSSLPath == "" {
		return unavailableCrypto("smime"), nil
	}
	runDir, err := os.MkdirTemp(config.WorkRoot, "mailproof-smime-")
	if err != nil {
		return CryptoResult{}, fmt.Errorf("create isolated S/MIME directory: %w", err)
	}
	defer os.RemoveAll(runDir)
	result := evidence.Run(ctx, map[string]struct{}{config.OpenSSLPath: {}}, evidence.Command{
		Path:  config.OpenSSLPath,
		Args:  []string{"cms", "-verify", "-inform", "SMIME", "-CApath", config.TrustRoot, "-noout"},
		Stdin: message, Directory: runDir, Timeout: config.Timeout, StdoutLimit: config.OutputLimit, StderrLimit: config.OutputLimit,
	})
	return normalizeCryptoResult("smime", result, config.OpenSSLPath), nil
}

// VerifyOpenPGP verifies a detached signature using an existing read-only
// keyring. It deliberately omits every network and import option.
func VerifyOpenPGP(ctx context.Context, config CryptoConfig, signed, signature []byte) (CryptoResult, error) {
	if err := config.Validate(); err != nil {
		return CryptoResult{}, err
	}
	if config.TrustRoot == "" || config.GPGVPath == "" {
		return unavailableCrypto("openpgp"), nil
	}
	runDir, err := os.MkdirTemp(config.WorkRoot, "mailproof-openpgp-")
	if err != nil {
		return CryptoResult{}, fmt.Errorf("create isolated OpenPGP directory: %w", err)
	}
	defer os.RemoveAll(runDir)
	messagePath := filepath.Join(runDir, "signed.eml")
	signaturePath := filepath.Join(runDir, "signature.asc")
	if err := os.WriteFile(messagePath, signed, 0o600); err != nil {
		return CryptoResult{}, fmt.Errorf("write signed content: %w", err)
	}
	if err := os.WriteFile(signaturePath, signature, 0o600); err != nil {
		return CryptoResult{}, fmt.Errorf("write detached signature: %w", err)
	}
	result := evidence.Run(ctx, map[string]struct{}{config.GPGVPath: {}}, evidence.Command{
		Path:      config.GPGVPath,
		Args:      []string{"--homedir", config.TrustRoot, "--status-fd", "1", signaturePath, messagePath},
		Directory: runDir, Timeout: config.Timeout, StdoutLimit: config.OutputLimit, StderrLimit: config.OutputLimit,
	})
	return normalizeCryptoResult("openpgp", result, config.GPGVPath), nil
}

func normalizeCryptoResult(format string, command evidence.CommandResult, version string) CryptoResult {
	result := CryptoResult{Format: format, Status: command.Status, ConfiguredTrust: "not_verified", Revocation: RevocationIndeterminate, ToolVersion: version, ExitCode: command.ExitCode, OutputDigest: command.StdoutDigest, Limitations: []string{}}
	if command.Status == evidence.Observed {
		result.CryptographicallyValid = true
		result.ConfiguredTrust = "verified"
		result.Revocation = RevocationNotChecked
		result.Status = evidence.Observed
		return result
	}
	if command.Error != "" {
		result.Limitations = append(result.Limitations, command.Error)
	}
	return result
}

func (r CryptoResult) Evidence(subjectDigest, configDigest, rawPath string, observedAt time.Time) (evidence.Evidence, error) {
	value, err := json.Marshal(r)
	if err != nil {
		return evidence.Evidence{}, fmt.Errorf("encode crypto result: %w", err)
	}
	category := "smime"
	if r.Format == "openpgp" {
		category = "openpgp"
	}
	return evidence.Evidence{ID: "crypto-" + category, Category: category, Adapter: r.Format, AdapterVersion: r.ToolVersion, ConfigDigest: configDigest, SubjectDigest: subjectDigest, InputDigest: subjectDigest, ObservedAt: observedAt.UTC(), Value: value, RawResponsePath: rawPath, Status: r.Status, Authority: evidence.Strong, Limitations: append([]string{}, r.Limitations...)}, nil
}

func isMountedReadOnly(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().Perm()&0o222 == 0
}

func sanitizeToolOutput(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "\r", " "), "\n", " ")
}
