// Package artifact safely publishes immutable message artifacts.
package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

var ErrUnsafeSource = errors.New("unsafe source file")
var ErrSourceChanged = errors.New("source file changed while sealing")

// Seal streams a regular source file to the content-addressed store without
// mutating the source. Existing content is deliberately retained.
func Seal(ctx context.Context, root, source string) (string, int64, error) {
	info, err := os.Lstat(source)
	if err != nil {
		return "", 0, fmt.Errorf("stat source: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", 0, ErrUnsafeSource
	}
	in, err := os.Open(source)
	if err != nil {
		return "", 0, fmt.Errorf("open source: %w", err)
	}
	defer in.Close()
	messageDir := filepath.Join(root, "messages")
	if err := os.MkdirAll(messageDir, 0o750); err != nil {
		return "", 0, fmt.Errorf("create message directory: %w", err)
	}
	tmp, err := os.CreateTemp(messageDir, ".sealing-*")
	if err != nil {
		return "", 0, fmt.Errorf("create temporary artifact: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	hash := sha256.New()
	buf := make([]byte, 32*1024)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			_ = tmp.Close()
			return "", 0, err
		}
		n, readErr := in.Read(buf)
		if n > 0 {
			m, writeErr := io.MultiWriter(tmp, hash).Write(buf[:n])
			written += int64(m)
			if writeErr != nil {
				_ = tmp.Close()
				return "", 0, fmt.Errorf("write artifact: %w", writeErr)
			}
			if m != n {
				_ = tmp.Close()
				return "", 0, io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = tmp.Close()
			return "", 0, fmt.Errorf("read source: %w", readErr)
		}
	}
	finalInfo, err := os.Stat(source)
	if err != nil {
		_ = tmp.Close()
		return "", 0, fmt.Errorf("restat source: %w", err)
	}
	if !os.SameFile(info, finalInfo) || finalInfo.Size() != written {
		_ = tmp.Close()
		return "", 0, ErrSourceChanged
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", 0, fmt.Errorf("sync artifact: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", 0, fmt.Errorf("close artifact: %w", err)
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	target := filepath.Join(messageDir, digest+".eml")
	if _, err := os.Stat(target); err == nil {
		return digest, written, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", 0, fmt.Errorf("stat target: %w", err)
	}
	if err := os.Link(tmpName, target); err != nil {
		if errors.Is(err, os.ErrExist) {
			return digest, written, nil
		}
		return "", 0, fmt.Errorf("publish artifact: %w", err)
	}
	dir, err := os.Open(messageDir)
	if err != nil {
		return "", 0, fmt.Errorf("open message directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return "", 0, fmt.Errorf("sync message directory: %w", err)
	}
	return digest, written, nil
}

// ReadHeaders reads only the RFC822 header prefix through a no-follow descriptor.
func ReadHeaders(path string, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("header limit must be positive")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open headers: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat headers: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, ErrUnsafeSource
	}
	reader := io.LimitReader(file, limit)
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read headers: %w", err)
	}
	return data, nil
}
