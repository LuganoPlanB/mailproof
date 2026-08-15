package artifact

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSealPreservesBytesAndIsIdempotent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	source := filepath.Join(dir, "message")
	want := []byte("Subject: x\r\n\r\nbody\x00\n")
	if err := os.WriteFile(source, want, 0o600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		digest, _, err := Seal(context.Background(), filepath.Join(dir, "artifacts"), source)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(dir, "artifacts", "messages", digest+".eml"))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("artifact bytes changed: %q", got)
		}
	}
}

func TestSealRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, _, err := Seal(context.Background(), filepath.Join(dir, "artifacts"), link)
	if !errors.Is(err, ErrUnsafeSource) {
		t.Fatalf("Seal() error = %v, want ErrUnsafeSource", err)
	}
}

func TestReadHeadersRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("Subject: x\n\nbody"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadHeaders(link, 1024); err == nil {
		t.Fatal("ReadHeaders accepted symlink")
	}
}
