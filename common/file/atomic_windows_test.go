//go:build windows

package file

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWriteAtomicRetriesTransientWindowsReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := WriteAtomic(path, []byte("old complete PEM"), 0600); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { time.Sleep(20 * time.Millisecond); _ = windows.CloseHandle(h); close(done) }()
	if err := WriteAtomic(path, []byte("new complete PEM"), 0600); err != nil {
		t.Fatal(err)
	}
	<-done
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "new complete PEM" {
		t.Fatalf("replacement=%q %v", got, err)
	}
}

func TestWriteAtomicPermanentFailurePreservesOldFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := WriteAtomic(path, []byte("old complete PEM"), 0600); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	if err := WriteAtomic(path, []byte("new complete PEM"), 0600); err == nil {
		t.Fatal("expected a bounded replacement error while reader remains open")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "old complete PEM" {
		t.Fatalf("old file lost: %q %v", got, err)
	}
	entries, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".v2bx-*"))
	if err != nil || len(entries) != 0 {
		t.Fatal("temporary private file left after failure")
	}
}
