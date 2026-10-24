package file

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

// WriteAtomic replaces a complete file only after its temporary file is closed.
// The temporary file lives in the same directory so Rename stays on one volume.
func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".v2bx-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// Windows readers may briefly deny replacement while loading a PEM file.
	// Keep the complete old file intact and retry only these transient errors.
	for attempt := 0; ; attempt++ {
		err := os.Rename(f.Name(), path)
		if err == nil || runtime.GOOS != "windows" || attempt >= 8 ||
			(!errors.Is(err, syscall.Errno(5)) && !errors.Is(err, syscall.Errno(32)) && !errors.Is(err, syscall.Errno(33))) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}
