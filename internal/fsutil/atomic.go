package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
)

// WriteFileAtomic replaces path with data so that a reader, or a crash, sees
// either the old file or the new one and never a partial file: the data goes to
// a temporary file in the same directory, which is flushed to disk (fsync) and
// renamed over path, and then the directory is flushed too so the rename itself
// survives a power cut. The file ends up with permission perm.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op after a successful rename
	if err := tmp.Chmod(perm); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
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
	if err := Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDir(dir)
}

// syncDir flushes a directory entry. Windows cannot fsync a directory, and
// NTFS makes the rename durable on its own, so nothing is done there.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
