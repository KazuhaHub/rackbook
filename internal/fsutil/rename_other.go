//go:build !windows

package fsutil

func rename(oldpath, newpath string, do func(string, string) error) error {
	return do(oldpath, newpath)
}
